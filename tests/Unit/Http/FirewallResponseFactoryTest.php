<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Http;

use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use Kanopi\FirewallBundle\Http\FirewallResponseFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

#[CoversClass(FirewallResponseFactory::class)]
final class FirewallResponseFactoryTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    /**
     * The cookie attributes the bundle defaults to, mirroring the library.
     */
    private const COOKIE = [
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
        'same_site' => 'strict',
    ];

    public function testABlockCarriesItsStatusAndMessage(): void
    {
        $response = $this->factory()->blocked(new FirewallBlockedException('Blocked: 203.0.113.5', 403));

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('Blocked: 203.0.113.5', $response->getContent());
    }

    public function testABlockIsServedAsUnsniffablePlainText(): void
    {
        // The banning message is a template over request data — headers,
        // query, cookies — so escaping is one belt and a content type no
        // browser will parse as markup is the other.
        $response = $this->factory()->blocked(new FirewallBlockedException('x', 429));

        self::assertSame('text/plain; charset=utf-8', $response->headers->get('Content-Type'));
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    #[DataProvider('provideImpossibleStatusCodes')]
    public function testAnOutOfRangeStatusFallsBackToBadRequest(int $configured): void
    {
        // `getStatusCode()` is the exception's code, and that is whatever an
        // operator typed into `banning_status_code`. Handing 0 or 999 to
        // Response would throw from inside the listener and turn a block
        // into a stack trace.
        self::assertSame(400, $this->factory()->blocked(new FirewallBlockedException('x', $configured))->getStatusCode());
    }

    /**
     * @return iterable<string, array{0: int}>
     */
    public static function provideImpossibleStatusCodes(): iterable
    {
        yield 'zero' => [0];
        yield 'below the range' => [99];
        yield 'above the range' => [600];
        yield 'negative' => [-1];
    }

    public function testHttpExceptionModeThrowsForTheErrorController(): void
    {
        try {
            $this->factory(blockedResponse: 'http_exception')
                ->blocked(new FirewallBlockedException('Blocked: 203.0.113.5', 403));
            self::fail('an HttpException should have been thrown');
        } catch (HttpException $httpException) {
            self::assertSame(403, $httpException->getStatusCode());
            // The message is dropped: an error template is HTML, and the
            // banning message can carry bytes the client chose.
            self::assertSame('', $httpException->getMessage());
            self::assertInstanceOf(FirewallBlockedException::class, $httpException->getPrevious());
        }
    }

    public function testTheInterstitialIsServedAsAnUncacheableTwoHundred(): void
    {
        $request = Request::create('/gated');
        $response = $this->factory()->challengeRequired($this->challenge($request), $request);

        // 200 because the visitor is being asked a question, not refused —
        // a 4xx would have a CDN and a browser treat a solvable page as an
        // error.
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('text/html; charset=utf-8', $response->headers->get('Content-Type'));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertStringContainsString('challenge_answer', (string) $response->getContent());
    }

    public function testARuleWithItsOwnProviderRendersWithASignedProviderToken(): void
    {
        // The lockout this package reported as kanopi/firewall#311, now the
        // other way round. The default provider is `math` and the rule names
        // `altcha`, so the interstitial has to say which one served it — and
        // that field is signed by the library, which is the only thing that
        // can sign it.
        $request = Request::create('/gated');

        $content = (string) $this->factory()
            ->challengeRequired($this->challenge($request, 'per-rule-provider.yml'), $request)
            ->getContent();

        // The field is named for the interface constant and carries the
        // signed value; `provider_token` is the context key, not the markup.
        self::assertStringContainsString('name="challenge_provider"', $content);
        self::assertStringContainsString('altcha', $content, 'the rule\'s provider served it, not the default');
    }

    public function testARedirectedVisitorIsSentOnUncacheably(): void
    {
        // `response: redirect` is a signpost and not a ban, and a cached
        // copy would send the next visitor to the same notice.
        $response = $this->factory()->redirected(new FirewallRedirectException('/notice', 302));

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('/notice', $response->headers->get('Location'));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function testARedirectStatusThatIsNotARedirectFallsBackToOne(): void
    {
        // `RedirectResponse` refuses anything outside 300-399 outright, so
        // the block path's fallback of 400 would throw from inside the
        // listener — the visitor refused with a stack trace instead of sent
        // where the rule meant to send them.
        $response = $this->factory()->redirected(new FirewallRedirectException('/notice', 999));

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('/notice', $response->headers->get('Location'));
    }

    public function testALockdownCarriesRetryAfterForTheCdnInFront(): void
    {
        // Without it a CDN takes a bare 503 for a permanent condition and
        // keeps serving the refusal after the lockdown is lifted.
        $response = $this->factory()->blocked(new FirewallLockdownException('Down for maintenance', 503, 600));

        self::assertSame(503, $response->getStatusCode());
        self::assertSame('600', $response->headers->get('Retry-After'));
    }

    public function testAnOrdinaryBlockCarriesNoRetryAfter(): void
    {
        $response = $this->factory()->blocked(new FirewallBlockedException('Blocked', 403));

        self::assertFalse($response->headers->has('Retry-After'));
    }

    public function testLockdownKeepsItsRetryAfterThroughTheErrorController(): void
    {
        // The body belongs to the application's error template in this mode;
        // the headers are still the firewall's to state.
        try {
            $this->factory(blockedResponse: 'http_exception')
                ->blocked(new FirewallLockdownException('Down for maintenance', 503, 600));
            self::fail('http_exception mode should throw');
        } catch (HttpException $httpException) {
            self::assertSame(503, $httpException->getStatusCode());
            self::assertSame(['Retry-After' => '600'], $httpException->getHeaders());
        }
    }

    public function testASolvedChallengeRedirectsWithThePassCookie(): void
    {
        $response = $this->factory()->challengeSolved(new ChallengeSolvedException('token-value', '/wanted'));

        // 303, not 302: the visitor got here by POSTing a solution, and a
        // client that repeats the POST re-submits one a single-use provider
        // has already burned.
        self::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/wanted', $response->headers->get('Location'));

        $cookie = $response->headers->getCookies()[0];
        self::assertSame('fw_challenge_pass', $cookie->getName());
        self::assertSame('token-value', $cookie->getValue());
        self::assertTrue($cookie->isSecure());
        self::assertTrue($cookie->isHttpOnly());
        self::assertSame('strict', $cookie->getSameSite());
    }

    public function testTheCookieExpiresWithTheTokenItCarries(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new ChallengeSolved(Request::create('/'), 'math', 120));

        $response = $this->factory($recorder)->challengeSolved(new ChallengeSolvedException('t', '/'));

        self::assertEqualsWithDelta(time() + 120, $response->headers->getCookies()[0]->getExpiresTime(), 5.0);
    }

    public function testTheCookieFallsBackToAnHourWithoutARecordedSolve(): void
    {
        $response = $this->factory()->challengeSolved(new ChallengeSolvedException('t', '/'));

        self::assertEqualsWithDelta(time() + 3600, $response->headers->getCookies()[0]->getExpiresTime(), 5.0);
    }

    public function testAnUnrelatedDecisionAlsoFallsBackToAnHour(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestAllowed(Request::create('/')));

        $response = $this->factory($recorder)->challengeSolved(new ChallengeSolvedException('t', '/'));

        self::assertEqualsWithDelta(time() + 3600, $response->headers->getCookies()[0]->getExpiresTime(), 5.0);
    }

    public function testANonPositiveTtlFallsBackToAnHour(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new ChallengeSolved(Request::create('/'), 'math', 0));

        $response = $this->factory($recorder)->challengeSolved(new ChallengeSolvedException('t', '/'));

        self::assertEqualsWithDelta(time() + 3600, $response->headers->getCookies()[0]->getExpiresTime(), 5.0);
    }

    public function testAnEmptyCookieNameSkipsCookieDelivery(): void
    {
        // How an API-only deployment turns the cookie off: the token comes
        // back to the client another way and returns as the header.
        $factory = $this->factory(cookieName: '');

        self::assertSame([], $factory->challengeSolved(new ChallengeSolvedException('t', '/'))->headers->getCookies());
    }

    public function testTheCookieAttributesAreConfigurable(): void
    {
        $factory = $this->factory(cookieOptions: [
            'path' => '/app',
            'domain' => 'example.test',
            'secure' => false,
            'http_only' => false,
            'same_site' => 'lax',
        ]);

        $cookie = $factory->challengeSolved(new ChallengeSolvedException('t', '/'))->headers->getCookies()[0];

        self::assertSame('/app', $cookie->getPath());
        self::assertSame('example.test', $cookie->getDomain());
        self::assertFalse($cookie->isSecure());
        self::assertFalse($cookie->isHttpOnly());
        self::assertSame('lax', $cookie->getSameSite());
    }

    /**
     * A real `ChallengeRequiredException`, from a real firewall.
     *
     * Not constructed by hand. The whole value of the 2.26.0 fix is that the
     * exception carries the provider the firewall resolved and the context it
     * built — including the `provider_token` this package could not sign —
     * so an exception assembled here would be testing the assembly rather
     * than the thing that was fixed.
     *
     * @param Request $request
     *   The request to have challenged.
     * @param string $fixture
     *   The configuration to challenge it with.
     */
    private function challenge(Request $request, string $fixture = 'challenge.yml'): ChallengeRequiredException
    {
        try {
            Firewall::create([self::CONFIG . $fixture], ['[global][mode]' => 'exception'])->evaluate($request);
        } catch (ChallengeRequiredException $challengeRequiredException) {
            return $challengeRequiredException;
        }

        self::fail(sprintf('%s should have challenged %s', $fixture, $request->getPathInfo()));
    }

    /**
     * A factory over the challenge fixture.
     *
     * @param array{path: string, domain: string|null, secure: bool, http_only: bool, same_site: 'lax'|'strict'|'none'}|null $cookieOptions
     *   Cookie attributes, defaulting to the bundle's.
     */
    private function factory(
        ?DecisionRecorder $recorder = null,
        string $blockedResponse = 'plain',
        ?string $cookieName = null,
        ?array $cookieOptions = null
    ): FirewallResponseFactory {
        $recorder ??= new DecisionRecorder();
        $overrides = $cookieName === null ? [] : ['[challenge][cookie_name]' => $cookieName];
        $resolver = new ChallengeConfigResolver([self::CONFIG . 'challenge.yml'], $overrides);

        return new FirewallResponseFactory(
            $resolver,
            $recorder,
            $cookieOptions ?? self::COOKIE,
            $blockedResponse
        );
    }
}
