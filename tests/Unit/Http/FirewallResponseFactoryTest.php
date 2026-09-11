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
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use Kanopi\FirewallBundle\Http\ChallengeRenderer;
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
        $response = $this->factory()->challengeRequired(Request::create('/gated'));

        // 200 because the visitor is being asked a question, not refused —
        // a 4xx would have a CDN and a browser treat a solvable page as an
        // error.
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('text/html; charset=utf-8', $response->headers->get('Content-Type'));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertStringContainsString('challenge_answer', (string) $response->getContent());
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
            new ChallengeRenderer($resolver, $recorder),
            $resolver,
            $recorder,
            $cookieOptions ?? self::COOKIE,
            $blockedResponse
        );
    }
}
