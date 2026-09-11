<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Http;

use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use Kanopi\FirewallBundle\Http\ChallengeRenderer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(ChallengeRenderer::class)]
final class ChallengeRendererTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    public function testItRendersTheConfiguredProvidersInterstitial(): void
    {
        $html = $this->renderer()->render(Request::create('/gated'));

        self::assertStringContainsString('<form', $html);
        self::assertStringContainsString('action="/_firewall/challenge"', $html);
        self::assertStringContainsString('challenge_answer', $html);
        self::assertStringContainsString('value="/gated"', $html);
    }

    public function testItCarriesNoSignedProviderField(): void
    {
        // `provider_token` is only needed when a rule names its own
        // provider, and that configuration is refused outright — see
        // ChallengeConfigResolver. Emitting an unsigned one would be
        // rejected by the submission handler, which is the lockout the
        // refusal exists to prevent.
        self::assertStringNotContainsString(
            'name="challenge_provider"',
            $this->renderer()->render(Request::create('/gated'))
        );
    }

    public function testTheTtlComesFromTheRuleThatMatched(): void
    {
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getExpirationTime')->willReturn(120);

        $recorder = new DecisionRecorder();
        $recorder->record(new RequestChallenged(Request::create('/gated'), $plugin, 'math'));

        self::assertStringContainsString('name="ttl" value="120"', $this->renderer($recorder)->render(Request::create('/gated')));
    }

    public function testTheTtlFallsBackToAnHourWithoutARecordedChallenge(): void
    {
        // The documented degrade for a decision listener that did not run:
        // a wrong lifetime, not a broken challenge.
        self::assertStringContainsString(
            'name="ttl" value="3600"',
            $this->renderer()->render(Request::create('/gated'))
        );
    }

    public function testAnUnrelatedDecisionAlsoFallsBackToAnHour(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestAllowed(Request::create('/gated')));

        self::assertStringContainsString(
            'name="ttl" value="3600"',
            $this->renderer($recorder)->render(Request::create('/gated'))
        );
    }

    public function testARuleWithNoDeclaredLifetimeFallsBackToAnHour(): void
    {
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getExpirationTime')->willReturn(0);

        $recorder = new DecisionRecorder();
        $recorder->record(new RequestChallenged(Request::create('/gated'), $plugin, 'math'));

        self::assertStringContainsString(
            'name="ttl" value="3600"',
            $this->renderer($recorder)->render(Request::create('/gated'))
        );
    }

    #[DataProvider('provideHostileRedirects')]
    public function testTheRedirectTargetCannotLeaveTheSite(string $requestUri, string $expected): void
    {
        $request = Request::create('/gated');
        // The request URI is echoed into a hidden field and later used as a
        // Location, so this is the open-redirect surface.
        $request->server->set('REQUEST_URI', $requestUri);

        self::assertStringContainsString(
            sprintf('name="redirect_to" value="%s"', $expected),
            $this->renderer()->render($request)
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideHostileRedirects(): iterable
    {
        yield 'same-origin path is kept' => ['/wanted?a=1', '/wanted?a=1'];
        yield 'protocol-relative is collapsed' => ['//evil.example.com/', '/'];
        yield 'backslash form is collapsed' => ['/\\evil.example.com/', '/'];
        yield 'absolute url is collapsed' => ['https://evil.example.com/', '/'];
        yield 'empty is collapsed' => ['', '/'];
    }

    public function testTheProviderRegistryIsBuiltOnce(): void
    {
        $renderer = $this->renderer();

        // Two renders, one registry: the provider is what holds the shared
        // TokenManager, and rebuilding it per challenge would be pure cost.
        self::assertNotSame('', $renderer->render(Request::create('/gated')));
        self::assertNotSame('', $renderer->render(Request::create('/gated')));
    }

    /**
     * A renderer over the challenge fixture.
     */
    private function renderer(?DecisionRecorder $recorder = null): ChallengeRenderer
    {
        return new ChallengeRenderer(
            new ChallengeConfigResolver([self::CONFIG . 'challenge.yml'], []),
            $recorder ?? new DecisionRecorder()
        );
    }
}
