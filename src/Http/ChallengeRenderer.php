<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Http;

use Kanopi\Firewall\Challenge\ChallengeProviderRegistry;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Symfony\Component\HttpFoundation\Request;

/**
 * Renders the interstitial the library declines to render in `exception`
 * mode.
 *
 * `sendChallengeResponse()` builds this document itself in `block` mode and
 * `exit()`s with it; in `exception` mode it throws before reaching that code,
 * leaving the HTTP side to the host. So the bundle stands up its own
 * `TokenManager` and `ChallengeProviderRegistry` from the same configuration
 * and asks the same provider for the same document. Nothing is reimplemented
 * — `renderInterstitial()` is the library's, and the built-in providers
 * (math, altcha, turnstile, recaptcha) all go through
 * `InterstitialRenderer::render()`, so the markup, the submit JavaScript and
 * the field names match what `block` mode serves byte for byte.
 *
 * `provider_token` is deliberately absent from the render context. It is
 * needed only when a rule names its own provider, and
 * `ChallengeConfigResolver` refuses that configuration outright — see the
 * long note there for why a lockout is the alternative.
 */
final class ChallengeRenderer
{
    /**
     * The library's own fallback when a rule declares no expiry.
     */
    private const DEFAULT_TTL = 3600;

    /**
     * Built once per process, on the first challenge.
     */
    private ?ChallengeProviderRegistry $registry = null;

    public function __construct(
        private readonly ChallengeConfigResolver $resolver,
        private readonly DecisionRecorder $decisionRecorder
    ) {
    }

    /**
     * The interstitial document for this request.
     *
     * @param Request $request
     *   The request that was challenged.
     *
     * @return string
     *   A complete HTML document.
     *
     * @throws \Kanopi\Firewall\Exception\ConfigurationException
     *   When the provider cannot be built — a missing `site_key`, an FQCN
     *   that is not a provider. `Firewall::create()` warms every configured
     *   provider at startup, so by here this is a guard rather than a case
     *   that happens.
     */
    public function render(Request $request): string
    {
        $settings = $this->resolver->resolve();
        $provider = $this->providerRegistry($settings)->get($settings->provider);

        return $provider->renderInterstitial($request, [
            'submit_url' => $settings->path,
            // Same sanitizer the library applies, and for the same reason:
            // the value is echoed into a hidden field and later used as a
            // Location, so a protocol-relative or off-site target here is an
            // open redirect with a firewall's name on it.
            'redirect_to' => $this->sanitizeRedirect($request->getRequestUri()),
            'ttl' => (string) $this->ttl($request),
            'cookie_name' => $settings->cookieName,
            'header_name' => $settings->headerName,
        ]);
    }

    /**
     * How long a pass token earned here should last.
     *
     * The library reads this off the rule that matched
     * (`$plugin->getExpirationTime()`), and `ChallengeRequiredException`
     * carries neither the rule nor the number. The `RequestChallenged` event
     * announced immediately before the throw carries the rule, so the
     * recorder is how the bundle arrives at the same answer.
     *
     * Falls back to the library's own default when nothing was recorded,
     * which is the documented degrade for a decision listener that did not
     * run. A visitor then gets an hour instead of whatever the rule asked
     * for — a wrong TTL, not a broken challenge.
     */
    private function ttl(Request $request): int
    {
        $decision = $this->decisionRecorder->getDecision();

        if (!$decision instanceof RequestChallenged) {
            return self::DEFAULT_TTL;
        }

        $ttl = $decision->getPlugin()->getExpirationTime($request);

        return $ttl > 0 ? $ttl : self::DEFAULT_TTL;
    }

    /**
     * The provider registry, built from the resolved challenge settings.
     */
    private function providerRegistry(ChallengeSettings $settings): ChallengeProviderRegistry
    {
        return $this->registry ??= new ChallengeProviderRegistry(
            new TokenManager($settings->secret, $settings->audience, $settings->provider),
            $settings->provider,
            $settings->providerOptions
        );
    }

    /**
     * Reduce a redirect target to a same-origin path.
     *
     * Mirrors `Firewall::sanitizeRedirect()`. Duplicated rather than reached
     * for because it is `protected` on a `final` class, and four lines of
     * string comparison is a cheaper coupling than any way of borrowing it.
     */
    private function sanitizeRedirect(string $target): string
    {
        if ($target === '' || $target[0] !== '/') {
            return '/';
        }

        if (str_starts_with($target, '//') || str_starts_with($target, '/\\')) {
            return '/';
        }

        return $target;
    }
}
