<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Http;

use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Turns the library's three request-time exceptions into responses.
 *
 * Each one reproduces what `block` mode would have written before it
 * `exit()`ed, header for header. That is not fussiness: two of those headers
 * are load-bearing.
 */
final class FirewallResponseFactory
{
    /**
     * The library's fallback when a challenge names no lifetime.
     */
    private const DEFAULT_TTL = 3600;

    /**
     * @param ChallengeConfigResolver $resolver
     *   Supplies the pass-cookie name.
     * @param DecisionRecorder $decisionRecorder
     *   Supplies the solved challenge's TTL, which the exception omits.
     * @param array{path: string, domain: string|null, secure: bool, http_only: bool, same_site: 'lax'|'strict'|'none'} $cookieOptions
     *   Attributes for the pass cookie, from `kanopi_firewall.challenge.cookie`.
     * @param string $blockedResponse
     *   `plain` to write the refusal directly, `http_exception` to hand it to
     *   the application's error controller.
     */
    public function __construct(
        private readonly ChallengeConfigResolver $resolver,
        private readonly DecisionRecorder $decisionRecorder,
        private readonly array $cookieOptions,
        private readonly string $blockedResponse = 'plain'
    ) {
    }

    /**
     * The refusal.
     *
     * `text/plain` and `nosniff` are copied from the library on purpose. The
     * banning message is a template — `{{request.header.X-Foo}}` and friends
     * — so it can carry bytes the client chose. `interpolateTemplate()`
     * HTML-escapes every substitution, and serving the result as something a
     * browser will never parse as markup is the second of those two belts.
     * Sending this as `text/html` would leave the escaping as the only thing
     * between a blocked attacker and reflected XSS on the block page.
     *
     * ## Lockdown carries `Retry-After`
     *
     * `FirewallLockdownException` is a refusal of everybody rather than of
     * this visitor, and it is meant to be temporary. `Retry-After` is what
     * says so to the one reader that matters during a lockdown: a CDN in
     * front of the site, which will otherwise take a bare 503 for a
     * permanent condition and keep serving it after the lockdown is lifted.
     * The header is set even in `http_exception` mode, where the error
     * controller renders the body but the headers are still the firewall's
     * to state.
     *
     * @throws HttpException
     *   In `http_exception` mode, so the application's error controller
     *   renders it. The message is dropped there: an error template is HTML
     *   by definition, so handing it attacker-influenced text would give
     *   back exactly the property the paragraph above is protecting.
     */
    public function blocked(FirewallBlockedException $exception): Response
    {
        $status = $this->normalizeStatus($exception->getStatusCode());
        $headers = [
            'Content-Type' => 'text/plain; charset=utf-8',
            'X-Content-Type-Options' => 'nosniff',
            // A cached block page is a block that outlives the ban, served by
            // a CDN to somebody who was never blocked. The library relies on
            // the absence of a caching directive plus the status code; being
            // explicit costs nothing and survives a shared cache configured
            // to store 4xx.
            'Cache-Control' => 'no-store, private',
        ];

        if ($exception instanceof FirewallLockdownException) {
            $headers['Retry-After'] = (string) $exception->getRetryAfter();
        }

        if ($this->blockedResponse === 'http_exception') {
            throw new HttpException($status, '', $exception, array_intersect_key(
                $headers,
                ['Retry-After' => true]
            ));
        }

        return new Response($exception->getMessage(), $status, $headers);
    }

    /**
     * The interstitial.
     *
     * 200, not 401 or 403: the visitor is not being refused, they are being
     * asked a question, and the document carries the form that answers it. A
     * 4xx here would have a CDN and a browser treat a solvable page as an
     * error, and `Firewall::sendChallengeResponse()` sends 200 for the same
     * reason.
     *
     * ## The exception renders itself, and that is the whole point
     *
     * This bundle used to build the document: stand up a provider registry
     * from the same configuration, pick the provider, assemble the six
     * render-context fields and ask it to render. It worked for the common
     * case and could not work for one rule naming its own provider, because
     * the field that makes such a solution verifiable — `provider_token` —
     * is signed by a `protected` method behind a `private const` prefix on a
     * `final` class. Rendering without it did not fail: the visitor solved
     * the challenge, the pass token carried the wrong provider claim, the
     * rule refused it, and they were served the same interstitial forever
     * with nothing logged above `notice`.
     *
     * The bundle's answer was to refuse that configuration outright at
     * `cache:clear`. The library's answer, from 2.26.0, is
     * `ChallengeRequiredException::renderInterstitial()` — which holds the
     * provider the firewall actually chose and the context it actually
     * built, so there is nothing left here to get wrong. That is
     * kanopi/firewall#311, reported from this package, and this one call is
     * the whole of consuming the fix.
     */
    public function challengeRequired(ChallengeRequiredException $challengeRequiredException, Request $request): Response
    {
        return new Response($challengeRequiredException->renderInterstitial($request), Response::HTTP_OK, [
            'Content-Type' => 'text/html; charset=utf-8',
            // Non-negotiable. The interstitial embeds per-visitor state — a
            // signed math answer, a widget nonce — and a cached copy served
            // to a second visitor is a challenge nobody can solve.
            'Cache-Control' => 'no-store',
        ]);
    }

    /**
     * A visitor sent somewhere else rather than refused.
     *
     * `response: redirect` is a signpost, not a ban — a notice page, a
     * contact form, a "your account is suspended" explanation. It records
     * nothing by default, and it runs before the block bucket, so the
     * gentlest terminal answer wins.
     *
     * `no-store` for the same reason a challenge carries it: the decision
     * was made about this visitor, and a cached copy would send the next one
     * to the same notice.
     */
    public function redirected(FirewallRedirectException $firewallRedirectException): Response
    {
        $response = new RedirectResponse(
            $firewallRedirectException->getLocation(),
            $this->normalizeRedirectStatus($firewallRedirectException->getStatusCode())
        );
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    /**
     * The pass cookie and the redirect back to where the visitor was going.
     *
     * `getRedirect()` is already reduced to a same-origin path by the
     * library, so it is safe in a `Location` header without further work.
     *
     * 303 rather than 302: the visitor arrived here by POSTing a solution,
     * and 303 is the status that says "GET the next thing instead of
     * repeating what you just sent". A 302 leaves the method up to the
     * client, and one that repeats the POST re-submits a solution the
     * single-use providers have already burned.
     */
    public function challengeSolved(ChallengeSolvedException $exception): Response
    {
        $response = new RedirectResponse($exception->getRedirect(), Response::HTTP_SEE_OTHER);
        $response->headers->set('Cache-Control', 'no-store');

        $cookieName = $this->resolver->resolve()->cookieName;

        // An empty cookie name is how an operator turns off cookie delivery
        // for an API-only deployment, where the token comes back in the JSON
        // body and the client sends it as the configured header instead.
        if ($cookieName !== '') {
            $response->headers->setCookie(Cookie::create($cookieName)
                ->withValue($exception->getToken())
                ->withExpires(time() + $this->solvedTtl())
                ->withPath($this->cookieOptions['path'])
                ->withDomain($this->cookieOptions['domain'])
                ->withSecure($this->cookieOptions['secure'])
                ->withHttpOnly($this->cookieOptions['http_only'])
                ->withSameSite($this->cookieOptions['same_site']));
        }

        return $response;
    }

    /**
     * How long the issued pass cookie should live.
     *
     * The exception carries the token but not its lifetime, and the token is
     * opaque. The `ChallengeSolved` event announced immediately before the
     * throw carries the TTL the library used, so the cookie and the token
     * expire together.
     *
     * When nothing was recorded the cookie gets the library's own default of
     * an hour. A mismatch either way is self-correcting rather than
     * dangerous: `TokenManager::verify()` is what decides whether a token is
     * still good, so a cookie that outlives its token means one extra
     * challenge, not one extra hour of access.
     */
    private function solvedTtl(): int
    {
        $decision = $this->decisionRecorder->getDecision();

        if (!$decision instanceof ChallengeSolved) {
            return self::DEFAULT_TTL;
        }

        $ttl = $decision->getTtl();

        return $ttl > 0 ? $ttl : self::DEFAULT_TTL;
    }

    /**
     * Keep a redirect's status inside the range that is *a redirect*.
     *
     * Narrower than `normalizeStatus()` and needs to be: `RedirectResponse`
     * refuses anything outside 300-399 with an `InvalidArgumentException`,
     * so the general fallback of 400 would turn a misconfigured
     * `metadata.redirect_status` into a 500 thrown from inside the listener
     * — the visitor refused with a stack trace instead of sent where the
     * rule meant to send them.
     *
     * 302 rather than 301: a permanent redirect is cached by the browser
     * against the URL, so a typo in a rule's status would outlive the rule
     * and keep sending that visitor to the notice page after the rule was
     * removed.
     */
    private function normalizeRedirectStatus(int $status): int
    {
        return $status >= 300 && $status <= 399 ? $status : Response::HTTP_FOUND;
    }

    /**
     * Keep the status inside the range Symfony will accept.
     *
     * `FirewallBlockedException::getStatusCode()` is `getCode()`, and a
     * `RuntimeException` code is any integer an operator can put in
     * `banning_status_code`. Symfony's `Response` throws
     * `InvalidArgumentException` for anything outside 100-599, so a typo
     * there would turn a block into a 500 from inside the listener — the
     * request refused for the wrong reason, with a stack trace instead of a
     * ban message.
     */
    private function normalizeStatus(int $status): int
    {
        return $status >= 100 && $status <= 599 ? $status : Response::HTTP_BAD_REQUEST;
    }
}
