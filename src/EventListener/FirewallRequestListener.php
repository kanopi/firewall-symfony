<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\EventListener;

use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Firewall;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Http\FirewallResponseFactory;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Evaluates every main request, and turns a refusal into a `Response`.
 *
 * This is the whole integration. Symfony has no middleware, and it does not
 * need one here: `RequestEvent::getRequest()` already hands over the
 * `Symfony\Component\HttpFoundation\Request` that `evaluate()` takes, so
 * there is nothing to convert. A PSR-7 bridge or a PSR-15 adapter would add
 * two conversions and a dependency to move an object from where it is to
 * where it already needs to be.
 *
 * `RequestEvent::setResponse()` is the short-circuit. It stops propagation,
 * so nothing after this listener runs — no session, no routing, no
 * authentication — and the kernel returns the response as though a controller
 * had produced it.
 *
 * ## The process never exits
 *
 * `evaluate()` writes its own response and calls `exit()` in every mode
 * except `exception`. Inside a kernel that would skip `kernel.terminate`,
 * abandon whatever the runtime was going to flush, and — under a worker
 * runtime — take the worker down with it. So the bundle forces
 * `[global][mode] => exception` and there is no configuration that turns
 * that off: `kanopi_firewall.mode` offers `enforce`, `observe` and
 * `disabled`, and the library's `block` is not among them.
 *
 * ## `observe` is the library's `log`, not a caught `enforce`
 *
 * The obvious way to build a dry-run mode is to run `enforce` and swallow
 * the exception. It is also wrong: in `exception` mode the library calls
 * `block()` before it throws, which records the offense and applies
 * `blocking_escalation`. An "observe" deployment built that way would
 * quietly ban the addresses it was only supposed to watch. So `observe` maps
 * to the library's own `log` mode, which evaluates everything and writes
 * nothing.
 *
 * That inherits two edges from the library, both handled here:
 *
 *  - **`log` mode still `exit()`s on a challenge submission.** The POST
 *    interception in `evaluate()` runs before the mode is consulted. In
 *    `observe` nobody is being challenged for real, so there is no
 *    legitimate solution to submit, and the listener does not forward those
 *    POSTs at all.
 *  - **`log` mode evaluates nothing when `PHP_SAPI === 'cli'`.** That
 *    short-circuit is right for Drush and cron and wrong for RoadRunner and
 *    Swoole, which serve HTTP from a CLI SAPI. It cannot be fixed from
 *    outside the library, so it is reported once per process at `warning`
 *    rather than left to look like a firewall with nothing to say.
 *    `enforce` is unaffected — `exception` mode is exempt from that
 *    short-circuit.
 */
final class FirewallRequestListener
{
    /**
     * Whether the CLI-SAPI notice has been emitted in this process.
     */
    private bool $warnedAboutCliSapi = false;

    /**
     * @param FirewallFactory $firewallFactory
     *   Builds the firewall on the first request that needs one.
     * @param FirewallResponseFactory $responseFactory
     *   Translates the library's exceptions into responses.
     * @param DecisionRecorder $decisionRecorder
     *   Cleared before each evaluation; read afterwards by the renderer and
     *   the profiler panel.
     * @param string $mode
     *   `enforce`, `observe` or `disabled`.
     * @param string $challengePath
     *   `challenge.path`. Held as a plain string rather than resolved from
     *   the merged YAML because the bundle always writes this value into the
     *   library config as an override, so the two cannot disagree — and
     *   reading it here must not cost a config load on every POST.
     * @param bool $onlyMainRequests
     *   Skip sub-requests.
     * @param LoggerInterface|null $logger
     *   For the CLI-SAPI notice. The application's logger, not the
     *   library's, because this is a statement about the deployment rather
     *   than about a request.
     */
    public function __construct(
        private readonly FirewallFactory $firewallFactory,
        private readonly FirewallResponseFactory $responseFactory,
        private readonly DecisionRecorder $decisionRecorder,
        private readonly string $mode,
        private readonly string $challengePath,
        private readonly bool $onlyMainRequests,
        private readonly ?LoggerInterface $logger = null
    ) {
    }

    /**
     * Evaluate the request behind this event.
     */
    public function __invoke(RequestEvent $requestEvent): void
    {
        if ($this->mode === 'disabled') {
            return;
        }

        // A forwarded or ESI sub-request carries the same client, the same
        // headers and the same IP as the main request that already passed.
        // Evaluating it again cannot reach a different verdict, but it does
        // increment every per-IP rate limit a second time — so a page with
        // three ESI fragments consumes four requests' worth of budget.
        if ($this->onlyMainRequests && !$requestEvent->isMainRequest()) {
            return;
        }

        $request = $requestEvent->getRequest();

        if ($this->mode === 'observe') {
            $this->warnIfCliSapi();

            if ($this->isChallengeSubmission($request)) {
                return;
            }
        }

        $firewall = $this->firewallFactory->get();

        // NULL means the firewall could not start and the configured policy
        // is fail_open. The factory has already logged that at `critical`.
        if (!$firewall instanceof Firewall) {
            return;
        }

        $this->decisionRecorder->reset();

        try {
            $firewall->evaluate($request);
        } catch (FirewallException $firewallException) {
            // ## Why one catch and a match, rather than four catches
            //
            // Four catches is the shape this wants, and it was the shape it
            // had. `Firewall::evaluate()` does not declare
            // `@throws FirewallRedirectException` — it throws it, from
            // `sendRedirectResponse()`, but the docblock 2.26.0 shipped lists
            // only blocked, challenged, solved and configuration. A static
            // analyser reading that contract calls
            // `catch (FirewallRedirectException)` dead code, and it is right
            // to: a host following the documented contract would never write
            // one, and a `response: redirect` rule in `mode: exception` would
            // then reach the kernel uncaught and serve a 500 instead of a
            // redirect. Reported upstream.
            //
            // Catching the base and dispatching on type says the same thing
            // without depending on that list being complete, which for a
            // listener standing between the library and every request is the
            // more robust place to be anyway.
            $requestEvent->setResponse(match (true) {
                // First, because it is the narrowest and the only one
                // carrying a token.
                $firewallException instanceof ChallengeSolvedException
                    => $this->responseFactory->challengeSolved($firewallException),
                // The exception deliberately does not say whether this is a
                // first challenge or a rejected answer — telling a bot which
                // would be free information — so the same interstitial serves
                // both. It also carries the provider the firewall chose and
                // the context it built, which is what makes a rule with its
                // own `metadata.challenge_provider` renderable here at all.
                $firewallException instanceof ChallengeRequiredException
                    => $this->responseFactory->challengeRequired($firewallException, $request),
                // Terminal and gentler than a refusal: `response: redirect`
                // is a signpost, and the library evaluates it before the
                // block bucket for that reason.
                $firewallException instanceof FirewallRedirectException
                    => $this->responseFactory->redirected($firewallException),
                // `FirewallLockdownException` arrives here too — it extends
                // this one, and the response factory is where the difference
                // (a `Retry-After`) is expressed.
                $firewallException instanceof FirewallBlockedException
                    => $this->responseFactory->blocked($firewallException),
                // Rethrown, which is the same outcome the four catches gave:
                // ConfigurationException and StorageException both mean
                // something an operator configured is not working, and a 500
                // that stops the deploy is the right answer. Swallowing them
                // here would serve unfiltered traffic under a policy named
                // `on_startup_failure`, which this is not.
                default => throw $firewallException,
            });
        }
    }

    /**
     * Is this the POST an interstitial makes when it has an answer?
     *
     * Matches `Firewall::isChallengeSubmission()` on the two things that are
     * observable from here. The library also requires a challenge provider to
     * be wired up; this does not, because the caller only uses the answer to
     * decide *not* to hand the request over, and being over-cautious there
     * costs a POST to one path going unevaluated in a mode that enforces
     * nothing anyway.
     */
    private function isChallengeSubmission(Request $request): bool
    {
        return $request->isMethod('POST')
            && $this->challengePath !== ''
            && $request->getPathInfo() === $this->challengePath;
    }

    /**
     * Say so, once, when `observe` cannot observe anything.
     */
    private function warnIfCliSapi(): void
    {
        if ($this->warnedAboutCliSapi || PHP_SAPI !== 'cli') {
            return;
        }

        $this->warnedAboutCliSapi = true;

        ($this->logger ?? new NullLogger())->warning(
            'kanopi_firewall.mode is "observe" on a CLI SAPI, so no request is being evaluated',
            [
                'sapi' => PHP_SAPI,
                'reason' => 'Firewall::evaluate() returns early when PHP_SAPI is "cli" in every mode but exception.',
                'affects' => 'RoadRunner, Swoole and anything else serving HTTP from the CLI SAPI.',
                'fix' => 'Use kanopi_firewall.mode: enforce, which is exempt from that short-circuit.',
            ]
        );
    }
}
