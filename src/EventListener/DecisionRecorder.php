<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\EventListener;

use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Event\DecisionEvent;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Event\RequestMarked;
use Kanopi\Firewall\Event\RequestRecorded;
use Kanopi\Firewall\Event\RequestRedirected;
use Kanopi\Firewall\Event\RequestTarpitted;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Remembers the verdict the library announced for the current request.
 *
 * Two things need it, and neither can get it any other way.
 *
 * **The interstitial needs to know which provider was chosen.**
 * `sendChallengeResponse()` resolves the provider, announces
 * `RequestChallenged` carrying its name, and *then* throws
 * `ChallengeRequiredException` — which carries only a message. So the
 * provider name is on the event or nowhere. Where a plugin names its own
 * provider (`metadata.challenge_provider`), rendering the default one's
 * interstitial would serve the visitor a puzzle whose answer no rule accepts.
 *
 * **The profiler panel needs to know which rule matched.** Same reason:
 * `FirewallBlockedException` carries a status and a message, not the plugin.
 *
 * The library's contract is that a decision listener cannot change a verdict
 * and that nothing should depend on one running — an exception thrown inside
 * `announce()` is swallowed and logged. This obeys both. It changes nothing,
 * and every consumer degrades rather than fails when the recording is absent:
 * the renderer falls back to the configured default provider, and the panel
 * says the decision is unknown. What it must not do is throw, which is why
 * there is no logic in here beyond an assignment.
 */
final class DecisionRecorder implements EventSubscriberInterface
{
    /**
     * Every decision announced for the current request, in order.
     *
     * @var list<DecisionEvent>
     */
    private array $decisions = [];

    /**
     * {@inheritdoc}
     *
     * Symfony dispatches an object with no name under its own class name, so
     * the library's PSR-14 events are subscribed to by FQCN.
     *
     * @return array<class-string<DecisionEvent>, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            RequestAllowed::class => 'record',
            RequestBlocked::class => 'record',
            RequestChallenged::class => 'record',
            ChallengeSolved::class => 'record',
            ChallengeFailed::class => 'record',
            // The three 2.26.0 added. Subscribing to a fixed list rather
            // than to `DecisionEvent` is what makes this a list that has to
            // be kept up: a decision nobody subscribes to leaves the
            // profiler reporting "not evaluated" for a request the firewall
            // acted on, which is the one reading it must never give.
            RequestRecorded::class => 'record',
            RequestRedirected::class => 'record',
            RequestMarked::class => 'record',
            // Added in 2.30.0, and found by DecisionRecorderTest the day CI
            // resolved it -- which is the test doing exactly its job.
            RequestTarpitted::class => 'record',
        ];
    }

    /**
     * Record a decision.
     *
     * Kept, not replaced. Until kanopi/firewall 2.26.0 one `evaluate()`
     * announced exactly one decision, and "last one wins" was the whole
     * design. `mark`, `record` and `tarpit` made that false: they are
     * non-terminal, so the ladder announces them and carries on — and a
     * request nothing else matches then ends in a default `RequestAllowed`.
     * Keeping only the last event let that allow overwrite the decision that
     * mattered, and the panel said "allowed" for every marked, recorded and
     * tarpitted request (#9).
     */
    public function record(DecisionEvent $decisionEvent): void
    {
        $this->decisions[] = $decisionEvent;
    }

    /**
     * Forget the current decision.
     *
     * Called by the request listener before each evaluation. Under PHP-FPM
     * this is redundant — the process holds one request — but under a worker
     * runtime (RoadRunner, FrankenPHP, Swoole) the container outlives the
     * request, and a stale verdict shown in a later request's profiler, or
     * used to pick a challenge provider for a different visitor, is worse
     * than no verdict at all.
     */
    public function reset(): void
    {
        $this->decisions = [];
    }

    /**
     * The decision that describes this request.
     *
     * The last one announced, except that a default allow following another
     * decision adds nothing to it: "a rule marked this request, and then no
     * rule refused it" is a marked request, not an allowed one. A terminal
     * decision after a non-terminal one — a tarpit and then a block — is
     * still the answer, because it is the one the visitor got.
     *
     * @return DecisionEvent|null
     *   NULL when nothing was announced — the firewall was disabled, skipped
     *   for CLI, or failed to start.
     */
    public function getDecision(): ?DecisionEvent
    {
        foreach (array_reverse($this->decisions) as $decision) {
            if (!$decision instanceof RequestAllowed || $decision->getPlugin() !== null) {
                return $decision;
            }
        }

        return $this->decisions === [] ? null : $this->decisions[count($this->decisions) - 1];
    }

    /**
     * Every decision announced for this request, in order.
     *
     * For what a non-terminal decision adds to a terminal one: the mark on a
     * request that was then blocked, or how long a slow block was held.
     *
     * @return list<DecisionEvent>
     *   Empty when nothing was announced.
     */
    public function getDecisions(): array
    {
        return $this->decisions;
    }

    /**
     * The provider name the library chose for this request's challenge.
     *
     * @return string|null
     *   NULL when the request was not challenged, so the caller falls back
     *   to `challenge.provider`.
     */
    public function getChallengedProvider(): ?string
    {
        $decision = $this->getDecision();

        return $decision instanceof RequestChallenged ? $decision->getProvider() : null;
    }
}
