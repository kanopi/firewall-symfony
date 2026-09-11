<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\DataCollector;

use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Event\DecisionEvent;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Firewall;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\VarDumper\Cloner\Data;

/**
 * The WebProfiler panel: what the firewall decided, and whether it is
 * healthy enough for that decision to mean anything.
 *
 * The second half is the part worth having. `getFailedRules()` reports rules
 * that could not be constructed and are therefore **not running**;
 * `getDegradedBackends()` reports backends that are running and have nothing
 * to consult — a Redis rate limiter that cannot reach Redis counts nothing
 * and allows everyone, while looking completely healthy from the outside.
 * A firewall running three rules short is indistinguishable, in a log, from
 * a firewall running correctly. This panel is where that stops being true.
 */
final class FirewallDataCollector extends DataCollector
{
    /**
     * Panel identifier, and the Twig variable the template is given.
     */
    public const NAME = 'kanopi_firewall';

    /**
     * @param DecisionRecorder $decisionRecorder
     *   Holds this request's verdict.
     * @param FirewallFactory $firewallFactory
     *   For the mode, the panic switch and the health lists.
     * @param string $mode
     *   `kanopi_firewall.mode`. Needed because `disabled` is a bundle-level
     *   state with no library equivalent — the listener returns before the
     *   firewall exists, so asking the firewall what mode it is in would
     *   both build the thing the listener avoided and answer `exception`,
     *   which is the mode it would have run in and not the one in force.
     * @param bool $collectHealth
     *   Whether to include the two health lists.
     */
    public function __construct(
        private readonly DecisionRecorder $decisionRecorder,
        private readonly FirewallFactory $firewallFactory,
        private readonly string $mode = 'enforce',
        private readonly bool $collectHealth = true
    ) {
        $this->data = [];
    }

    /**
     * {@inheritdoc}
     */
    public function collect(Request $request, Response $response, ?\Throwable $throwable = null): void
    {
        $decision = $this->decisionRecorder->getDecision();

        $this->data = [
            'verdict' => $this->verdict($decision),
            'enforced' => $decision instanceof DecisionEvent ? $decision->isEnforced() : null,
            'rule' => $this->rule($decision),
            'status_code' => $decision instanceof RequestBlocked ? $decision->getStatusCode() : null,
            'provider' => $this->provider($decision),
            'reason' => $decision instanceof ChallengeFailed ? $decision->getReason() : null,
            'mode' => null,
            'configured_mode' => null,
            'panic_switch' => null,
            'failed_rules' => [],
            'degraded_backends' => [],
            'error' => null,
        ];

        if ($this->mode === 'disabled') {
            $this->data['mode'] = 'disabled';
            $this->data['configured_mode'] = 'disabled';

            return;
        }

        try {
            $firewall = $this->firewallFactory->get();
        } catch (\Throwable $factoryFailure) {
            // A firewall that could not start under `fail_closed` has already
            // turned this request into an error page; the panel's job is then
            // to say why, not to throw a second time and lose the profile
            // along with it.
            $this->data['error'] = $factoryFailure->getMessage();

            return;
        }

        if (!$firewall instanceof Firewall) {
            $this->data['error'] = 'The firewall did not start, and the fail_open policy let the request through.';

            return;
        }

        $this->data['mode'] = $firewall->getMode()->value;
        $this->data['configured_mode'] = $firewall->getConfiguredMode()->value;
        $this->data['panic_switch'] = $this->panicSwitch($firewall);

        // Both of these build every rule that is not built yet, which is what
        // opens a storage connection — the library's docs are explicit that
        // they belong in a health check and not on a request path. On a
        // request that was evaluated, every rule is already built and this
        // costs nothing. On one that was not — a sub-request, a disabled
        // firewall, a CLI SAPI in observe mode — it would be the first thing
        // to build them, adding connection latency to a request that
        // deliberately did no firewall work at all.
        if (!$this->collectHealth || !$decision instanceof DecisionEvent) {
            return;
        }

        $this->data['failed_rules'] = $firewall->getFailedRules();
        $this->data['degraded_backends'] = $firewall->getDegradedBackends();
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): void
    {
        $this->data = [];
    }

    /**
     * Everything the template renders.
     *
     * One accessor rather than fifteen. The profiler stores `$this->data`
     * serialized, so the template is reading a plain array either way, and
     * a wall of one-line getters would only be there to hide that.
     *
     * @return array<string, mixed>
     *   Empty before `collect()` runs.
     */
    public function getData(): array
    {
        // `DataCollector::$data` is typed `array|Data` for collectors that
        // store cloned variables. This one never does — everything it keeps
        // is already a scalar or a plain array, so it survives the
        // profiler's serialization on its own — but the property type is
        // the parent's, so the narrowing has to be stated.
        /** @var array<string, mixed> */
        return $this->data instanceof Data ? $this->data->getValue(true) : $this->data;
    }

    /**
     * A one-word verdict for the toolbar.
     */
    private function verdict(?DecisionEvent $decision): string
    {
        return match (true) {
            $decision instanceof RequestBlocked => 'blocked',
            $decision instanceof RequestChallenged => 'challenged',
            $decision instanceof ChallengeSolved => 'challenge solved',
            $decision instanceof ChallengeFailed => 'challenge failed',
            $decision instanceof RequestAllowed => $decision->wasBypassed() ? 'bypassed' : 'allowed',
            default => 'not evaluated',
        };
    }

    /**
     * The rule that produced the verdict, if a rule did.
     *
     * @return array{name: string, class: string}|null
     *   NULL for a default allow, and for a durable block-list hit — which
     *   is a rule nobody wrote, it is a ban somebody earned earlier.
     */
    private function rule(?DecisionEvent $decision): ?array
    {
        $plugin = match (true) {
            $decision instanceof RequestBlocked, $decision instanceof RequestAllowed => $decision->getPlugin(),
            $decision instanceof RequestChallenged => $decision->getPlugin(),
            default => null,
        };

        return $plugin === null ? null : ['name' => $plugin->getName(), 'class' => $plugin::class];
    }

    /**
     * The challenge provider involved, if any.
     */
    private function provider(?DecisionEvent $decision): ?string
    {
        return match (true) {
            $decision instanceof RequestChallenged,
            $decision instanceof ChallengeSolved,
            $decision instanceof ChallengeFailed => $decision->getProvider(),
            default => null,
        };
    }

    /**
     * The panic switch, flattened for storage.
     *
     * `getPanicSwitch()` returns a `FirewallMode` enum, and the profiler
     * serializes what it is given — so the enum is reduced to its value
     * here rather than left for a template to unwrap.
     *
     * @return array{active: bool, mode: string|null, path: string|null, problem: string|null}
     */
    private function panicSwitch(Firewall $firewall): array
    {
        $panic = $firewall->getPanicSwitch();

        return [
            'active' => $panic['active'],
            'mode' => $panic['mode']?->value,
            'path' => $panic['path'],
            'problem' => $panic['problem'],
        ];
    }
}
