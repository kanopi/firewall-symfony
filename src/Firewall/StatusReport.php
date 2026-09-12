<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Firewall;

use Kanopi\Firewall\Firewall;

/**
 * What the firewall is currently doing, as one flat set of fields.
 *
 * The answer to "is this thing on?", assembled from the four places that
 * each hold a piece of it and none of which is the whole story:
 *
 *  - the **bundle's** configuration, which decides whether a verdict may
 *    become a response at all;
 *  - the **merged library** configuration, which decides what verdict is
 *    reached, and which is not any one file on disk;
 *  - the **running firewall**, which is the only thing that knows which
 *    rules failed to build and whether the panic switch is down;
 *  - the **storage backend**, which is the only thing that knows how many
 *    clients are actually being refused right now.
 *
 * Every field is a scalar or a list of them, because this is rendered as a
 * table for a person and as an object for a script, and a shape that only
 * works in one of those is a shape that will grow an `if`.
 *
 * ## Why it builds the firewall
 *
 * `failed_rules` cannot be answered without constructing every rule, and
 * constructing a rule is what opens its storage connection. That is the
 * expensive half of this report and it is also the only half that can tell
 * an operator their firewall is running three rules short — which is the
 * failure that looks exactly like a healthy firewall. A status command that
 * skipped it to stay cheap would be reporting the easy part.
 *
 * Every one of those calls can throw: the whole point of
 * `on_startup_failure: fail_closed` is that a firewall which cannot start
 * raises. So each is guarded, and a failure is reported as a field rather
 * than as a stack trace — `bin/console kanopi:firewall:status` on a broken
 * deployment is exactly when an answer is worth most.
 */
final class StatusReport
{
    /**
     * @param string $mode
     *   `kanopi_firewall.mode`.
     * @param int $listenerPriority
     *   `kanopi_firewall.listener.priority`.
     * @param string $loggingMode
     *   The resolved `kanopi_firewall.logging.mode`.
     * @param string $binDir
     *   Where the library's `bin/` scripts are.
     * @param string $libraryVersion
     *   The installed kanopi/firewall version, resolved where the services
     *   are defined — see `Resources/config/services.php`.
     * @param array<int, string|array<string, mixed>> $configInputs
     *   The config inputs the firewall is built from.
     * @param ConfigSnapshot $configSnapshot
     *   The merged library configuration.
     * @param FirewallFactory $firewallFactory
     *   Builds the firewall this process would use.
     * @param BlockManager $blockManager
     *   Reaches the durable block list.
     */
    public function __construct(
        private readonly string $mode,
        private readonly int $listenerPriority,
        private readonly string $loggingMode,
        private readonly string $binDir,
        private readonly string $libraryVersion,
        private readonly array $configInputs,
        private readonly ConfigSnapshot $configSnapshot,
        private readonly FirewallFactory $firewallFactory,
        private readonly BlockManager $blockManager
    ) {
    }

    /**
     * The whole report.
     *
     * @return array<string, mixed>
     *   Field name to value, in the order they should be read.
     */
    public function toArray(): array
    {
        $rules = $this->configSnapshot->rules();
        $enabled = array_filter($rules, static fn (array $rule): bool => $rule['enabled']);

        return array_merge(
            [
                'library_version' => $this->libraryVersion,
                'bundle_mode' => $this->mode,
                'enforcing' => $this->mode === 'enforce',
            ],
            $this->runtime(),
            [
                'rules_enabled' => count($enabled),
                'rules_declared' => count($rules),
                'config_inputs' => $this->inputs(),
                'config_load_errors' => $this->configSnapshot->loadErrors(),
                'storage_type' => $this->configSnapshot->storageType(),
                'lockdown' => $this->lockdown(),
            ],
            $this->storage(),
            [
                'logging_mode' => $this->loggingMode,
                'listener_priority' => $this->listenerPriority,
                'script_dir' => $this->binDir,
            ]
        );
    }

    /**
     * Lockdown, in the words an operator needs mid-incident.
     *
     * Named rather than reported as a boolean beside a count, because the
     * dangerous state is not "on" but "on with nobody allowed" — that
     * refuses the operator reading this report as surely as it refuses
     * everyone else.
     */
    private function lockdown(): string
    {
        $lockdown = $this->configSnapshot->lockdown();

        if (!$lockdown['active']) {
            return 'off';
        }

        return $lockdown['allowed'] === 0
            ? 'ACTIVE, and lockdown_allow is empty — every request is refused'
            : sprintf('ACTIVE, %d allowed range(s)', $lockdown['allowed']);
    }

    /**
     * What the running firewall reports about itself.
     *
     * @return array<string, mixed>
     *   The runtime fields, or the reason there are none.
     */
    private function runtime(): array
    {
        try {
            $firewall = $this->firewallFactory->get();
        } catch (\Throwable $throwable) {
            // Reached under `fail_closed`, which is the default: the
            // firewall could not be built and the factory rethrew. Reported
            // as a field because this is the moment an operator most needs
            // the rest of the report — the configuration, the paths, the
            // storage type are all still worth knowing, and they are what
            // will explain the failure.
            return [
                'firewall_started' => false,
                'startup_error' => $throwable->getMessage(),
            ];
        }

        if (!$firewall instanceof Firewall) {
            // NULL, so the build failed under `fail_open` and the factory
            // logged it at critical. Traffic is being served unfiltered.
            return [
                'firewall_started' => false,
                'startup_error' => 'The firewall could not be built and on_startup_failure is '
                    . 'fail_open, so requests are being served unfiltered. The reason was logged '
                    . 'at critical.',
            ];
        }

        $health = (new HealthReport($firewall))->toArray();

        return [
            'firewall_started' => true,
            'healthy' => $health['healthy'],
            'library_mode' => $health['mode'],
            'panic_switch' => $health['panic_switch']['active']
                ? sprintf('ACTIVE (%s)', $health['panic_switch']['path'] ?? 'unknown path')
                : 'off',
            'rules_not_running' => $health['errors'],
            'degraded_backends' => $health['warnings'],
        ];
    }

    /**
     * What the storage backend reports.
     *
     * @return array<string, mixed>
     *   The backend fields, or the reason there are none.
     */
    private function storage(): array
    {
        try {
            $queryable = $this->blockManager->isQueryable();

            return [
                'storage_backend' => $this->blockManager->backendClass(),
                'storage_queryable' => $queryable,
                // Counted only where it can be counted. A backend that
                // cannot be enumerated answers every read with an empty
                // list, so a `0` here would be a measurement rather than
                // the absence of one.
                'blocks_in_force' => $queryable ? count($this->blockManager->all()) : 'cannot be listed',
            ];
        } catch (\Throwable $throwable) {
            return ['storage_error' => $throwable->getMessage()];
        }
    }

    /**
     * The config inputs, with the inline ones named rather than dumped.
     *
     * @return array<int, string>
     *   One entry per input, in merge order.
     */
    private function inputs(): array
    {
        $inputs = [];

        foreach ($this->configInputs as $input) {
            $inputs[] = is_string($input)
                ? $input
                : sprintf(
                    'kanopi_firewall.settings (%d top-level key%s)',
                    count($input),
                    count($input) === 1 ? '' : 's'
                );
        }

        return $inputs;
    }
}
