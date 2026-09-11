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
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Builds the one `Firewall` this process uses, and owns what happens if it
 * cannot be built.
 *
 * ## Why a factory rather than a container service
 *
 * `Firewall` is `final` with a `protected` constructor and a `create()` that
 * hard-codes `new self`, so it cannot be proxied — which rules out Symfony's
 * lazy services. Constructing it eagerly is not acceptable either: `create()`
 * reads YAML, opens the storage backend and can reach a database, and that
 * would happen on every request including the ones the listener is about to
 * skip (a sub-request, a disabled firewall, a console command). A factory the
 * listener calls at the last possible moment gets laziness without a proxy.
 *
 * ## Why the failure policy lives here
 *
 * The library's error-handling guide is explicit that fail-open versus
 * fail-closed is the integrator's decision and that the library will not make
 * it. This is the integrator. `fail_closed` rethrows, so a
 * `ConfigurationException` or an unreachable storage backend surfaces as a
 * 500 — loud, and correct for anything where serving unfiltered traffic is
 * worse than serving an error. `fail_open` logs at `critical` and returns
 * NULL, and the listener lets the request through.
 *
 * Either way the outcome is memoized. A firewall that cannot start will not
 * start on the next request either, and retrying a database connection that
 * is refusing on every request in the pool turns a filtering outage into a
 * latency outage.
 */
final class FirewallFactory
{
    /**
     * Whether `create()` has been attempted, successfully or not.
     */
    private bool $attempted = false;

    /**
     * The built firewall, or NULL when the build failed under `fail_open`.
     */
    private ?Firewall $firewall = null;

    /**
     * @param array<int, string|array<string, mixed>> $configs
     *   YAML paths and/or config arrays, in merge order, as
     *   `Firewall::create()` takes them.
     * @param array<string, mixed> $overrides
     *   PropertyAccess bracket paths applied after the merge.
     * @param ProxyPosture $proxyPosture
     *   Contributes `global.behind_proxy`, which can only be answered once
     *   the kernel has applied `framework.trusted_proxies` — so it is
     *   merged here rather than baked into $overrides at compile time.
     * @param LoggerBridge $loggerBridge
     *   Applied immediately after `create()`, which is the only moment it can
     *   take effect — see LoggerBridge.
     * @param string $onStartupFailure
     *   `fail_closed` or `fail_open`.
     * @param LoggerInterface|null $logger
     *   Where a `fail_open` build failure is reported. Deliberately the
     *   application's logger and not the library's: the library's logger is
     *   configured by the config that just failed to load. NULL when the
     *   application has no `logger` service, which is what an installation
     *   without MonologBundle looks like.
     * @param EventDispatcherInterface|null $eventDispatcher
     *   Passed straight through to `create()`. Symfony's dispatcher is a
     *   PSR-14 dispatcher, so no adapter is needed.
     */
    public function __construct(
        private readonly array $configs,
        private readonly array $overrides,
        private readonly ProxyPosture $proxyPosture,
        private readonly LoggerBridge $loggerBridge,
        private readonly string $onStartupFailure,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?EventDispatcherInterface $eventDispatcher = null
    ) {
    }

    /**
     * The firewall, built on first call.
     *
     * @return Firewall|null
     *   NULL only when the build failed and the policy is `fail_open`.
     *
     * @throws \Throwable
     *   Whatever `Firewall::create()` threw, when the policy is
     *   `fail_closed`. `ConfigurationException` and `StorageException` are
     *   the documented ones; the catch is wider because a malformed
     *   `plugins:` entry can surface as a TypeError from deeper in the
     *   library, and swallowing that under `fail_open` while letting it
     *   escape under `fail_closed` would make the policy a half-truth.
     */
    public function get(): ?Firewall
    {
        if ($this->attempted) {
            return $this->firewall;
        }

        $this->attempted = true;

        try {
            $this->firewall = Firewall::create(
                $this->configs,
                array_merge($this->overrides, $this->proxyPosture->overrides()),
                $this->eventDispatcher
            );
        } catch (\Throwable $throwable) {
            if ($this->onStartupFailure === 'fail_closed') {
                throw $throwable;
            }

            ($this->logger ?? new NullLogger())->critical(
                'The firewall could not start; this request and every other one is unfiltered',
                [
                    'error' => $throwable->getMessage(),
                    'error_type' => $throwable::class,
                    'policy' => 'fail_open',
                ]
            );

            return null;
        }

        $this->loggerBridge->apply();

        return $this->firewall;
    }
}
