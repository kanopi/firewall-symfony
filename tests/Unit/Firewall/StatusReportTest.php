<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Utility\BlockList;
use Kanopi\FirewallBundle\Firewall\BlockManager;
use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Kanopi\FirewallBundle\Firewall\StatusReport;
use Kanopi\FirewallBundle\Tests\Fixtures\OpaqueStorage;
use Kanopi\FirewallBundle\Tests\Fixtures\ReadsStructuredOutput;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(StatusReport::class)]
final class StatusReportTest extends TestCase
{
    use ReadsStructuredOutput;

    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    public function testItAnswersTheQuestionSomebodyRunsItToAsk(): void
    {
        $report = $this->report([self::CONFIG . 'block.yml'])->toArray();

        self::assertSame('v9.9.9', $report['library_version']);
        self::assertSame('enforce', $report['bundle_mode']);
        self::assertTrue($report['enforcing']);
        self::assertTrue($report['firewall_started']);
        self::assertTrue($report['healthy']);
        self::assertSame('exception', $report['library_mode']);
        self::assertSame('off', $report['panic_switch']);
        self::assertSame(1, $report['rules_enabled']);
        self::assertSame(1, $report['rules_declared']);
        self::assertSame([], $report['config_load_errors']);
        self::assertSame(250, $report['listener_priority']);
        self::assertSame('replace', $report['logging_mode']);
    }

    public function testObserveIsNotEnforcing(): void
    {
        // The one field a deploy script is most likely to read, and the one
        // that a mode string alone makes somebody think about twice.
        $report = $this->report([self::CONFIG . 'block.yml'], mode: 'observe')->toArray();

        self::assertSame('observe', $report['bundle_mode']);
        self::assertFalse($report['enforcing']);
    }

    public function testTheInlineSettingsArrayIsNamedRatherThanDumped(): void
    {
        // A status table with a nested rule set pasted into one cell is not
        // a status table.
        $report = $this->report([
            self::CONFIG . 'block.yml',
            ['global' => ['banning_status_code' => 429], 'plugins' => []],
        ])->toArray();

        self::assertSame(
            [self::CONFIG . 'block.yml', 'kanopi_firewall.settings (2 top-level keys)'],
            $report['config_inputs']
        );
    }

    public function testOneSettingIsOneKeyAndNotOneKeys(): void
    {
        $report = $this->report([self::CONFIG . 'block.yml', ['plugins' => []]])->toArray();

        self::assertSame(
            [self::CONFIG . 'block.yml', 'kanopi_firewall.settings (1 top-level key)'],
            $report['config_inputs']
        );
    }

    public function testAnInputThatFailedToLoadIsOnTheReport(): void
    {
        $report = $this->report([self::CONFIG . 'block.yml', self::CONFIG . 'missing.yml'])->toArray();

        self::assertCount(1, $this->listAt($report, 'config_load_errors'));
        self::assertStringContainsString('missing.yml', $this->text($report, 'config_load_errors', 0));
    }

    public function testLockdownWithAnEmptyAllowlistSaysWhatThatMeans(): void
    {
        // The dangerous state is not "on", it is "on with nobody allowed" —
        // which refuses the operator reading this report too.
        $configs = [[
            'global' => ['behind_proxy' => false, 'lockdown' => true],
            'storage' => ['type' => InMemoryStorage::class],
            'logger' => ['handlers' => [['class' => 'Monolog\\Handler\\NullHandler']]],
            'plugins' => [['plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress', 'config' => ['203.0.113.5']]],
        ]];

        self::assertSame(
            'ACTIVE, and lockdown_allow is empty — every request is refused',
            $this->report($configs)->toArray()['lockdown']
        );
    }

    public function testLockdownWithAnAllowlistCountsIt(): void
    {
        $configs = [[
            'global' => [
                'behind_proxy' => false,
                'lockdown' => true,
                'lockdown_allow' => ['198.51.100.0/24'],
            ],
            'storage' => ['type' => InMemoryStorage::class],
            'logger' => ['handlers' => [['class' => 'Monolog\\Handler\\NullHandler']]],
            'plugins' => [['plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress', 'config' => ['203.0.113.5']]],
        ]];

        self::assertSame('ACTIVE, 1 allowed range(s)', $this->report($configs)->toArray()['lockdown']);
    }

    public function testNoLockdownIsReportedAsOff(): void
    {
        self::assertSame('off', $this->report([self::CONFIG . 'block.yml'])->toArray()['lockdown']);
    }

    public function testTheStorageBackendIsAskedRatherThanInferredFromConfiguration(): void
    {
        // `storage_type` is what was configured; `storage_backend` is what
        // answered. They agree here, and the pair is the point: a type that
        // could not be built would show the difference.
        $report = $this->report([self::CONFIG . 'block.yml'])->toArray();

        self::assertSame(InMemoryStorage::class, $report['storage_type']);
        self::assertSame(InMemoryStorage::class, $report['storage_backend']);
        self::assertTrue($report['storage_queryable']);
        self::assertSame(0, $report['blocks_in_force']);
    }

    public function testABackendThatCannotBeListedSaysSoRatherThanReportingZero(): void
    {
        // A `0` would be a measurement. This is the absence of one.
        $configs = [[
            'global' => ['behind_proxy' => false],
            'storage' => ['type' => OpaqueStorage::class],
            'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
            'plugins' => [],
        ]];

        $report = $this->report($configs)->toArray();

        self::assertFalse($report['storage_queryable']);
        self::assertSame('cannot be listed', $report['blocks_in_force']);
    }

    public function testABlockThatIsInForceIsCounted(): void
    {
        $configs = [[
            'global' => ['behind_proxy' => false],
            'storage' => ['type' => InMemoryStorage::class],
            'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
            'plugins' => [],
        ]];

        // The same BlockList the report will read, so the write is visible:
        // in-memory storage is per-instance, which is exactly why the doctor
        // warns about it.
        $blockList = new BlockList($configs);
        $blocks = new BlockManager($blockList);
        $blocks->add('198.51.100.9', 600);

        self::assertSame(1, $this->report($configs, blockManager: $blocks)->toArray()['blocks_in_force']);
    }

    public function testAStorageBackendThatCannotBeReachedIsAFieldAndNotAStackTrace(): void
    {
        // `bin/console kanopi:firewall:status` on a broken deployment is
        // exactly when the rest of the report is worth most.
        $report = $this->report([self::CONFIG . 'broken-storage.yml'])->toArray();

        self::assertIsString($report['storage_error']);
        self::assertArrayNotHasKey('blocks_in_force', $report);
        self::assertSame(
            self::CONFIG . 'broken-storage.yml',
            $this->text($report, 'config_inputs', 0),
            'the rest still reports'
        );
    }

    public function testAFirewallThatCannotStartIsReportedRatherThanRethrown(): void
    {
        // fail_closed, the default: the factory rethrows. The command has to
        // survive that to be able to explain it.
        $report = $this->report([self::CONFIG . 'broken-storage.yml'])->toArray();

        self::assertFalse($report['firewall_started']);
        self::assertIsString($report['startup_error']);
        self::assertArrayNotHasKey('healthy', $report);
    }

    public function testFailOpenIsReportedAsUnfilteredTrafficAndNotAsHealth(): void
    {
        // NULL from the factory means the build failed and the policy is to
        // serve anyway. "Started: no" is the only honest reading.
        $report = $this->report([self::CONFIG . 'broken-storage.yml'], onStartupFailure: 'fail_open')->toArray();

        self::assertFalse($report['firewall_started']);
        self::assertStringContainsString('served unfiltered', $this->text($report, 'startup_error'));
    }

    public function testAPanicSwitchThatIsDownIsOnTheReportWithItsPath(): void
    {
        // The realistic failure is nobody noticing three weeks later that
        // it is still on, so the path is printed: it is what has to be
        // deleted.
        $panicFile = tempnam(sys_get_temp_dir(), 'kanopi-panic-');
        file_put_contents((string) $panicFile, 'log');

        try {
            $configs = [[
                'global' => ['behind_proxy' => false, 'panic_file' => $panicFile],
                'storage' => ['type' => InMemoryStorage::class],
                'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
                'plugins' => [['plugin' => 'Kanopi\Firewall\Plugins\IpAddress', 'config' => ['203.0.113.5']]],
            ]];

            $report = $this->report($configs)->toArray();

            self::assertStringContainsString('ACTIVE', $this->text($report, 'panic_switch'));
            self::assertStringContainsString((string) $panicFile, $this->text($report, 'panic_switch'));
            self::assertSame('log', $report['library_mode'], 'the switch is what is in force');
        } finally {
            unlink((string) $panicFile);
        }
    }

    public function testRulesPulledInByAnIncludeAreCounted(): void
    {
        // The rule is in a file the bundle never names — the point of
        // reporting the merge rather than the inputs.
        $report = $this->report([self::CONFIG . 'includes-block.yml'])->toArray();

        self::assertSame(1, $report['rules_declared']);
        self::assertSame(1, $report['rules_enabled']);
    }

    /**
     * A report over real collaborators.
     *
     * @param array<int, string|array<string, mixed>> $configs
     *   The config inputs.
     * @param string $mode
     *   `kanopi_firewall.mode`.
     * @param string $onStartupFailure
     *   `fail_closed` or `fail_open`.
     * @param BlockManager|null $blockManager
     *   A manager sharing state with the caller, for the counting test.
     */
    private function report(
        array $configs,
        string $mode = 'enforce',
        string $onStartupFailure = 'fail_closed',
        ?BlockManager $blockManager = null
    ): StatusReport {
        $overrides = ['[global][mode]' => 'exception'];

        return new StatusReport(
            $mode,
            250,
            'replace',
            '/vendor/bin',
            'v9.9.9',
            $configs,
            new ConfigSnapshot($configs, $overrides),
            new FirewallFactory(
                $configs,
                $overrides,
                new ProxyPosture(false),
                new LoggerBridge('off'),
                $onStartupFailure
            ),
            $blockManager ?? new BlockManager(new BlockList($configs))
        );
    }
}
