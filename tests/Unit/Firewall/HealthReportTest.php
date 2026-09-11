<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Utility\DegradedBackends;
use Kanopi\FirewallBundle\Firewall\HealthReport;
use Kanopi\FirewallBundle\Tests\Fixtures\FailingPlugin;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HealthReport::class)]
final class HealthReportTest extends TestCase
{
    /**
     * Panic file for the test that needs one.
     */
    private string $panicFile = '';

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        // Static on the library, and every test in the run shares it. A
        // report that inherited another test's degraded backend would pass
        // or fail depending on the order the suite happened to run in.
        DegradedBackends::reset();
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        DegradedBackends::reset();

        if ($this->panicFile !== '' && is_file($this->panicFile)) {
            unlink($this->panicFile);
        }
    }

    public function testAFirewallWithEveryRuleRunningIsHealthy(): void
    {
        $report = (new HealthReport($this->firewall()))->toArray();

        self::assertTrue($report['healthy']);
        self::assertSame([], $report['errors']);
        self::assertSame([], $report['warnings']);
        self::assertSame([], $report['failed_rules']);
        self::assertFalse($report['panic_switch']['active']);
        self::assertNull($report['panic_switch']['mode'], 'the enum is flattened for JSON');
    }

    public function testTheModeIsReportedBesideTheConfiguredOne(): void
    {
        // Both, because the effective mode alone cannot distinguish
        // "somebody configured log" from "somebody is holding the panic
        // switch down", and only one of those is meant to be temporary.
        $report = (new HealthReport($this->firewall(overrides: ['[global][mode]' => 'log'])))->toArray();

        self::assertSame('log', $report['mode']);
        self::assertSame('log', $report['configured_mode']);
        self::assertFalse($report['mode_overridden']);
    }

    public function testARuleThatIsNotRunningMakesTheFirewallUnhealthy(): void
    {
        // The failure this class exists for: the rule is skipped, the
        // request is evaluated by the rules that did build, and for a block
        // rule that is a fail-open nothing else reports.
        $report = (new HealthReport($this->firewall(withFailingRule: true)))->toArray();

        self::assertFalse($report['healthy']);
        self::assertCount(1, $report['failed_rules']);
        self::assertSame('block', $report['failed_rules'][0]['bucket']);
        self::assertCount(1, $report['errors']);
        self::assertStringContainsString('is not running', $report['errors'][0]);
        self::assertStringContainsString('refused the connection', $report['errors'][0]);
    }

    public function testABackendRunningWithoutItsStoreIsAWarningAndNotAFailure(): void
    {
        // Deliberate: the firewall is still enforcing every rule that does
        // not depend on that store, which is the degrade the library chose.
        // Paging somebody because Redis blipped while the block list kept
        // working is how a monitor gets muted.
        DegradedBackends::record('rate limit', 'RedisRateLimitStorage', 'connection refused');

        $report = (new HealthReport($this->firewall()))->toArray();

        self::assertTrue($report['healthy']);
        self::assertSame([], $report['errors']);
        self::assertCount(1, $report['warnings']);
        self::assertStringContainsString('rate limit is running without its store', $report['warnings'][0]);
        self::assertStringContainsString('connection refused', $report['warnings'][0]);
    }

    public function testAPanicSwitchThatIsDownIsReportedAsAWarning(): void
    {
        // The realistic failure is not somebody flipping it during an
        // incident; it is nobody noticing three weeks later.
        $this->panicFile = tempnam(sys_get_temp_dir(), 'kanopi-panic-');
        file_put_contents($this->panicFile, 'log');

        $report = (new HealthReport($this->firewall(panicFile: $this->panicFile)))->toArray();

        self::assertTrue($report['panic_switch']['active']);
        self::assertSame('log', $report['panic_switch']['mode']);
        self::assertTrue($report['mode_overridden'], 'the effective mode is no longer the configured one');
        self::assertCount(1, $report['warnings']);
        self::assertStringContainsString('panic switch is ACTIVE', $report['warnings'][0]);
        self::assertStringContainsString($this->panicFile, $report['warnings'][0]);
    }

    public function testAPanicFileThatDidNotTakeIsAnErrorRatherThanAWarning(): void
    {
        // Somebody reached for the switch and it did not work, and they are
        // watching the site rather than the logs to find that out.
        $this->panicFile = tempnam(sys_get_temp_dir(), 'kanopi-panic-');
        file_put_contents($this->panicFile, 'not-a-mode');

        $report = (new HealthReport($this->firewall(panicFile: $this->panicFile)))->toArray();

        self::assertFalse($report['panic_switch']['active']);
        self::assertIsString($report['panic_switch']['problem']);
        self::assertCount(1, $report['errors']);
        self::assertStringContainsString('was not applied', $report['errors'][0]);
    }

    /**
     * A real firewall, because `Firewall` is final with a protected
     * constructor and cannot be doubled.
     *
     * @param bool $withFailingRule
     *   Add a rule whose constructor throws.
     * @param string|null $panicFile
     *   `global.panic_file`, for the tests about the switch.
     * @param array<string, mixed> $overrides
     *   Applied after the configuration, as `Firewall::create()` takes them.
     */
    private function firewall(
        bool $withFailingRule = false,
        ?string $panicFile = null,
        array $overrides = []
    ): Firewall {
        $global = ['behind_proxy' => false];

        if ($panicFile !== null) {
            $global['panic_file'] = $panicFile;
        }

        return Firewall::create([[
            'global' => $global,
            'storage' => ['type' => 'Kanopi\Firewall\Storage\InMemoryStorage'],
            'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
            'plugins' => $withFailingRule
                ? [['plugin' => FailingPlugin::class, 'response' => 'block', 'enable' => true, 'config' => ['x']]]
                : [],
        ]], $overrides);
    }
}
