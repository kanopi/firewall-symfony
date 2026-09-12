<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Kanopi\FirewallBundle\Tests\Fixtures\ReadsStructuredOutput;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ConfigSnapshot::class)]
final class ConfigSnapshotTest extends TestCase
{
    use ReadsStructuredOutput;

    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    public function testItReportsTheMergeRatherThanAnyOneInput(): void
    {
        // The point of the class: what runs is the merge, and no file on
        // disk contains it.
        $snapshot = new ConfigSnapshot(
            [self::CONFIG . 'block.yml', ['global' => ['banning_status_code' => 429]]],
            ['[global][mode]' => 'log']
        );

        $config = $snapshot->all();

        self::assertSame('log', $this->text($config, 'global', 'mode'), 'the override lands last');
        self::assertSame(429, $this->at($config, 'global', 'banning_status_code'), 'the inline array merged');
        self::assertSame(
            'Blocked: {{request.ip}}',
            $this->text($config, 'global', 'banning_message'),
            'the file merged'
        );
    }

    public function testTheMergeHappensOnce(): void
    {
        $snapshot = new ConfigSnapshot([['global' => ['mode' => 'log']]], []);

        self::assertSame($snapshot->all(), $snapshot->all());
    }

    public function testRulesComeBackInEvaluationOrderAndNotFileOrder(): void
    {
        // Weight is what the library sorts on. A list in declaration order
        // would show an operator a sequence the firewall does not use.
        $snapshot = new ConfigSnapshot([[
            'plugins' => [
                ['plugin' => 'A', 'weight' => 10, 'metadata' => ['name' => 'last']],
                ['plugin' => 'B', 'weight' => -100, 'metadata' => ['name' => 'first']],
                ['plugin' => 'C', 'metadata' => ['name' => 'middle']],
            ],
        ]], []);

        self::assertSame(
            ['first', 'middle', 'last'],
            array_column($snapshot->rules(), 'name')
        );
    }

    public function testRulesOfEqualWeightKeepTheOrderTheyWereDeclaredIn(): void
    {
        $snapshot = new ConfigSnapshot([[
            'plugins' => [
                ['plugin' => 'A', 'metadata' => ['name' => 'one']],
                ['plugin' => 'B', 'metadata' => ['name' => 'two']],
            ],
        ]], []);

        self::assertSame(['one', 'two'], array_column($snapshot->rules(), 'name'));
    }

    public function testARuleWithNoNameIsCalledWhatTheLogWillCallIt(): void
    {
        $snapshot = new ConfigSnapshot([[
            'plugins' => [['plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress']],
        ]], []);

        self::assertSame('IpAddress', $snapshot->rules()[0]['name']);
    }

    public function testARuleWithNoPluginAtAllIsStillListed(): void
    {
        // A malformed entry is exactly what somebody is looking for when
        // they run this, so it is shown rather than skipped.
        $snapshot = new ConfigSnapshot([['plugins' => [['response' => 'allow'], 'not-an-entry']]], []);

        $rules = $snapshot->rules();

        self::assertCount(1, $rules, 'a plugins entry that is not an array cannot be described');
        self::assertSame('(none)', $rules[0]['name']);
        self::assertSame('allow', $rules[0]['response']);
    }

    public function testAbsentEnableMeansEnabled(): void
    {
        // The library's own reading: a rule is written to be evaluated, and
        // `enable: false` is how it is parked.
        $snapshot = new ConfigSnapshot([[
            'plugins' => [
                ['plugin' => 'A', 'metadata' => ['name' => 'implicit']],
                ['plugin' => 'B', 'enable' => false, 'metadata' => ['name' => 'parked']],
            ],
        ]], []);

        $rules = array_column($snapshot->rules(), 'enabled', 'name');

        self::assertTrue($rules['implicit']);
        self::assertFalse($rules['parked']);
    }

    public function testEntriesCountsWhatARuleActuallyMatchesOn(): void
    {
        $snapshot = new ConfigSnapshot([[
            'plugins' => [
                ['plugin' => 'A', 'config' => ['203.0.113.1', '203.0.113.2'], 'metadata' => ['name' => 'two']],
                ['plugin' => 'B', 'metadata' => ['name' => 'none']],
            ],
        ]], []);

        $entries = array_column($snapshot->rules(), 'entries', 'name');

        self::assertSame(2, $entries['two']);
        self::assertSame(0, $entries['none'], 'usually a source that has never been fetched');
    }

    public function testTheDefaultResponseAndWeightAreTheLibrarys(): void
    {
        $snapshot = new ConfigSnapshot([['plugins' => [['plugin' => 'A']]]], []);

        self::assertSame('block', $snapshot->rules()[0]['response']);
        self::assertSame(0, $snapshot->rules()[0]['weight']);
    }

    public function testLockdownIsReportedBecauseNoModeFieldShowsIt(): void
    {
        // A flag, not a mode, so every field that reports a mode says
        // "exception" while the site refuses everybody.
        $snapshot = new ConfigSnapshot([[
            'global' => ['lockdown' => true, 'lockdown_allow' => ['198.51.100.0/24', '203.0.113.0/24']],
        ]], []);

        self::assertSame(['active' => true, 'allowed' => 2], $snapshot->lockdown());
    }

    public function testLockdownAsAModeIsStillLockdown(): void
    {
        // `mode: lockdown` is documented shorthand for the flag, including
        // from a panic file — reading only the flag would report "off" for a
        // firewall refusing every request.
        $snapshot = new ConfigSnapshot([['global' => ['mode' => 'lockdown']]], []);

        self::assertSame(['active' => true, 'allowed' => 0], $snapshot->lockdown());
    }

    public function testNoLockdownIsTheOrdinaryCase(): void
    {
        $snapshot = new ConfigSnapshot([['global' => ['mode' => 'exception']]], []);

        self::assertSame(['active' => false, 'allowed' => 0], $snapshot->lockdown());
    }

    public function testAnInputThatFailedToLoadIsReportedRatherThanIgnored(): void
    {
        // The quietest failure in the system: loading is lenient, so an
        // unreadable file leaves the firewall running on whatever else
        // merged, and a firewall with no rules allows everything.
        $snapshot = new ConfigSnapshot([self::CONFIG . 'does-not-exist.yml'], []);

        $errors = $snapshot->loadErrors();

        self::assertCount(1, $errors);
        self::assertStringContainsString('does-not-exist.yml', $errors[0]);
    }

    public function testNothingIsReportedWhenEverythingLoaded(): void
    {
        self::assertSame([], (new ConfigSnapshot([self::CONFIG . 'block.yml'], []))->loadErrors());
    }

    public function testTheStorageTypeAndLibraryModeAreReadFromTheMerge(): void
    {
        $snapshot = new ConfigSnapshot([self::CONFIG . 'block.yml'], ['[global][mode]' => 'exception']);

        self::assertSame('Kanopi\Firewall\Storage\InMemoryStorage', $snapshot->storageType());
        self::assertSame('exception', $snapshot->libraryMode());
    }

    public function testTheDefaultsAreStatedWhenTheConfigurationSaysNothing(): void
    {
        $snapshot = new ConfigSnapshot([['plugins' => []]], []);

        self::assertSame('', $snapshot->storageType(), 'no storage type is different from a default one');
        self::assertSame('block', $snapshot->libraryMode(), 'the library\'s own default');
    }
}
