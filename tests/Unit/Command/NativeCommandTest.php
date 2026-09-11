<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Utility\BlockList;
use Kanopi\FirewallBundle\Command\AbstractFirewallCommand;
use Kanopi\FirewallBundle\Command\BlockCommand;
use Kanopi\FirewallBundle\Command\ConfigCommand;
use Kanopi\FirewallBundle\Command\FindReferenceCommand;
use Kanopi\FirewallBundle\Command\HealthCommand;
use Kanopi\FirewallBundle\Command\RulesCommand;
use Kanopi\FirewallBundle\Command\StatusCommand;
use Kanopi\FirewallBundle\Command\UnblockCommand;
use Kanopi\FirewallBundle\Firewall\BlockManager;
use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Kanopi\FirewallBundle\Firewall\StatusReport;
use Kanopi\FirewallBundle\Tests\Fixtures\OpaqueStorage;
use Kanopi\FirewallBundle\Tests\Fixtures\ReadsStructuredOutput;
use Kanopi\FirewallBundle\Tests\Fixtures\RefusingStorage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(AbstractFirewallCommand::class)]
#[CoversClass(BlockCommand::class)]
#[CoversClass(ConfigCommand::class)]
#[CoversClass(FindReferenceCommand::class)]
#[CoversClass(HealthCommand::class)]
#[CoversClass(RulesCommand::class)]
#[CoversClass(StatusCommand::class)]
#[CoversClass(UnblockCommand::class)]
final class NativeCommandTest extends TestCase
{
    use ReadsStructuredOutput;

    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    /**
     * The bundle's config inputs for most of these tests.
     *
     * @var array<int, string|array<string, mixed>>
     */
    private array $configs = [];

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        $this->configs = [self::CONFIG . 'block.yml'];
    }

    public function testStatusAnswersTheFirstQuestionAnybodyAsks(): void
    {
        $tester = $this->tester(new StatusCommand($this->statusReport()));

        self::assertSame(0, $tester->execute([]));
        self::assertStringContainsString('Bundle mode', $tester->getDisplay());
        self::assertStringContainsString('enforce', $tester->getDisplay());
    }

    public function testStatusFailsOnlyWhenTheFirewallCouldNotBeBuilt(): void
    {
        // A report that returned 0 while saying "the firewall could not be
        // built" would be a report nothing can gate on.
        $this->configs = [self::CONFIG . 'broken-storage.yml'];

        $tester = $this->tester(new StatusCommand($this->statusReport()));

        self::assertSame(1, $tester->execute([]));
        self::assertStringContainsString('Startup error', $tester->getDisplay());
    }

    public function testAMistypedFormatIsRefusedWithTheOnesThatWork(): void
    {
        // Exit 2, not 1: "the arguments made no sense" rather than "the
        // firewall said no", which a script reads differently.
        $tester = $this->tester(new StatusCommand($this->statusReport()));

        self::assertSame(2, $tester->execute(['--format' => 'xml']));
        self::assertStringContainsString('Unknown --format "xml"', $tester->getDisplay());
        self::assertStringContainsString('table, json, yaml', $tester->getDisplay());
    }

    public function testHealthIsShapedForAProbe(): void
    {
        $tester = $this->tester(new HealthCommand($this->factory()));

        self::assertSame(0, $tester->execute(['--format' => 'json']));

        $report = $this->decode($tester->getDisplay());
        self::assertTrue($report['healthy']);
        self::assertSame([], $this->listAt($report, 'errors'));
        self::assertArrayHasKey('panic_switch', $report);
    }

    public function testHealthFailsWhenARuleIsNotRunning(): void
    {
        $this->configs = [[
            'global' => ['behind_proxy' => false],
            'storage' => ['type' => InMemoryStorage::class],
            'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
            'plugins' => [[
                'plugin' => \Kanopi\FirewallBundle\Tests\Fixtures\FailingPlugin::class,
                'response' => 'block',
                'enable' => true,
                'config' => ['x'],
            ]],
        ]];

        $tester = $this->tester(new HealthCommand($this->factory()));

        self::assertSame(1, $tester->execute([]));
        self::assertStringContainsString('is not running', $tester->getDisplay());
    }

    public function testHealthPassesAWarningUnlessAskedToBeStrict(): void
    {
        // A degraded backend is a warning by design: the firewall is still
        // enforcing every rule that does not depend on that store. Paging
        // at 3am for it is how a monitor gets muted.
        \Kanopi\Firewall\Utility\DegradedBackends::reset();
        \Kanopi\Firewall\Utility\DegradedBackends::record('rate limit', 'RedisRateLimitStorage', 'refused');

        try {
            self::assertSame(0, $this->tester(new HealthCommand($this->factory()))->execute([]));
            self::assertSame(
                1,
                $this->tester(new HealthCommand($this->factory()))->execute(['--strict' => true])
            );
        } finally {
            \Kanopi\Firewall\Utility\DegradedBackends::reset();
        }
    }

    public function testHealthReportsAFirewallThatCannotBeBuiltInTheShapeOfOneThatCan(): void
    {
        // A probe should not have to tell a stack trace from a verdict.
        $this->configs = [self::CONFIG . 'broken-storage.yml'];

        $tester = $this->tester(new HealthCommand($this->factory()));

        self::assertSame(1, $tester->execute(['--format' => 'json']));

        $report = $this->decode($tester->getDisplay());
        self::assertFalse($report['healthy']);
        self::assertFalse($report['firewall_started']);
        self::assertCount(1, $this->listAt($report, 'errors'));
    }

    public function testHealthSaysTrafficIsUnfilteredUnderFailOpen(): void
    {
        $this->configs = [self::CONFIG . 'broken-storage.yml'];

        $tester = $this->tester(new HealthCommand($this->factory('fail_open')));

        self::assertSame(1, $tester->execute([]));
        self::assertStringContainsString('served unfiltered', $tester->getDisplay());
    }

    public function testHealthKeepsTheNestingOutOfTheTableAndTheSentencesIn(): void
    {
        // The probe shape does not survive a table: `panic_switch` is four
        // nested fields that flatten to "no, , ," and `failed_rules` is a
        // list of maps. A person gets a summary and the sentences.
        $panicFile = tempnam(sys_get_temp_dir(), 'kanopi-panic-');
        file_put_contents((string) $panicFile, 'log');

        try {
            $this->configs = [[
                'global' => ['behind_proxy' => false, 'panic_file' => $panicFile],
                'storage' => ['type' => InMemoryStorage::class],
                'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
                'plugins' => [['plugin' => 'Kanopi\Firewall\Plugins\IpAddress', 'config' => ['203.0.113.5']]],
            ]];

            $tester = $this->tester(new HealthCommand($this->factory()));

            self::assertSame(0, $tester->execute([]));

            $display = $tester->getDisplay();
            self::assertStringContainsString('ACTIVE', $display);
            self::assertStringNotContainsString('no, , ,', $display);
            self::assertStringContainsString('configured: exception', $display, 'both modes, since they differ');
            self::assertStringContainsString('panic switch is ACTIVE', $display, 'and the sentence');
        } finally {
            unlink((string) $panicFile);
        }
    }

    public function testHealthSaysSoWhenThereIsNothingToReport(): void
    {
        $tester = $this->tester(new HealthCommand($this->factory()));

        $tester->execute([]);

        self::assertStringContainsString('Every configured rule is running', $tester->getDisplay());
    }

    public function testHealthRefusesAMistypedFormatBeforeBuildingAnything(): void
    {
        $tester = $this->tester(new HealthCommand($this->factory()));

        self::assertSame(2, $tester->execute(['--format' => 'csv']));
    }

    public function testRulesListsWhatWillBeEvaluated(): void
    {
        $tester = $this->tester(new RulesCommand(new ConfigSnapshot($this->configs, [])));

        self::assertSame(0, $tester->execute([]));
        self::assertStringContainsString('test-block-ip', $tester->getDisplay());
        self::assertStringContainsString('IpAddress', $tester->getDisplay());
    }

    public function testRulesCanBeReadByAScript(): void
    {
        $tester = $this->tester(new RulesCommand(new ConfigSnapshot($this->configs, [])));

        $tester->execute(['--format' => 'json']);

        self::assertSame(
            [[
                'name' => 'test-block-ip',
                'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                'response' => 'block',
                'weight' => 0,
                'enabled' => true,
                'entries' => 1,
            ]],
            $this->decode($tester->getDisplay())
        );
    }

    public function testRulesRefusesAMistypedFormat(): void
    {
        $tester = $this->tester(new RulesCommand(new ConfigSnapshot($this->configs, [])));

        self::assertSame(2, $tester->execute(['--format' => 'toml']));
    }

    public function testConfigPrintsTheMergeRatherThanAnyOneFile(): void
    {
        $configs = [self::CONFIG . 'block.yml', ['global' => ['banning_status_code' => 429]]];

        $tester = $this->tester(new ConfigCommand(new ConfigSnapshot($configs, ['[global][mode]' => 'exception'])));

        self::assertSame(0, $tester->execute([]));

        $display = $tester->getDisplay();
        self::assertStringContainsString('banning_status_code: 429', $display, 'the inline settings');
        self::assertStringContainsString('mode: exception', $display, 'the override');
        self::assertStringContainsString('InMemoryStorage', $display, 'the file');
    }

    public function testConfigRedactsSecretsBecauseThisEndsUpInCiLogs(): void
    {
        $tester = $this->tester(new ConfigCommand(new ConfigSnapshot(
            [['challenge' => ['secret' => 'super-secret', 'provider_options' => ['secret_key' => 'also-secret']]]],
            []
        )));

        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertStringNotContainsString('super-secret', $display);
        self::assertStringNotContainsString('also-secret', $display, 'a provider key one level down too');
        self::assertStringContainsString('redacted', $display);
    }

    public function testConfigPrintsSecretsWhenThatIsTheQuestion(): void
    {
        // Proving that the value the application resolved is the value you
        // meant is the one case that needs it.
        $tester = $this->tester(new ConfigCommand(new ConfigSnapshot(
            [['challenge' => ['secret' => 'super-secret']]],
            []
        )));

        $tester->execute(['--show-secrets' => true]);

        self::assertStringContainsString('super-secret', $tester->getDisplay());
    }

    public function testConfigLeavesAnEmptySecretAloneBecauseThatIsTheAnswer(): void
    {
        // `challenge.secret: ''` with challenge rules configured is a fatal
        // misconfiguration, and a redaction marker would hide it.
        $tester = $this->tester(new ConfigCommand(new ConfigSnapshot(
            [['challenge' => ['secret' => '', 'provider' => 'math']]],
            []
        )));

        $tester->execute([]);

        self::assertStringNotContainsString('redacted', $tester->getDisplay());
    }

    public function testConfigFailsWhenTheDocumentIsNotTheWholeDocument(): void
    {
        // A pipeline diffing this against a known-good copy must not read a
        // file that failed to load as a legitimate change.
        $tester = $this->tester(new ConfigCommand(new ConfigSnapshot(
            [self::CONFIG . 'block.yml', self::CONFIG . 'absent.yml'],
            []
        )));

        self::assertSame(1, $tester->execute([]));
    }

    public function testConfigCanBeReadAsJson(): void
    {
        $tester = $this->tester(new ConfigCommand(new ConfigSnapshot($this->configs, [])));

        $tester->execute(['--format' => 'json']);

        self::assertNotSame([], $this->decode($tester->getDisplay()));
    }

    public function testConfigRefusesAMistypedFormat(): void
    {
        $tester = $this->tester(new ConfigCommand(new ConfigSnapshot($this->configs, [])));

        self::assertSame(2, $tester->execute(['--format' => 'ini']));
    }

    public function testBlockingAnAddressReportsWhatSupportWillBeAskedFor(): void
    {
        $blocks = $this->blockManager();

        $tester = $this->tester(new BlockCommand($blocks));

        self::assertSame(0, $tester->execute(['ip' => '198.51.100.9', '--duration' => '600']));

        $display = $tester->getDisplay();
        self::assertStringContainsString('Blocked 198.51.100.9', $display);
        self::assertStringContainsString('Reference', $display);
        self::assertStringContainsString('Expires', $display);
    }

    public function testBlockingWarnsWhenTheBlockDidNotSurviveTheCommand(): void
    {
        // In-memory storage accepts the write and reports success, and the
        // record is gone when the process exits. Without this the command is
        // indistinguishable from one that worked.
        $tester = $this->tester(new BlockCommand($this->blockManager()));

        $tester->execute(['ip' => '198.51.100.9']);

        self::assertStringContainsString('in-memory', $tester->getDisplay());
    }

    public function testBlockingWithARealBackendSaysNothingAboutMemory(): void
    {
        $tester = $this->tester(new BlockCommand($this->blockManager(OpaqueStorage::class)));

        $tester->execute(['ip' => '198.51.100.9']);

        self::assertStringNotContainsString('in-memory', $tester->getDisplay());
    }

    #[DataProvider('provideRefusedBlocks')]
    public function testARefusedBlockIsReportedInTheWordsTheOperatorNeeds(
        string $ip,
        string $storage,
        string $fragment
    ): void {
        $tester = $this->tester(new BlockCommand($this->blockManager($storage)));

        self::assertSame(1, $tester->execute(['ip' => $ip]));
        self::assertStringContainsString($fragment, $tester->getDisplay());
    }

    /**
     * @return iterable<string, array{0: string, 1: class-string, 2: string}>
     */
    public static function provideRefusedBlocks(): iterable
    {
        yield 'a range' => ['10.0.0.0/8', InMemoryStorage::class, 'is a range'];
        yield 'not an address' => ['example.com', InMemoryStorage::class, 'not a valid IP'];
        // The fragment is short because SymfonyStyle wraps an error
        // block to the terminal width, and a longer one straddles a line.
        yield 'a backend that will not write' => ['198.51.100.9', RefusingStorage::class, 'record a block for'];
    }

    public function testATypoInTheDurationDoesNotCreateAPermanentBlock(): void
    {
        // `0` means "until somebody lifts it", which is not what a mistyped
        // duration should mean.
        $tester = $this->tester(new BlockCommand($this->blockManager()));

        $tester->execute(['ip' => '198.51.100.9', '--duration' => 'an hour']);

        self::assertStringNotContainsString('never', $tester->getDisplay());
    }

    public function testAZeroDurationBlocksUntilItIsLifted(): void
    {
        $tester = $this->tester(new BlockCommand($this->blockManager()));

        $tester->execute(['ip' => '198.51.100.9', '--duration' => '0']);

        self::assertStringContainsString('never', $tester->getDisplay());
    }

    public function testReBlockingIsRefusedAndForcingItWorks(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 60);

        self::assertSame(1, $this->tester(new BlockCommand($blocks))->execute(['ip' => '198.51.100.9']));

        $tester = $this->tester(new BlockCommand($blocks));

        self::assertSame(0, $tester->execute(['ip' => '198.51.100.9', '--force' => true]));
        self::assertStringContainsString('Replaced the block on', $tester->getDisplay());
    }

    public function testAReasonIsStoredForWhoeverReadsTheListNext(): void
    {
        $blocks = $this->blockManager();

        $this->tester(new BlockCommand($blocks))->execute([
            'ip' => '198.51.100.9',
            '--reason' => 'Scraping /api',
        ]);

        self::assertSame('Scraping /api', $blocks->payloadValue($blocks->lookup('198.51.100.9'), 'reason'));
    }

    public function testUnblockingLiftsOneAddress(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);

        $tester = $this->tester(new UnblockCommand($blocks));

        self::assertSame(0, $tester->execute(['ip' => '198.51.100.9']));
        self::assertStringContainsString('Lifted 1 block', $tester->getDisplay());
        self::assertSame([], $blocks->all());
    }

    public function testUnblockingARangeLiftsEverythingInside(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);
        $blocks->add('198.51.100.10', 600);

        $tester = $this->tester(new UnblockCommand($blocks));

        $tester->execute(['ip' => '198.51.100.0/24']);

        self::assertStringContainsString('Lifted 2 blocks', $tester->getDisplay());
    }

    public function testNothingMatchingIsAnAnswerRatherThanAFailure(): void
    {
        // A deploy step that defensively lifts an address should not start
        // failing once the address is gone.
        $tester = $this->tester(new UnblockCommand($this->blockManager()));

        self::assertSame(0, $tester->execute(['ip' => '203.0.113.1']));
        self::assertStringContainsString('Nothing in the block list matches', $tester->getDisplay());
    }

    public function testADryRunChangesNothing(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);

        $tester = $this->tester(new UnblockCommand($blocks));
        $tester->execute(['ip' => '198.51.100.9', '--dry-run' => true]);

        self::assertStringContainsString('Would lift 1 block', $tester->getDisplay());
        self::assertStringContainsString('Dry run', $tester->getDisplay());
        self::assertCount(1, $blocks->all());
    }

    public function testAnAddressAndAllTogetherIsRefusedRatherThanResolved(): void
    {
        // Guessing that --all wins would empty the list for somebody who
        // typed an address; guessing the address wins would ignore a flag
        // they passed deliberately.
        $tester = $this->tester(new UnblockCommand($this->blockManager()));

        self::assertSame(2, $tester->execute(['ip' => '198.51.100.9', '--all' => true]));
        self::assertStringContainsString('not both', $tester->getDisplay());
    }

    public function testNeitherAnAddressNorAllIsRefused(): void
    {
        $tester = $this->tester(new UnblockCommand($this->blockManager()));

        self::assertSame(2, $tester->execute([]));
        self::assertStringContainsString('Name an address or range', $tester->getDisplay());
    }

    public function testEmptyingTheListNeedsForceWhenThereIsNobodyToAsk(): void
    {
        // Doing nothing quietly is the outcome that gets mistaken for
        // success in a deploy script.
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);

        $tester = $this->tester(new UnblockCommand($blocks));

        self::assertSame(2, $tester->execute(['--all' => true], ['interactive' => false]));
        self::assertStringContainsString('--force', $tester->getDisplay());
        self::assertCount(1, $blocks->all(), 'nothing was lifted');
    }

    public function testForceEmptiesTheListUnattended(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);

        $tester = $this->tester(new UnblockCommand($blocks));

        self::assertSame(0, $tester->execute(['--all' => true, '--force' => true], ['interactive' => false]));
        self::assertSame([], $blocks->all());
    }

    public function testAPersonSayingNoIsADecisionAndNotAFailure(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);

        $tester = $this->tester(new UnblockCommand($blocks));
        $tester->setInputs(['no']);

        self::assertSame(0, $tester->execute(['--all' => true]));
        self::assertStringContainsString('left alone', $tester->getDisplay());
        self::assertCount(1, $blocks->all());
    }

    public function testAPersonSayingYesEmptiesTheList(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);

        $tester = $this->tester(new UnblockCommand($blocks));
        $tester->setInputs(['yes']);

        self::assertSame(0, $tester->execute(['--all' => true]));
        self::assertSame([], $blocks->all());
    }

    public function testADryRunOfEmptyingTheListNeedsNoConfirmation(): void
    {
        $blocks = $this->blockManager();
        $blocks->add('198.51.100.9', 600);

        $tester = $this->tester(new UnblockCommand($blocks));

        self::assertSame(0, $tester->execute(['--all' => true, '--dry-run' => true], ['interactive' => false]));
        self::assertStringContainsString('Would lift 1 block', $tester->getDisplay());
    }

    public function testEmptyingAnAlreadyEmptyListSaysSo(): void
    {
        $tester = $this->tester(new UnblockCommand($this->blockManager()));

        self::assertSame(0, $tester->execute(['--all' => true, '--force' => true]));
        self::assertStringContainsString('already empty', $tester->getDisplay());
    }

    public function testUnblockingOnABackendThatCannotBeListedIsReportedRatherThanReportedEmpty(): void
    {
        $tester = $this->tester(new UnblockCommand($this->blockManager(OpaqueStorage::class)));

        self::assertSame(1, $tester->execute(['ip' => '198.51.100.0/24']));
        self::assertStringContainsString('cannot be queried', $tester->getDisplay());
    }

    public function testAReferenceLeadsBackToTheClientItBelongsTo(): void
    {
        $blocks = $this->blockManager();
        $reference = $blocks->add('198.51.100.9', 600, 'Scraping /api')['reference'];

        $tester = $this->tester(new FindReferenceCommand($blocks));

        self::assertSame(0, $tester->execute(['reference' => strtolower($reference)]));

        $display = $tester->getDisplay();
        self::assertStringContainsString('198.51.100.9', $display);
        self::assertStringContainsString('Scraping /api', $display);
        self::assertStringContainsString('kanopi:firewall:unblock 198.51.100.9', $display, 'and what to do next');
    }

    public function testAReferenceLookupIsReadableByAScript(): void
    {
        $blocks = $this->blockManager();
        $reference = $blocks->add('198.51.100.9', 600)['reference'];

        $tester = $this->tester(new FindReferenceCommand($blocks));
        $tester->execute(['reference' => $reference, '--format' => 'json']);

        $found = $this->decode($tester->getDisplay());

        self::assertSame('198.51.100.9', $this->text($found, 'address'));
        self::assertSame('yes', $this->text($found, 'found'));
        self::assertStringNotContainsString('unblock', $tester->getDisplay(), 'no prose for a parser');
    }

    public function testAReferenceThatMatchesNothingSaysWhyThatIsNormal(): void
    {
        // Blocks lapse, and the page the caller is looking at may be cached
        // or from yesterday.
        $tester = $this->tester(new FindReferenceCommand($this->blockManager()));

        self::assertSame(1, $tester->execute(['reference' => '0123456789ABCDEF0123456789ABCDEF']));
        self::assertStringContainsString('lapsed', $tester->getDisplay());
    }

    public function testAMissIsStillMachineReadable(): void
    {
        $tester = $this->tester(new FindReferenceCommand($this->blockManager()));

        self::assertSame(1, $tester->execute([
            'reference' => '0123456789ABCDEF0123456789ABCDEF',
            '--format' => 'json',
        ]));

        self::assertSame(
            ['reference' => '0123456789ABCDEF0123456789ABCDEF', 'found' => 'no'],
            $this->decode($tester->getDisplay())
        );
    }

    public function testABackendThatCannotBeSearchedIsAnErrorAndNotAMiss(): void
    {
        // "Not found" and "could not look" are different answers, and only
        // one of them means the customer is not blocked.
        $tester = $this->tester(new FindReferenceCommand($this->blockManager(OpaqueStorage::class)));

        self::assertSame(1, $tester->execute(['reference' => '0123456789ABCDEF0123456789ABCDEF']));
        self::assertStringContainsString('cannot be queried', $tester->getDisplay());
    }

    public function testFindReferenceRefusesAMistypedFormat(): void
    {
        $tester = $this->tester(new FindReferenceCommand($this->blockManager()));

        self::assertSame(2, $tester->execute(['reference' => 'ABC', '--format' => 'xml']));
    }

    /**
     * A block manager over the configured backend.
     *
     * @param string $storage
     *   The backend class to configure, as the YAML would name it.
     */
    private function blockManager(string $storage = InMemoryStorage::class): BlockManager
    {
        return new BlockManager(new BlockList([[
            'global' => ['behind_proxy' => false],
            'storage' => ['type' => $storage],
            'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
            'plugins' => [],
        ]]));
    }

    /**
     * A factory over `$this->configs`.
     */
    private function factory(string $onStartupFailure = 'fail_closed'): FirewallFactory
    {
        return new FirewallFactory(
            $this->configs,
            ['[global][mode]' => 'exception'],
            new ProxyPosture(false),
            new LoggerBridge('off'),
            $onStartupFailure
        );
    }

    /**
     * A status report over `$this->configs`.
     */
    private function statusReport(): StatusReport
    {
        return new StatusReport(
            'enforce',
            250,
            'replace',
            '/vendor/bin',
            'v9.9.9',
            $this->configs,
            new ConfigSnapshot($this->configs, ['[global][mode]' => 'exception']),
            $this->factory(),
            $this->blockManager()
        );
    }

    /**
     * A tester for one command. See ScriptCommandTest for why there is no
     * `Application` around it.
     */
    private function tester(Command $command): CommandTester
    {
        $command->setName('kanopi:firewall:test');

        return new CommandTester($command);
    }
}
