<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Kanopi\FirewallBundle\Command\AbstractScriptCommand;
use Kanopi\FirewallBundle\Command\BlocksCommand;
use Kanopi\FirewallBundle\Command\CheckCommand;
use Kanopi\FirewallBundle\Command\EffectiveConfig;
use Kanopi\FirewallBundle\Command\InitCommand;
use Kanopi\FirewallBundle\Command\LogPruneCommand;
use Kanopi\FirewallBundle\Command\MigrateCommand;
use Kanopi\FirewallBundle\Command\RuleCommand;
use Kanopi\FirewallBundle\Command\ScriptRunner;
use Kanopi\FirewallBundle\Command\SourcesCommand;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(AbstractScriptCommand::class)]
#[CoversClass(BlocksCommand::class)]
#[CoversClass(CheckCommand::class)]
#[CoversClass(InitCommand::class)]
#[CoversClass(LogPruneCommand::class)]
#[CoversClass(MigrateCommand::class)]
#[CoversClass(RuleCommand::class)]
#[CoversClass(SourcesCommand::class)]
final class ScriptCommandTest extends TestCase
{
    /**
     * Directory holding the stand-in scripts.
     */
    private const BIN = __DIR__ . '/../../Fixtures/bin';

    public function testTheConfiguredPathsAreAppendedAsBareArguments(): void
    {
        $tester = $this->tester(new BlocksCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute([]);

        self::assertStringContainsString('ARGS:/etc/firewall.yml', $tester->getDisplay());
    }

    public function testTheOptionStyleIsUsedWhereTheScriptDemandsIt(): void
    {
        // `firewall-check` is the only script that will not take bare paths,
        // and the only one where getting it wrong is silent: it would read
        // the path as something else and report on an empty ruleset.
        $tester = $this->tester(new CheckCommand(...$this->collaborators(['/etc/a.yml', '/etc/b.yml'])));

        $tester->execute([]);

        self::assertStringContainsString('ARGS:--config=/etc/a.yml|--config=/etc/b.yml', $tester->getDisplay());
    }

    public function testDeclaredOptionsAreForwardedAndUndeclaredOnesAreRejected(): void
    {
        // The whole reason the wrappers declare their options: a mistyped
        // one is caught here rather than reaching the script and being
        // ignored.
        $tester = $this->tester(new CheckCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--ip' => '203.0.113.5', '--url' => '/wp-admin/', '--explain' => true]);

        self::assertStringContainsString('--ip=203.0.113.5', $tester->getDisplay());
        self::assertStringContainsString('--url=/wp-admin/', $tester->getDisplay());
        self::assertStringContainsString('--explain', $tester->getDisplay());

        $this->expectException(\Symfony\Component\Console\Exception\InvalidOptionException::class);
        $tester->execute(['--lnit' => true]);
    }

    public function testOptionsThatWereNotGivenAreNotForwarded(): void
    {
        // Symfony reports every declared option, set or not. Forwarding them
        // blindly would hand the script `--json` nobody asked for and change
        // its output format.
        $tester = $this->tester(new CheckCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute([]);

        self::assertStringNotContainsString('--json', $tester->getDisplay());
        self::assertStringNotContainsString('--ip=', $tester->getDisplay());
    }

    public function testARepeatableOptionIsForwardedOncePerValue(): void
    {
        $tester = $this->tester(new BlocksCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--lift' => ['203.0.113.1', '203.0.113.2']]);

        self::assertStringContainsString('--lift=203.0.113.1|--lift=203.0.113.2', $tester->getDisplay());
    }

    public function testAnEmptyValueIsNotForwardedAsAnEmptyOption(): void
    {
        // `--find=` would be a different question from not asking.
        $tester = $this->tester(new BlocksCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--find' => '', '--lift' => ['']]);

        self::assertStringNotContainsString('--find', $tester->getDisplay());
        self::assertStringNotContainsString('--lift', $tester->getDisplay());
    }

    public function testTheActionAndRuleNameStayInFrontOfTheConfigPaths(): void
    {
        // `firewall-rule` reads its action from the first bare word and its
        // rule name from the second, so a name after the config would be
        // read as another config file and rejected as "not found".
        $tester = $this->tester(new RuleCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['action' => 'remove', 'rule-name' => 'office']);

        self::assertStringContainsString('ARGS:remove|office|/etc/firewall.yml', $tester->getDisplay());
    }

    public function testAnActionWithNoRuleNameStillLeadsTheArguments(): void
    {
        $tester = $this->tester(new RuleCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['action' => 'add', '--ip' => ['203.0.113.9'], '--name' => 'office']);

        self::assertStringContainsString(
            'ARGS:add|--name=office|--ip=203.0.113.9|/etc/firewall.yml',
            $tester->getDisplay()
        );
    }

    public function testTheRuleCommandSeesOnlyTheRealFilesOnDisk(): void
    {
        // It edits configuration: it places its managed file beside the
        // first config it is given and lists rules as things you can remove
        // by name. A synthetic file would put the managed file in the temp
        // directory and offer rules nothing can edit.
        $tester = $this->tester(new RuleCommand(...$this->collaborators(
            ['/etc/firewall.yml', ['global' => ['banning_status_code' => 429]]],
            ['[challenge][secret]' => 's3cret']
        )));

        $tester->execute(['action' => 'list']);

        self::assertStringContainsString('ARGS:list|/etc/firewall.yml', $tester->getDisplay());
    }

    public function testEveryOtherCommandSeesTheConfigurationTheListenerRuns(): void
    {
        // Not passing these is what made the doctor report a fatal error
        // about a healthy application: the secret lives in bundle config,
        // which is a container array the child process cannot see.
        $tester = $this->tester(new BlocksCommand(...$this->collaborators(
            ['/etc/firewall.yml', ['global' => ['banning_status_code' => 429]]],
            ['[challenge][secret]' => 's3cret']
        )));

        $tester->execute([]);

        self::assertMatchesRegularExpression(
            '#ARGS:/etc/firewall\.yml\|\S+\|\S+#',
            $tester->getDisplay(),
            'the real file, then the settings array, then the overrides'
        );
    }

    public function testAnExplicitConfigOptionReplacesTheConfiguredPaths(): void
    {
        $tester = $this->tester(new BlocksCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--config' => ['/tmp/other.yml']]);

        $display = $tester->getDisplay();
        self::assertStringContainsString('ARGS:/tmp/other.yml', $display);
        self::assertStringNotContainsString('/etc/firewall.yml', $display);
    }

    public function testNothingConfiguredIsRefusedRatherThanRunAgainstTheDefaults(): void
    {
        // The library's defaults contain no rules, so a command that
        // "worked" here would report on a firewall that allows everything.
        $tester = $this->tester(new BlocksCommand(...$this->collaborators([])));

        self::assertSame(2, $tester->execute([]));
        self::assertStringContainsString('needs a configuration file', $tester->getDisplay());
    }

    public function testACommandThatWritesConfigurationSaysWhyItNeedsARealFile(): void
    {
        $tester = $this->tester(new RuleCommand(...$this->collaborators([['plugins' => []]])));

        self::assertSame(2, $tester->execute(['action' => 'list']));
        self::assertStringContainsString('kanopi_firewall.settings', $tester->getDisplay());
        self::assertStringContainsString('nothing can edit it', $tester->getDisplay());
    }

    public function testTheCommandThatWritesAConfigurationIsGivenNone(): void
    {
        // `firewall-init` writes a configuration rather than reading one, so
        // nothing is dumped for it and no secret is passed.
        $tester = $this->tester(new InitCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--platform' => 'drupal', '--mode' => 'log']);

        self::assertStringContainsString('ARGS:--platform=drupal|--mode=log', $tester->getDisplay());
        self::assertStringNotContainsString('/etc/firewall.yml', $tester->getDisplay());
    }

    public function testTheCommandThatTakesNoConfigurationHasNoConfigOption(): void
    {
        self::assertFalse((new InitCommand(...$this->collaborators([])))->getDefinition()->hasOption('config'));
    }

    #[DataProvider('provideQuietCommands')]
    public function testSymfonysOwnQuietIsNotTheScriptsQuiet(string $class): void
    {
        // Symfony Console owns `--quiet` for its own verbosity, so it cannot
        // be redeclared. The rename is the only way the script's flag stays
        // reachable at all.
        /** @var AbstractScriptCommand $command */
        $command = new $class(...$this->collaborators(['/etc/firewall.yml']));
        $tester = $this->tester($command);

        $tester->execute(['--quiet-output' => true]);

        self::assertStringContainsString('--quiet', $tester->getDisplay());
    }

    /**
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideQuietCommands(): iterable
    {
        yield 'sources' => [SourcesCommand::class];
        yield 'migrate' => [MigrateCommand::class];
        yield 'log-prune' => [LogPruneCommand::class];
    }

    public function testTheEscapeHatchStillReachesTheScript(): void
    {
        // An option added upstream has to be usable before this bundle is
        // updated for it.
        $tester = $this->tester(new MigrateCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--dry-run' => true, 'forward' => ['--not-declared-yet']]);

        self::assertStringContainsString('ARGS:--dry-run|--not-declared-yet|/etc/firewall.yml', $tester->getDisplay());
    }

    public function testTheScriptsExitCodeIsWhatTheCommandReturns(): void
    {
        // `firewall-migrate --dry-run` returns 3 for "changes pending" so a
        // deploy can gate on it. Collapsing that would break the contract.
        $tester = $this->tester(new MigrateCommand(...$this->collaborators(['/etc/firewall.yml'])));

        self::assertSame(3, $tester->execute(['forward' => ['--exit=3']]));
    }

    public function testEverySourcesOptionReachesTheScript(): void
    {
        $tester = $this->tester(new SourcesCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--force' => true, '--dry-run' => true, '--cache-dir' => '/var/cache/fw']);

        self::assertStringContainsString(
            'ARGS:--force|--dry-run|--cache-dir=/var/cache/fw|/etc/firewall.yml',
            $tester->getDisplay()
        );
    }

    public function testEveryLogPruneOptionReachesTheScript(): void
    {
        $tester = $this->tester(new LogPruneCommand(...$this->collaborators(['/etc/firewall.yml'])));

        $tester->execute(['--days' => '30', '--dry-run' => true]);

        self::assertStringContainsString('ARGS:--dry-run|--days=30|/etc/firewall.yml', $tester->getDisplay());
    }

    public function testTheTemporaryFilesAreGoneAfterwards(): void
    {
        // They can carry a resolved `challenge.secret`, which is why they
        // are created 0600 and deleted in a `finally`.
        $before = $this->tempFileCount();

        $tester = $this->tester(new BlocksCommand(...$this->collaborators(
            [['plugins' => []]],
            ['[challenge][secret]' => 's3cret']
        )));
        $tester->execute([]);

        self::assertSame($before, $this->tempFileCount());
    }

    /**
     * The collaborators every wrapper takes.
     *
     * @param array<int, string|array<string, mixed>> $configs
     *   The bundle's config inputs.
     * @param array<string, mixed> $overrides
     *   The bundle's overrides.
     *
     * @return array{0: ScriptRunner, 1: EffectiveConfig}
     *   Ready to spread into a constructor.
     */
    private function collaborators(array $configs, array $overrides = []): array
    {
        return [new ScriptRunner(self::BIN), new EffectiveConfig($configs, $overrides)];
    }

    /**
     * A tester for one command, with no application around it.
     *
     * Deliberately no `Application`: this package is tested against Symfony
     * 6.4, 7.4 and 8.1, and there is no one way to register a command in all
     * three — `Application::add()` was removed in 8, and `addCommand()` does
     * not exist in 6.4. A command does not need an application to run, only
     * to render `%command.full_name%` in its help, which is what
     * `Integration\ConsoleCommandTest` covers through the real console.
     */
    private function tester(Command $command): CommandTester
    {
        $command->setName('kanopi:firewall:test');

        return new CommandTester($command);
    }

    /**
     * How many of the bundle's temp files exist.
     */
    private function tempFileCount(): int
    {
        return count((array) glob(sys_get_temp_dir() . '/kanopi-firewall-effective-*'));
    }
}
