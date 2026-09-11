<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Kanopi\FirewallBundle\Command\DoctorCommand;
use Kanopi\FirewallBundle\Command\EffectiveConfig;
use Kanopi\FirewallBundle\Command\ScriptRunner;
use Kanopi\FirewallBundle\Diagnostics\IntegrationDoctor;
use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Kanopi\FirewallBundle\Tests\Fixtures\ReadsStructuredOutput;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(DoctorCommand::class)]
final class DoctorCommandTest extends TestCase
{
    use ReadsStructuredOutput;

    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    /**
     * Directory holding the stand-in scripts.
     */
    private const BIN = __DIR__ . '/../../Fixtures/bin';

    public function testTheWiringIsReportedBeforeTheRules(): void
    {
        // An integration failure invalidates the library's findings — a
        // firewall whose listener never runs is perfectly healthy and
        // completely ineffective — so the operator reads about the wiring
        // first.
        $tester = $this->tester();

        $tester->execute([]);

        $display = $tester->getDisplay();
        self::assertLessThan(
            strpos($display, 'Library checks'),
            (int) strpos($display, 'Symfony integration checks'),
            'the integration half comes first'
        );
        self::assertStringContainsString('ARGS:', $display, 'and the script still ran');
    }

    public function testAHealthyWiringPassesAndSaysWhatItChecked(): void
    {
        $tester = $this->tester();

        self::assertSame(0, $tester->execute([]));
        self::assertStringContainsString('Mode is "enforce"', $tester->getDisplay());
        self::assertStringContainsString('ok,', $tester->getDisplay(), 'the tally');
    }

    public function testAWarningDoesNotFailTheDeployGate(): void
    {
        // The command is built to be gated on, which only works if warnings
        // are survivable — the in-memory storage fixture raises one.
        self::assertSame(0, $this->tester()->execute([]));
    }

    public function testAnIntegrationErrorFailsEvenWhenTheLibraryIsHappy(): void
    {
        // A green library report does not redeem broken wiring, and this is
        // the command a deploy gates on.
        $tester = $this->tester(binDir: '/nowhere');

        self::assertSame(1, $tester->execute([]));
        self::assertStringContainsString('ERROR', $tester->getDisplay());
    }

    public function testTheWorseOfTheTwoHalvesIsWhatComesBack(): void
    {
        $tester = $this->tester();

        self::assertSame(3, $tester->execute(['forward' => ['--exit=3']]));
    }

    public function testTheIntegrationHalfCanBeRunOnItsOwn(): void
    {
        // Needs no configuration to be readable, which is what makes it
        // usable on a deployment the library cannot even load.
        $tester = $this->tester();

        self::assertSame(0, $tester->execute(['--integration-only' => true]));
        self::assertStringNotContainsString('ARGS:', $tester->getDisplay(), 'no script ran');
        self::assertStringNotContainsString('Library checks', $tester->getDisplay());
    }

    public function testTheIntegrationHalfAloneStillFailsOnAnError(): void
    {
        $tester = $this->tester(binDir: '/nowhere');

        self::assertSame(1, $tester->execute(['--integration-only' => true]));
    }

    public function testQuietHidesWhatIsFineAndForwardsTheScriptsOwnFlag(): void
    {
        $tester = $this->tester();

        $tester->execute(['--quiet-checks' => true]);

        $display = $tester->getDisplay();
        self::assertStringNotContainsString('Mode is "enforce"', $display, 'an OK finding is hidden');
        self::assertStringContainsString('Storage is in-memory', $display, 'a warning is not');
        self::assertStringContainsString('--quiet', $display, 'renamed on the way to the script');
    }

    public function testEverythingFineAndQuietSaysSoRatherThanPrintingNothing(): void
    {
        // An empty report reads as a command that did not run.
        $tester = $this->tester(configs: [[
            'global' => ['behind_proxy' => false],
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\FileStorage',
                'config' => ['storage_file' => sys_get_temp_dir() . '/kanopi-doctor-test-blocks.json'],
            ],
            'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
            'plugins' => [
                ['plugin' => 'Kanopi\Firewall\Plugins\IpAddress', 'response' => 'block', 'config' => ['203.0.113.5']],
            ],
        ]]);

        $tester->execute(['--integration-only' => true, '--quiet-checks' => true]);

        self::assertStringContainsString('Nothing to report', $tester->getDisplay());
    }

    public function testAConfigurationWithNoRulesAtAllIsNotTheSameAsOneWithParkedRules(): void
    {
        // Both allow every request, and the fix is different: one needs
        // rules written, the other needs one re-enabled.
        $tester = $this->tester(configs: [self::CONFIG . 'allow.yml']);

        $tester->execute(['--integration-only' => true]);

        self::assertStringContainsString('The configuration declares no rules', $tester->getDisplay());
    }

    public function testJsonEmitsTheIntegrationFindingsAsOneDocument(): void
    {
        $tester = $this->tester();

        $tester->execute(['--integration-only' => true, '--json' => true]);

        $decoded = $this->decode($tester->getDisplay());

        self::assertArrayHasKey('integration', $decoded);
        self::assertSame('ok', $this->text($decoded, 'integration', 0, 'status'));
        self::assertSame('Mode is "enforce"', $this->text($decoded, 'integration', 0, 'title'));
    }

    public function testJsonIsForwardedToTheScriptToo(): void
    {
        // Two documents, which is why the help says so. Buffering to splice
        // them would make a doctor that appears to hang on a slow database.
        $tester = $this->tester();

        $tester->execute(['--json' => true]);

        self::assertStringContainsString('"integration"', $tester->getDisplay());
        self::assertStringContainsString('--json', $tester->getDisplay());
    }

    public function testAFindingThatCitesTheDocumentationLinksToIt(): void
    {
        $tester = $this->tester();

        $tester->execute(['--integration-only' => true]);

        self::assertStringContainsString(
            'https://github.com/kanopi/firewall/blob/2.x/docs/configuration/storage.md',
            $tester->getDisplay()
        );
    }

    /**
     * A tester over real collaborators.
     *
     * @param array<int, string|array<string, mixed>>|null $configs
     *   Config inputs, or NULL for the fixture with one rule.
     * @param string|null $binDir
     *   Where the integration doctor looks for the scripts. The runner
     *   always uses the fixture directory, so an error can be arranged in
     *   one half without breaking the other.
     */
    private function tester(?array $configs = null, ?string $binDir = null): CommandTester
    {
        $configs ??= [self::CONFIG . 'block.yml'];

        $command = new DoctorCommand(
            new ScriptRunner(self::BIN),
            new EffectiveConfig($configs, []),
            new IntegrationDoctor(
                'enforce',
                250,
                true,
                '/_firewall/challenge',
                $binDir ?? self::BIN,
                'replace',
                'fail_closed',
                $configs,
                new ProxyPosture(false),
                new ConfigSnapshot($configs, [])
            )
        );
        $command->setName('kanopi:firewall:doctor');

        return new CommandTester($command);
    }
}
