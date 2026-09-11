<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Kanopi\FirewallBundle\Command\ScriptRunner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;

#[CoversClass(ScriptRunner::class)]
final class ScriptRunnerTest extends TestCase
{
    /**
     * Directory holding the stand-in script.
     */
    private const BIN = __DIR__ . '/../../Fixtures/bin';

    public function testItForwardsArgumentsAndRelaysStdout(): void
    {
        $output = new BufferedOutput();

        $status = (new ScriptRunner(self::BIN))->run('fake-script', ['--json', 'config.yml'], $output);

        self::assertSame(0, $status);
        self::assertStringContainsString('ARGS:--json|config.yml', $output->fetch());
    }

    public function testTheExitCodeIsPassedThroughUnchanged(): void
    {
        // `firewall-migrate` returns 3 for "changes pending" so it can gate
        // a deploy. Collapsing that to 0/1 would break the contract.
        $status = (new ScriptRunner(self::BIN))->run('fake-script', ['--exit=3'], new BufferedOutput());

        self::assertSame(3, $status);
    }

    public function testStderrGoesToStderrWhenTheOutputHasOne(): void
    {
        // `firewall-doctor` writes its errors to stderr specifically so a
        // CI log shows them when stdout is captured; collapsing the streams
        // here would undo that.
        $output = new SplitBufferedOutput();

        (new ScriptRunner(self::BIN))->run('fake-script', [], $output);

        self::assertStringContainsString('ARGS:', $output->fetch());
        self::assertStringContainsString('on stderr', $output->getErrorOutput()->fetch());
    }

    public function testStderrFallsBackToTheOnlyStreamThereIs(): void
    {
        $output = new BufferedOutput();

        (new ScriptRunner(self::BIN))->run('fake-script', [], $output);

        $written = $output->fetch();
        self::assertStringContainsString('ARGS:', $written);
        self::assertStringContainsString('on stderr', $written);
    }

    public function testAMissingScriptIsReportedRatherThanFatal(): void
    {
        $output = new BufferedOutput();

        $status = (new ScriptRunner(self::BIN))->run('firewall-nope', [], $output);

        self::assertSame(2, $status);
        self::assertStringContainsString('bin_dir', $output->fetch());
    }

    public function testATimeoutIsReportedAsUnanswerable(): void
    {
        $output = new SplitBufferedOutput();

        $status = (new ScriptRunner(self::BIN, 0.2))->run('fake-script', ['--hang'], $output);

        // 2 — "the command could not answer the question" — which is what
        // every one of these scripts uses for that condition.
        self::assertSame(2, $status);
        self::assertStringContainsString('could not be run', $output->getErrorOutput()->fetch());
    }

    public function testAZeroTimeoutMeansNoTimeout(): void
    {
        $status = (new ScriptRunner(self::BIN, 0.0))->run('fake-script', [], new BufferedOutput());

        self::assertSame(0, $status);
    }
}
