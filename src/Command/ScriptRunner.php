<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Exception\ExceptionInterface as ProcessExceptionInterface;
use Symfony\Component\Process\PhpExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Runs one of the library's shipped `bin/` scripts and relays it verbatim.
 *
 * ## Why a subprocess and not a reimplementation
 *
 * The eight scripts are between 150 and 640 lines of argument parsing,
 * output formatting and exit-code policy, and most of it is not reachable
 * through a public class — `firewall-check`'s whole reason for existing is
 * the three ways hand-assembling the same call fails quietly. Rewriting them
 * as native `Command` classes would buy nicer help text and cost a 2,500-line
 * fork that drifts from the parent on every release, in the one part of the
 * system an operator reaches for during an incident. The exit codes are part
 * of the contract too — `firewall-migrate` returns 3 for "changes pending" so
 * it can gate a deploy — and reproducing those by hand is exactly the kind of
 * detail a fork loses first.
 *
 * What the wrapper adds over typing `vendor/bin/firewall-doctor` is the part
 * that is actually annoying: the configuration paths. `bin/console` already
 * knows which YAML this application's firewall is built from, so the
 * commands supply it.
 *
 * The trade-offs, stated plainly: no interactive TTY, output arrives as the
 * child flushes it rather than through Symfony's styling, and there is a
 * process spawn per invocation. All three are irrelevant for operational
 * commands run by hand or from cron, which is what these are.
 */
final class ScriptRunner
{
    /**
     * @param string $binDir
     *   Directory holding the scripts — Composer's `vendor/bin` unless the
     *   application moved it.
     * @param float $timeout
     *   Seconds before the child is killed. `firewall-sources` fetches
     *   remote lists and `firewall-migrate` alters tables, so the default is
     *   generous; 0.0 disables it.
     */
    public function __construct(
        private readonly string $binDir,
        private readonly float $timeout = 300.0
    ) {
    }

    /**
     * Run a script and stream its output.
     *
     * @param string $script
     *   Script name, e.g. `firewall-doctor`.
     * @param array<int, string> $arguments
     *   Arguments, already in the order the script expects.
     * @param OutputInterface $output
     *   Where to relay. When it is a `ConsoleOutputInterface` the child's
     *   stderr goes to stderr — `firewall-doctor` writes its errors there
     *   specifically so a CI log shows them when stdout is captured, and
     *   collapsing the two streams here would undo that.
     *
     * @return int
     *   The child's exit code, passed through unchanged.
     */
    public function run(string $script, array $arguments, OutputInterface $output): int
    {
        $path = $this->binDir . '/' . $script;

        if (!is_file($path)) {
            $output->writeln(sprintf(
                '<error>%s is not installed at %s. Set kanopi_firewall.commands.bin_dir if Composer\'s '
                . 'bin-dir is somewhere else.</error>',
                $script,
                $this->binDir
            ));

            return 2;
        }

        $errorOutput = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;

        // Invoked through the PHP binary rather than executed directly: on
        // Windows, and wherever Composer wrote a proxy file instead of a
        // symlink, the script's shebang is not what runs it.
        $process = new Process(
            array_merge([(new PhpExecutableFinder())->find(false) ?: PHP_BINARY, $path], $arguments),
            null,
            null,
            null,
            $this->timeout > 0.0 ? $this->timeout : null
        );

        try {
            return $process->run(static function (string $type, string $buffer) use ($output, $errorOutput): void {
                // Written, not `writeln`: the scripts emit their own
                // newlines, and re-wrapping would put blank lines through
                // `--json` output that a pipeline is parsing.
                ($type === Process::ERR ? $errorOutput : $output)->write($buffer, false, OutputInterface::OUTPUT_RAW);
            });
        } catch (ProcessExceptionInterface $processException) {
            // A timeout, or a binary that could not be started. Reported as
            // 2 — "the command could not answer the question" — which is
            // what every one of these scripts uses for the same condition.
            $errorOutput->writeln(sprintf('<error>%s could not be run: %s</error>', $script, $processException->getMessage()));

            return 2;
        }
    }
}
