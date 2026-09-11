<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\FirewallBundle\Diagnostics\IntegrationDoctor;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Diagnose the firewall, and the Symfony wiring around it.
 *
 * The only wrapper that does more than forward to a script. It runs two
 * doctors and prints one report:
 *
 *  - The **integration** checks, which are this bundle's: listener priority
 *    against the router, whether a challenge submission can reach the
 *    firewall, whether the proxy posture is known, whether the configuration
 *    actually loaded, whether a block written by hand would survive the
 *    command that wrote it.
 *  - The library's own `bin/firewall-doctor`, which checks the firewall:
 *    storage reachability, GeoIP freshness, rules that will not build.
 *
 * They run in that order deliberately. An integration failure invalidates
 * the library's findings — a firewall whose listener never runs is perfectly
 * healthy and completely ineffective — so an operator should read about the
 * wiring before reading a clean bill of health about the rules.
 *
 * ## `--json` produces two documents
 *
 * The integration findings as one object, then whatever the script writes.
 * They cannot be merged: the second half is produced by another process
 * whose output format belongs to the library, and buffering it to splice the
 * two would mean a doctor that appears to hang while it waits on a slow
 * database rather than printing findings as it reaches them. A consumer that
 * wants exactly one document should ask for `--integration-only --json`, or
 * read `kanopi:firewall:health --format=json`, which is the machine-facing
 * command by design.
 */
final class DoctorCommand extends AbstractScriptCommand
{
    /**
     * Where the library's documentation lives, for a finding that cites it.
     */
    private const DOCS = 'https://github.com/kanopi/firewall/blob/2.x/';

    /**
     * @param ScriptRunner $scriptRunner
     *   Runs `bin/firewall-doctor`.
     * @param EffectiveConfig $effectiveConfig
     *   Materializes the configuration that script reads.
     * @param IntegrationDoctor $integrationDoctor
     *   The bundle's own checks.
     */
    public function __construct(
        ScriptRunner $scriptRunner,
        EffectiveConfig $effectiveConfig,
        private readonly IntegrationDoctor $integrationDoctor
    ) {
        parent::__construct($scriptRunner, $effectiveConfig);
    }

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription(
                'Diagnose the Symfony wiring and the live firewall: every rule built, every backend '
                . 'reached, every file readable'
            )
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output. Emits two documents — see --help')
            ->addOption('quiet-checks', null, InputOption::VALUE_NONE, 'Only show warnings and errors')
            ->addOption(
                'integration-only',
                null,
                InputOption::VALUE_NONE,
                'Skip the library checks and only verify the Symfony wiring. Needs no configuration to be readable'
            )
            ->setHelp(
                <<<'HELP'
                Two reports, integration first:

                  <info>%command.full_name%</info>                     both halves
                  <info>%command.full_name% --integration-only</info>   just the Symfony wiring
                  <info>%command.full_name% --quiet-checks</info>       only what is wrong

                The exit code is the worse of the two halves, so this is the command to gate a
                deploy on. A warning does not fail it; an error does.

                <comment>--json</comment> emits the integration findings as one JSON object and then whatever
                <comment>bin/firewall-doctor --json</comment> writes, which is a second document. For a single
                machine-readable answer use <comment>--integration-only --json</comment>, or
                <comment>kanopi:firewall:health --format=json</comment>.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-doctor';
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $findings = $this->integrationDoctor->run();
        $json = (bool) $input->getOption('json');
        $symfonyStyle = new SymfonyStyle($input, $output);

        if ($json) {
            $symfonyStyle->writeln((string) json_encode(
                ['integration' => array_map(
                    static fn (Diagnosis $diagnosis): array => $diagnosis->toArray(),
                    $findings
                )],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
            ), OutputInterface::OUTPUT_RAW);
        } else {
            $this->renderFindings($symfonyStyle, $findings, (bool) $input->getOption('quiet-checks'));
        }

        $integrationFailed = $this->hasError($findings);

        if ((bool) $input->getOption('integration-only')) {
            return $integrationFailed ? self::EXIT_ERROR : self::EXIT_OK;
        }

        if (!$json) {
            $symfonyStyle->section('Library checks (bin/firewall-doctor)');
        }

        $libraryExit = parent::execute($input, $output);

        // The worse of the two. A green library report does not redeem a
        // listener that runs after the router, and this command is meant to
        // be usable as a deploy gate — so it has to fail if either half
        // does.
        return max($libraryExit, $integrationFailed ? self::EXIT_ERROR : self::EXIT_OK);
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return array_merge(
            $this->forwardOptions($input, flags: ['json']),
            // Renamed because Symfony Console owns `--quiet` for its own
            // verbosity and would silence this command rather than the
            // script.
            (bool) $input->getOption('quiet-checks') ? ['--quiet'] : []
        );
    }

    /**
     * Print the integration findings.
     *
     * @param SymfonyStyle $symfonyStyle
     *   Where to print.
     * @param array<int, Diagnosis> $findings
     *   What the integration doctor reported.
     * @param bool $quiet
     *   TRUE hides the findings that are fine.
     */
    private function renderFindings(SymfonyStyle $symfonyStyle, array $findings, bool $quiet): void
    {
        $symfonyStyle->section('Symfony integration checks');

        $shown = 0;

        foreach ($findings as $finding) {
            if ($quiet && $finding->status === Diagnosis::OK) {
                continue;
            }

            ++$shown;
            $this->renderFinding($symfonyStyle, $finding);
        }

        if ($shown === 0) {
            $symfonyStyle->writeln(' <fg=green>Nothing to report.</>');
        }

        $tally = array_count_values(array_map(
            static fn (Diagnosis $diagnosis): string => $diagnosis->status,
            $findings
        ));

        $symfonyStyle->newLine();
        $symfonyStyle->writeln(sprintf(
            ' <fg=green>%d ok</>, <fg=yellow>%d warning</>, <fg=red>%d error</>',
            $tally[Diagnosis::OK] ?? 0,
            $tally[Diagnosis::WARNING] ?? 0,
            $tally[Diagnosis::ERROR] ?? 0
        ));
    }

    /**
     * Print one finding, with its remediation advice.
     */
    private function renderFinding(SymfonyStyle $symfonyStyle, Diagnosis $diagnosis): void
    {
        $label = match ($diagnosis->status) {
            Diagnosis::ERROR => '<fg=red;options=bold>ERROR</>',
            Diagnosis::WARNING => '<fg=yellow;options=bold>WARN</>',
            default => '<fg=green>OK</>',
        };

        $symfonyStyle->writeln(sprintf(' %s  %s', $label, $diagnosis->title));

        if ($diagnosis->detail !== null) {
            // Wrapped at 96 rather than left to the terminal: these details
            // are paragraphs of remediation advice, and an unwrapped one is
            // unreadable in a CI log that reports no terminal width.
            foreach (explode("\n", wordwrap($diagnosis->detail, 96)) as $line) {
                $symfonyStyle->writeln('        <fg=gray>' . $line . '</>');
            }
        }

        if ($diagnosis->reference !== null) {
            $symfonyStyle->writeln('        <fg=blue>see: ' . self::DOCS . $diagnosis->reference . '</>');
        }
    }

    /**
     * @param array<int, Diagnosis> $findings
     *   What the integration doctor reported.
     */
    private function hasError(array $findings): bool
    {
        foreach ($findings as $finding) {
            if ($finding->status === Diagnosis::ERROR) {
                return true;
            }
        }

        return false;
    }
}
