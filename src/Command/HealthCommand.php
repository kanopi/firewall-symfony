<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Kanopi\Firewall\Firewall;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\HealthReport;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Report whether the running firewall is actually doing its job.
 *
 * ## Why this is not `kanopi:firewall:doctor`
 *
 * The two look similar and answer different questions, and the difference is
 * the reason both exist:
 *
 *  - `doctor` asks **is this configured correctly**. It is a deploy gate:
 *    run it once, read the prose, fix what it names. Its output is a list of
 *    diagnoses written for a person.
 *  - `health` asks **is this working right now**. It is a monitoring probe:
 *    run it every minute, and the only thing consuming it is a script. Its
 *    output is a fixed, flat shape — `healthy`, `mode`, `panic_switch`,
 *    `failed_rules`, `degraded_backends` — that a check can key off without
 *    parsing sentences.
 *
 * It also reports one thing the doctor cannot: the backends that constructed
 * successfully and cannot reach their store. Those are invisible to every
 * static check, because the plugin using them built perfectly — a rate limit
 * rule reporting healthy while it counts nothing.
 *
 * ## Not for a request path
 *
 * Answering builds every rule, because rules are constructed lazily and a
 * firewall that has evaluated nothing has nothing that could have failed
 * yet. Building a rule is what opens its storage connection, which is what
 * makes the answer worth having — and what makes this a command rather than
 * a controller.
 */
final class HealthCommand extends AbstractFirewallCommand
{
    public function __construct(private readonly FirewallFactory $firewallFactory)
    {
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Report whether the running firewall is healthy')
            ->addOption(
                'strict',
                null,
                InputOption::VALUE_NONE,
                'Fail on warnings too — a degraded backend, or a panic switch left down'
            )
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% --format=json</info>          for a monitoring probe
                  <info>%command.full_name% --strict</info>               warnings fail as well

                Exits <comment>1</comment> when a configured rule is not running, or when a panic file is
                present and was not applied. A degraded backend is a warning, not a failure:
                the firewall is still enforcing every rule that does not depend on that
                store, which is the degrade the library chose deliberately. Paging somebody
                at 3am because Redis blipped while the block list kept working is how a
                monitor gets muted — <comment>--strict</comment> is there for the deployments that do want it.
                HELP
            );

        $this->addFormatOption();
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $printer = $this->printer($input, $output);

        if (!$printer instanceof ResultPrinter) {
            return self::EXIT_CONFIG_UNREADABLE;
        }

        try {
            $firewall = $this->firewallFactory->get();
        } catch (\Throwable $throwable) {
            // `fail_closed`, the default: the firewall could not be built.
            // Reported in the report's own shape rather than as an
            // exception, because the consumer here is a probe and a probe
            // should not have to tell a stack trace from a verdict.
            return $this->reportUnbuildable($printer, $throwable->getMessage());
        }

        if (!$firewall instanceof Firewall) {
            return $this->reportUnbuildable(
                $printer,
                'The firewall could not be built and on_startup_failure is fail_open, so requests '
                . 'are being served unfiltered. The reason was logged at critical.'
            );
        }

        $report = (new HealthReport($firewall))->toArray();

        if ($printer->isMachineReadable()) {
            $printer->properties($report);
        } else {
            $this->render($printer, new SymfonyStyle($input, $output), $report);
        }

        if ($report['errors'] !== []) {
            return self::EXIT_ERROR;
        }

        return (bool) $input->getOption('strict') && $report['warnings'] !== []
            ? self::EXIT_ERROR
            : self::EXIT_OK;
    }

    /**
     * Print the report for a person.
     *
     * The machine formats get `HealthReport`'s shape unchanged, because a
     * probe is written against it. A person gets a different arrangement of
     * the same facts, because that shape does not survive a table: nested
     * under `panic_switch` are four fields that flatten to `no, , ,`, and
     * `failed_rules` is a list of maps that flattens to an unreadable run of
     * commas. So the nesting is summarised, and the sentences the report
     * already wrote — which are the part worth reading — are printed as
     * error and warning blocks under it.
     *
     * @param array{
     *     healthy: bool,
     *     mode: string,
     *     configured_mode: string,
     *     mode_overridden: bool,
     *     panic_switch: array{active: bool, mode: string|null, path: string|null, problem: string|null},
     *     failed_rules: array<int, array{bucket: string, plugin: string, error: string}>,
     *     degraded_backends: array<int, array<string, string>>,
     *     errors: array<int, string>,
     *     warnings: array<int, string>
     * } $report
     *   The report, whose shape is restated here so the values arrive
     *   narrowed rather than as `mixed`.
     */
    private function render(ResultPrinter $printer, SymfonyStyle $symfonyStyle, array $report): void
    {
        $printer->properties([
            'healthy' => $report['healthy'],
            // Both are shown when they differ, because the effective mode
            // alone cannot distinguish "somebody configured log" from
            // "somebody is holding the panic switch down", and only one of
            // those is meant to be temporary.
            'mode' => $report['mode_overridden']
                ? sprintf('%s (configured: %s)', $report['mode'], $report['configured_mode'])
                : $report['mode'],
            'panic_switch' => $report['panic_switch']['active']
                ? sprintf('ACTIVE (%s)', $report['panic_switch']['path'] ?? 'unknown path')
                : 'off',
            'rules_not_running' => count($report['failed_rules']),
            'degraded_backends' => count($report['degraded_backends']),
        ]);

        foreach ($report['errors'] as $error) {
            $symfonyStyle->error($error);
        }

        foreach ($report['warnings'] as $warning) {
            $symfonyStyle->warning($warning);
        }

        if ($report['errors'] === [] && $report['warnings'] === []) {
            $symfonyStyle->success('Every configured rule is running and every backend reachable.');
        }
    }

    /**
     * Report a firewall that does not exist, in the shape of one that does.
     *
     * The keys a probe reads — `healthy`, `errors` — are present and say
     * what happened. A probe that got a different shape for this case would
     * have to special-case the one condition it most needs to catch.
     */
    private function reportUnbuildable(ResultPrinter $printer, string $reason): int
    {
        $printer->properties([
            'healthy' => false,
            'firewall_started' => false,
            'errors' => [$reason],
            'warnings' => [],
        ]);

        return self::EXIT_ERROR;
    }
}
