<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Kanopi\FirewallBundle\Firewall\StatusReport;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Show what the firewall is currently doing.
 *
 * The first command to reach for, and the one that answers the question
 * everything else is a follow-up to: is this thing on, what is it enforcing,
 * and is any of it failing. See StatusReport for where each field comes from
 * and why no single source has the whole answer.
 *
 * ## Why it exits non-zero when the firewall did not start
 *
 * A status command is a report, and a report that returned 0 while saying
 * "the firewall could not be built" would be a report nothing can gate on —
 * and `kanopi:firewall:status` is what somebody runs first in an incident
 * and first in a deploy script. Everything softer than that is left at 0:
 * a degraded backend, a lapsed source, an `observe` mode are all conditions
 * an operator may have chosen, and `kanopi:firewall:health --strict` is the
 * command for treating them as failures.
 */
final class StatusCommand extends AbstractFirewallCommand
{
    public function __construct(private readonly StatusReport $statusReport)
    {
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Show what the firewall is currently doing')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name%</info>
                  <info>%command.full_name% --format=json</info>

                Exits <comment>1</comment> only when the firewall could not be built at all. For a probe that
                fails on a rule that is not running, use <comment>kanopi:firewall:health</comment>; for one that
                fails on a misconfiguration, <comment>kanopi:firewall:doctor</comment>.
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

        $report = $this->statusReport->toArray();

        $printer->properties($report);

        return $report['firewall_started'] === false ? self::EXIT_ERROR : self::EXIT_OK;
    }
}
