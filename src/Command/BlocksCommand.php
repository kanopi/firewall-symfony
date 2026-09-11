<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * See who is blocked.
 *
 * Plural, and separate from `kanopi:firewall:block`, because they do
 * opposite things: this one reads the list, and the singular one adds to it.
 * Overloading one name with both — an argument to add, a flag to list —
 * would make the destructive reading of a bare typo the easy one to reach.
 * The split is the same one the Laravel package and the Drush commands make,
 * so the three integrations can be documented once.
 *
 * Reads and writes the **real** storage backend, unlike
 * `kanopi:firewall:check`, which swaps in a throwaway store so that asking a
 * question cannot ban anybody. That is the point of it: it is the command
 * for the moment somebody is on the phone about a customer who cannot check
 * out.
 *
 * `--lift` is the script's own flag and is kept here because this is a
 * wrapper around that script. `kanopi:firewall:unblock` is the one to reach
 * for, and is what the documentation shows.
 */
final class BlocksCommand extends AbstractScriptCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('List, inspect and lift durable blocks')
            ->addOption(
                'list',
                null,
                InputOption::VALUE_NONE,
                'Every block currently in force. The default when no action is given'
            )
            ->addOption('find', null, InputOption::VALUE_REQUIRED, 'Blocks matching an address or CIDR range')
            ->addOption('show', null, InputOption::VALUE_REQUIRED, 'One address, with when it offended')
            ->addOption(
                'lift',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Remove blocks matching an address or CIDR range. Repeatable'
            )
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'With --lift, report what would go without removing it')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% --list</info>                          who is blocked
                  <info>%command.full_name% --show=203.0.113.9</info>               and when they offended
                  <info>%command.full_name% --lift=203.0.113.0/24 --dry-run</info>  rehearse a wider lift

                To block an address, use <comment>kanopi:firewall:block</comment>; to lift one,
                <comment>kanopi:firewall:unblock</comment>. Both act on the same durable list this reads.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-block';
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return $this->forwardOptions(
            $input,
            flags: ['list', 'dry-run', 'json'],
            values: ['find', 'show'],
            repeatable: ['lift']
        );
    }
}
