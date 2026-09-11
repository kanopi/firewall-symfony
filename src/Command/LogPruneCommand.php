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
 * Delete firewall log rows older than the retention window.
 *
 * Applies to the library's own `DatabaseHandler`, and only to handlers
 * declared in the library's `logger.handlers`. A deployment that logs
 * through Monolog — which is this bundle's default, and what
 * `kanopi_firewall.logging` configures — has no such handler, and this will
 * correctly report that there is nothing to prune. Monolog's own rows are
 * Monolog's to rotate.
 *
 * `DatabaseHandler` can also prune itself on a fraction of writes, which
 * needs no scheduling. This is the honest version of the same job: it runs
 * when you say it runs and it tells you how many rows went. Set
 * `prune_probability: 0` on the handler and pruning happens only here.
 */
final class LogPruneCommand extends AbstractScriptCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Delete firewall log rows past their retention')
            ->addOption('days', null, InputOption::VALUE_REQUIRED, 'Prune to this many days instead of each handler\'s retention_days')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what would be deleted without deleting it')
            ->addOption('quiet-output', null, InputOption::VALUE_NONE, 'Only report failures. The script\'s own --quiet')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% --dry-run</info>       count what would go
                  <info>%command.full_name% --days=30</info>       prune to 30 days regardless of retention_days

                Only prunes handlers the library owns. Rows written through Monolog belong to
                whatever handler Monolog was configured with.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-log-prune';
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return array_merge(
            $this->forwardOptions($input, flags: ['dry-run'], values: ['days']),
            (bool) $input->getOption('quiet-output') ? ['--quiet'] : []
        );
    }
}
