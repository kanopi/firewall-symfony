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
 * Bring the firewall's own tables up to the schema this release declares.
 *
 * Nothing to do with Doctrine's migrations, and deliberately not wired into
 * them. The firewall's tables are created on first write by the storage
 * backend that owns them, and their schema is declared on those classes
 * rather than in a migration file — so a Doctrine migration would be a
 * second description of the same schema, and the two would disagree the
 * first time the library added a column.
 *
 * Only ever additive: it adds missing columns and indexes and never drops,
 * renames or rewrites anything, so no sequence of runs can lose a row.
 *
 * `--dry-run` exits **3** when changes are pending, which is what makes it
 * usable as a deploy gate: run it before the deploy, and a 3 means the
 * schema needs bringing forward.
 */
final class MigrateCommand extends AbstractScriptCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Bring database-backed storage and logging tables up to the declared schema')
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Report what is missing, and the statements, without running them. Exits 3 when changes are pending'
            )
            ->addOption('quiet-output', null, InputOption::VALUE_NONE, 'Only report changes and failures. The script\'s own --quiet')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% --dry-run</info>   exits 3 when changes are pending
                  <info>%command.full_name%</info>             applies them

                Additive only. It never drops, renames or rewrites, so running it twice is safe.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-migrate';
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return array_merge(
            $this->forwardOptions($input, flags: ['dry-run']),
            (bool) $input->getOption('quiet-output') ? ['--quiet'] : []
        );
    }
}
