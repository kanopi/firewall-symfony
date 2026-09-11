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
 * Refresh every rule source the configuration declares, out of band.
 *
 * Sources can refresh themselves on a TTL while requests are being served,
 * and that is the worse arrangement: a cold or expired cache makes a visitor
 * wait on somebody else's HTTP server, and an expiry under load sends every
 * concurrent request after the same URL at once.
 *
 * So run this from cron or a deploy step and pair it with
 * `sources.offline: true` in the library configuration, which makes the
 * runtime read cached results and never open a socket.
 *
 * `--quiet-output` rather than the script's `--quiet`: Symfony Console owns
 * `--quiet` for its own verbosity, and would silence this command's output
 * instead of the script's.
 */
final class SourcesCommand extends AbstractScriptCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Fetch and cache the remote rule sources')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Revalidate even when a cached copy is still fresh')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what would be fetched without writing the cache')
            ->addOption(
                'cache-dir',
                null,
                InputOption::VALUE_REQUIRED,
                'Write to this directory instead of the configured cache location'
            )
            ->addOption('quiet-output', null, InputOption::VALUE_NONE, 'Only report failures. The script\'s own --quiet')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name%</info>                       refresh everything that is due
                  <info>%command.full_name% --force</info>               refresh regardless of the TTL
                  <info>%command.full_name% --dry-run</info>             report without writing

                Exits <comment>1</comment> when a source failed to load, so a deploy step can gate on it.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-sources';
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return array_merge(
            $this->forwardOptions($input, flags: ['force', 'dry-run'], values: ['cache-dir']),
            (bool) $input->getOption('quiet-output') ? ['--quiet'] : []
        );
    }
}
