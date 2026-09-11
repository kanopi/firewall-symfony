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
 * Write a starting `firewall.yml` from four questions.
 *
 * The odd one out: it writes configuration rather than reading it, so it
 * runs with none of its own and nothing is dumped for it. What it is good at
 * is the part that would take some reading to assemble by hand — the shipped
 * presets for a platform, and the CIDR ranges to trust for a CDN. Point it
 * at a file, then list that file in `kanopi_firewall.config_files`.
 *
 * ## It cannot ask you anything
 *
 * The script prompts when its standard input is a terminal. Run through a
 * subprocess it never is, so every answer has to arrive as an option and an
 * unanswered question takes its default: `--platform=other`, `--cdn=none`,
 * `--storage=file`, `--mode=log`. That is a deliberate trade in
 * ScriptRunner — see there — and it is why this command lists the accepted
 * values rather than leaving them to the prompt.
 */
final class InitCommand extends AbstractScriptCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Write a starter firewall.yml for this platform and CDN')
            ->addOption('platform', null, InputOption::VALUE_REQUIRED, 'wordpress, drupal or other. Default other')
            ->addOption(
                'cdn',
                null,
                InputOption::VALUE_REQUIRED,
                'none, cloudflare, pantheon, wpengine or fastly. Default none'
            )
            ->addOption('storage', null, InputOption::VALUE_REQUIRED, 'file, database or redis. Default file')
            ->addOption(
                'mode',
                null,
                InputOption::VALUE_REQUIRED,
                'log (observe, recommended) or block (enforce). Default log'
            )
            ->addOption('output', null, InputOption::VALUE_REQUIRED, 'Where to write. Defaults to firewall.yml in the current directory')
            ->addOption('print', null, InputOption::VALUE_NONE, 'Write to standard output and create nothing')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Overwrite an existing file')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% --platform=drupal --mode=log --output=config/firewall.yml</info>
                  <info>%command.full_name% --platform=wordpress --cdn=cloudflare --print</info>

                Then add the file to your bundle configuration:

                  <comment>kanopi_firewall:
                      config_files:
                          - '%kernel.project_dir%/config/firewall.yml'</comment>

                The <comment>mode</comment> written here is the library's, and is not this bundle's
                <comment>kanopi_firewall.mode</comment> — the bundle's wins. Starting at <comment>log</comment> and reading
                what would have been blocked is the recommended way in either way.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-init';
    }

    /**
     * {@inheritdoc}
     */
    protected function configStyle(): string
    {
        return self::CONFIG_NONE;
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return $this->forwardOptions(
            $input,
            flags: ['print', 'force'],
            values: ['platform', 'cdn', 'storage', 'mode', 'output']
        );
    }
}
