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
use Symfony\Component\Console\Output\OutputInterface;

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
 *
 * ## It also says where the block list lives
 *
 * For file storage, the one thing the starter file cannot get right on its
 * own is where the block list goes. So after the script succeeds, this adds
 * `FIREWALL_STORAGE_FILE` to `.env`, creates `var/firewall/` and sets
 * `kanopi_firewall.storage_file` — see StorageFileWiring for why all three.
 * `--no-env` writes the YAML and nothing else.
 */
final class InitCommand extends AbstractScriptCommand
{
    /**
     * @param ScriptRunner $scriptRunner
     *   Runs the child process.
     * @param EffectiveConfig $effectiveConfig
     *   Unused by this command, which reads no configuration; required by
     *   the base class.
     * @param StorageFileWiring|null $storageFileWiring
     *   NULL leaves every file but the generated YAML alone.
     */
    public function __construct(
        ScriptRunner $scriptRunner,
        EffectiveConfig $effectiveConfig,
        private readonly ?StorageFileWiring $storageFileWiring = null
    ) {
        parent::__construct($scriptRunner, $effectiveConfig);
    }

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
            ->addOption('output', null, InputOption::VALUE_REQUIRED, 'Where to write. Defaults to config/firewall.yml under the current directory')
            ->addOption('print', null, InputOption::VALUE_NONE, 'Write to standard output and create nothing')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Overwrite an existing file')
            ->addOption(
                'no-env',
                null,
                InputOption::VALUE_NONE,
                'For file storage, write only the YAML: leave .env, var/firewall/ and config/packages alone'
            )
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% --platform=drupal --mode=log --output=config/firewall.yml</info>
                  <info>%command.full_name% --platform=wordpress --cdn=cloudflare --print</info>

                Then add the file to your bundle configuration:

                  <comment>kanopi_firewall:
                      config_files:
                          - '%kernel.project_dir%/config/firewall.yml'</comment>

                With file storage (the default) it also adds <comment>FIREWALL_STORAGE_FILE</comment> to .env,
                creates var/firewall/ and sets <comment>kanopi_firewall.storage_file</comment>, so the web server
                and bin/console share one block list. Nothing that is already set is overwritten;
                <comment>--no-env</comment> skips all three.

                The <comment>mode</comment> written here is the library's, and is not this bundle's
                <comment>kanopi_firewall.mode</comment> — the bundle's wins. Starting at <comment>log</comment> and reading
                what would have been blocked is the recommended way in either way.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $code = parent::execute($input, $output);

        if ($code !== self::SUCCESS || !$this->wantsWiring($input)) {
            return $code;
        }

        \assert($this->storageFileWiring instanceof StorageFileWiring);

        $firewallYml = $input->getOption('output');
        $lines = $this->storageFileWiring->apply(
            is_string($firewallYml) && $firewallYml !== '' ? $firewallYml : 'config/firewall.yml',
            (string) getcwd()
        );

        $output->writeln('');

        foreach ($lines as $line) {
            $output->writeln($line);
        }

        return $code;
    }

    /**
     * Whether this run wrote a file-storage configuration the wiring applies to.
     */
    private function wantsWiring(InputInterface $input): bool
    {
        $storage = $input->getOption('storage');

        return $this->storageFileWiring instanceof StorageFileWiring
            && !$input->getOption('print')
            && !$input->getOption('no-env')
            && in_array($storage, [null, '', 'file'], true);
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
