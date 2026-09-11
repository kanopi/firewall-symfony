<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Print the configuration the firewall actually runs.
 *
 * The Drush integration exports configuration because there it lives in
 * config entities and has to be got out somehow. Here it is already YAML —
 * so what is worth printing is not any one file but the **merge**: the
 * bundle's `config_files` and inline `settings`, every `configs:` include
 * they pull in, and the bundle's own overrides applied last.
 *
 * That merged document is what no file on disk contains and what every
 * surprising verdict is explained by. It is also exactly what the wrapped
 * scripts are handed, which makes this the answer to "what is
 * `kanopi:firewall:doctor` actually looking at".
 *
 * ## Secrets are redacted by default
 *
 * `challenge.secret` is in that document, and typically arrives from an
 * environment variable. EffectiveConfig goes to some trouble to keep it in a
 * 0600 file that is deleted when the command exits; printing it to a
 * terminal — or to a CI log, which is where a command like this most often
 * ends up — would undo that for the sake of a field nobody reads on
 * purpose. So it is replaced with a marker, and `--show-secrets` is there
 * for the one case that needs it: proving that the value the application
 * resolved is the value you meant.
 */
final class ConfigCommand extends AbstractFirewallCommand
{
    /**
     * Stands in for a redacted value.
     */
    private const REDACTED = '** redacted, pass --show-secrets **';

    /**
     * Keys whose values are replaced unless `--show-secrets` is given.
     *
     * Matched on the last path segment, case-insensitively, so a provider
     * block's `secret_key` is covered as well as `challenge.secret` — a
     * Turnstile or reCAPTCHA secret is no less a secret for living one level
     * deeper.
     *
     * @var array<int, string>
     */
    private const SECRET_KEYS = ['secret', 'secret_key', 'password', 'api_key', 'token'];

    public function __construct(private readonly ConfigSnapshot $configSnapshot)
    {
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Print the merged configuration the firewall actually runs')
            ->addOption(
                'show-secrets',
                null,
                InputOption::VALUE_NONE,
                'Print secret values instead of redacting them. Not for a CI log'
            )
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name%</info>                            the effective YAML
                  <info>%command.full_name% --format=json</info>
                  <info>%command.full_name% > /tmp/effective.yml</info>       keep a copy to diff

                This is the merge, not any one file: <comment>config_files</comment>, the inline <comment>settings</comment>
                array, every <comment>configs:</comment> include they pull in, and the bundle's overrides last.
                <comment>kanopi:firewall:status</comment> names the inputs; this shows what they became.

                Secret-looking values are redacted. <comment>--show-secrets</comment> prints them.
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

        $config = $this->configSnapshot->all();

        $printer->dump((bool) $input->getOption('show-secrets') ? $config : $this->redact($config));

        // Non-zero when the document is not the whole document. A pipeline
        // diffing this against a known-good copy would otherwise treat a
        // file that failed to load as a legitimate change in configuration,
        // which is the one reading that must not pass silently.
        return $this->configSnapshot->loadErrors() === [] ? self::EXIT_OK : self::EXIT_ERROR;
    }

    /**
     * Replace every secret-looking value, at any depth.
     *
     * @param array<array-key, mixed> $config
     *   The merged configuration.
     *
     * @return array<array-key, mixed>
     *   The same structure, with secrets replaced.
     */
    private function redact(array $config): array
    {
        $redacted = [];

        foreach ($config as $key => $value) {
            if (is_array($value)) {
                $redacted[$key] = $this->redact($value);

                continue;
            }

            $redacted[$key] = $this->isSecret($key) && $value !== null && $value !== ''
                ? self::REDACTED
                : $value;
        }

        return $redacted;
    }

    /**
     * Does this key name a secret?
     *
     * An empty value is left alone by the caller rather than marked, because
     * "no secret is set" is itself the answer to a question somebody runs
     * this command to ask — and `challenge.secret: ''` with challenge rules
     * configured is a fatal misconfiguration that a redaction marker would
     * hide.
     *
     * @param array-key $key
     *   The key to judge.
     */
    private function isSecret(int|string $key): bool
    {
        return in_array(strtolower((string) $key), self::SECRET_KEYS, true);
    }
}
