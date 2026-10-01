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
 * Ask whether a given request would be blocked, and by what.
 *
 * Safe to point at a production configuration: the script swaps storage for
 * a throwaway store by default, so checking an address cannot ban it. Pass
 * `--live-storage` to consult the durable block list, and read the warning
 * it prints — a blocked verdict is then recorded for real.
 *
 * `--lint` answers a different question entirely and takes no request: what
 * is wrong with these rules, regardless of any request.
 *
 * The one script whose configuration must arrive as `--config=PATH`. Getting
 * that wrong is silent — a bare path is read as something else and the check
 * reports on an empty ruleset — which is why the style is declared here
 * rather than assumed.
 */
final class CheckCommand extends AbstractScriptCommand
{
    /**
     * `firewall-check`'s code for a configuration it cannot read, or
     * arguments that made no sense — sysexits' EX_USAGE.
     */
    public const EXIT_USAGE = 64;

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Ask whether a given request would be blocked, and by what')
            ->addOption('ip', null, InputOption::VALUE_REQUIRED, 'Client IP, v4 or v6. Default 127.0.0.1')
            ->addOption('url', null, InputOption::VALUE_REQUIRED, 'Path, with optional query string. Default /')
            ->addOption(
                'method',
                null,
                InputOption::VALUE_REQUIRED,
                'HTTP method. Default GET, or POST when --body is given'
            )
            ->addOption(
                'header',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Request header as NAME:VALUE. Repeatable'
            )
            ->addOption('body', null, InputOption::VALUE_REQUIRED, 'Request body')
            ->addOption(
                'script-name',
                null,
                InputOption::VALUE_REQUIRED,
                'The PHP file the web server runs for this URL. Rarely right here: Symfony always runs public/index.php'
            )
            ->addOption('explain', null, InputOption::VALUE_NONE, 'Show every rule that evaluated, with result and timing')
            ->addOption('lint', null, InputOption::VALUE_NONE, 'Report what is wrong with the rules, evaluating no request')
            ->addOption(
                'live-storage',
                null,
                InputOption::VALUE_NONE,
                'Consult the configured storage instead of a throwaway store. A block is then recorded for real'
            )
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->setHelp(
                <<<'HELP'
                Evaluates one synthetic request against the configuration this application runs.

                  <info>%command.full_name% --ip=203.0.113.5 --url=/wp-admin/ --explain</info>
                  <info>%command.full_name% --lint</info>

                Exit codes are the script's, one per verdict, so a CI gate can assert which one:
                <comment>0</comment> allowed, <comment>1</comment> blocked, <comment>2</comment> challenged, <comment>3</comment> redirected,
                <comment>64</comment> the configuration could not be read or the arguments made no sense,
                <comment>70</comment> the evaluation failed unexpectedly.

                <comment>--script-name</comment> simulates a file the web server runs directly, as WordPress
                serves <comment>/wp-login.php</comment>. A Symfony application always runs <comment>public/index.php</comment>,
                so the default is the answer here unless the firewall sits in front of something else.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-check';
    }

    /**
     * {@inheritdoc}
     */
    protected function configStyle(): string
    {
        return self::CONFIG_OPTION;
    }

    /**
     * {@inheritdoc}
     *
     * 64, the script's own code for a configuration it cannot read, rather
     * than the 2 every other command uses. To this script 2 means
     * challenged, so a CI gate asserting that a URL is challenged would pass
     * on an application with no firewall configuration at all.
     */
    protected function noConfigExitCode(): int
    {
        return self::EXIT_USAGE;
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return $this->forwardOptions(
            $input,
            flags: ['explain', 'lint', 'live-storage', 'json'],
            values: ['ip', 'url', 'method', 'body', 'script-name'],
            repeatable: ['header']
        );
    }
}
