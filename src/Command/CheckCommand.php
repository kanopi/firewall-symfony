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

                Exit codes are the script's: <comment>0</comment> allowed, <comment>1</comment> the request would be
                blocked or challenged, <comment>2</comment> the configuration could not be read.
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
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return $this->forwardOptions(
            $input,
            flags: ['explain', 'lint', 'live-storage', 'json'],
            values: ['ip', 'url', 'method', 'body'],
            repeatable: ['header']
        );
    }
}
