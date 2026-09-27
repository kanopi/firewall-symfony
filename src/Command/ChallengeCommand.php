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
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Read a challenge pass, and withdraw one.
 *
 * A pass token is stateless and HMAC-signed, so until kanopi/firewall 2.30.0
 * the only way to stop one being accepted was to rotate `challenge.secret` —
 * which re-challenges every legitimate visitor holding a pass in order to
 * withdraw a single one. `bin/firewall-challenge` keeps a revocation list
 * instead, and this is that script for an application that already knows
 * where its configuration is.
 *
 * ## Why the effective configuration, and not the files on disk
 *
 * Every action but `--status` and `--restore` decodes a token, and a token
 * only decodes against the secret that signed it. That secret is usually
 * `kanopi_firewall.challenge.secret` — bundle config, applied as an override
 * — so the YAML files alone would carry a different secret or none, and
 * every real pass would be reported as "not signed by this configuration".
 * The effective configuration is the one the listener signs with, which is
 * the only one whose answer means anything.
 *
 * ## Like `kanopi:firewall:blocks`, this writes to the real store
 *
 * A revocation is a record in the configured storage backend, read by the
 * firewall on the next request that presents the pass. That is the point of
 * it, and the script names the backend in its output so a revocation written
 * to an in-memory store — forgotten when the process exits — says so.
 *
 * ## Exactly one action, checked before anything is written
 *
 * The script refuses zero or several actions itself. It is checked here as
 * well, and first, because by the time the script could refuse, the
 * effective configuration — resolved secret included — has already been
 * written to a temporary file. Refusing a typo should not need one.
 */
final class ChallengeCommand extends AbstractScriptCommand
{
    /**
     * The script's actions, of which exactly one must be given.
     */
    public const ACTIONS = ['inspect', 'revoke', 'revoke-nonce', 'restore', 'status'];

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Inspect, revoke and restore challenge passes')
            ->addOption('inspect', null, InputOption::VALUE_REQUIRED, 'Decode a pass: address, provider, issued, expires, nonce')
            ->addOption('revoke', null, InputOption::VALUE_REQUIRED, 'Withdraw that pass, until its own expiry')
            ->addOption(
                'revoke-nonce',
                null,
                InputOption::VALUE_REQUIRED,
                'Withdraw a pass by its nonce, for when the log is what you have'
            )
            ->addOption('restore', null, InputOption::VALUE_REQUIRED, 'Put a revoked pass back, by nonce')
            ->addOption('status', null, InputOption::VALUE_REQUIRED, 'Whether a nonce is currently revoked, and why')
            ->addOption(
                'expires',
                null,
                InputOption::VALUE_REQUIRED,
                'With --revoke-nonce: when the pass expires, as a unix timestamp. Defaults to now plus challenge.ttl'
            )
            ->addOption('reason', null, InputOption::VALUE_REQUIRED, 'Recorded alongside a revocation')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->setHelp(
                <<<'HELP'
                Reads and writes the revocation list the firewall consults, in the configured storage.

                  <info>%command.full_name% --inspect=TOKEN</info>                       what a pass says about itself
                  <info>%command.full_name% --revoke=TOKEN --reason="Shared in #ops"</info>  withdraw it
                  <info>%command.full_name% --revoke-nonce=NONCE</info>                  withdraw one seen in a log
                  <info>%command.full_name% --status=NONCE</info>                        is it revoked, and why
                  <info>%command.full_name% --restore=NONCE</info>                       accept it again

                Give exactly one action. The pass token is the value of the
                <comment>kanopi_firewall.challenge.cookie_name</comment> cookie, or of the
                <comment>kanopi_firewall.challenge.header_name</comment> header.

                A revocation lasts until the pass would have expired anyway, and is only consulted
                while <comment>challenge.revocable</comment> is on; the output says when it is not.

                Exit codes are the script's: <comment>0</comment> the question was answered, whatever the
                answer, <comment>1</comment> the token is not one this configuration signed or has already
                expired, <comment>2</comment> the configuration could not be read or the arguments made no sense.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $given = array_values(array_filter(
            self::ACTIONS,
            static fn (string $action): bool => is_string($input->getOption($action)) && $input->getOption($action) !== ''
        ));

        // The escape hatch can carry an action too; leave the count to the
        // script then, which sees the whole argument list.
        if (count($given) !== 1 && $input->getArgument('forward') === []) {
            $errorOutput = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
            $errorOutput->writeln(
                $given === []
                    ? '<error>Nothing to do. Give one of --inspect, --revoke, --revoke-nonce, --restore or --status.</error>'
                    : sprintf('<error>Give exactly one action, not %s.</error>', implode(' and ', array_map(
                        static fn (string $action): string => '--' . $action,
                        $given
                    )))
            );

            return self::EXIT_CONFIG_UNREADABLE;
        }

        return parent::execute($input, $output);
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-challenge';
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return $this->forwardOptions(
            $input,
            flags: ['json'],
            values: [...self::ACTIONS, 'expires', 'reason']
        );
    }
}
