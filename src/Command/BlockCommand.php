<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Kanopi\Firewall\Exception\FirewallException;
use Kanopi\FirewallBundle\Firewall\BlockManager;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Block a client now, without writing a rule.
 *
 * The rule-shaped answer to "stop this address" is
 * `kanopi:firewall:rule add --ip=… --response=block`, and it is the better
 * answer whenever there is time for it: a rule is configuration, it is
 * reviewable, it survives a cleared block list and it says why it exists.
 *
 * This is for when there is not time for it. A scraper is costing money now,
 * or a customer's compromised office IP needs stopping before anyone can
 * agree on a rule. The block is durable state rather than configuration, so
 * it takes effect on the next request with no deploy — and `--duration`
 * means it lapses on its own rather than outliving the incident.
 *
 * Takes the address as an argument rather than an option, because that is
 * the shape of the thing being acted on and `kanopi:firewall:block
 * 203.0.113.9` is what somebody types under pressure.
 *
 * There is no script behind this one. `bin/firewall-block` can list, find,
 * show and lift; it cannot add. See BlockManager for what filling that gap
 * required knowing about the storage contract.
 */
final class BlockCommand extends AbstractFirewallCommand
{
    /**
     * How long a block lasts when nobody says.
     *
     * An hour: long enough to end an incident, short enough that a block
     * nobody revisits does not become a permanent one by accident.
     */
    private const DEFAULT_DURATION = 3600;

    public function __construct(private readonly BlockManager $blockManager)
    {
        parent::__construct();
    }

    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Block a client address immediately')
            ->addArgument('ip', InputArgument::REQUIRED, 'The client address to block. A single IP, not a range')
            ->addOption(
                'duration',
                null,
                InputOption::VALUE_REQUIRED,
                'Seconds until the block lapses. 0 blocks until it is lifted',
                (string) self::DEFAULT_DURATION
            )
            ->addOption('reason', null, InputOption::VALUE_REQUIRED, 'A note stored with the block, for whoever reads the list next')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Replace an existing block, so a new duration applies')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% 203.0.113.9</info>                                  an hour
                  <info>%command.full_name% 203.0.113.9 --duration=0 --reason="Scraping /api"</info>  until lifted

                A range belongs in a rule, not here: a block is stored under one exact address
                and a range would match no visitor. Use
                <comment>kanopi:firewall:rule add --ip=203.0.113.0/24</comment> for that.

                Lift it with <comment>kanopi:firewall:unblock</comment>, and see the list with
                <comment>kanopi:firewall:blocks --list</comment>.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $symfonyStyle = new SymfonyStyle($input, $output);
        $ip = $input->getArgument('ip');

        try {
            $result = $this->blockManager->add(
                is_string($ip) ? $ip : '',
                $this->duration($input),
                $this->text($input, 'reason'),
                (bool) $input->getOption('force')
            );
        } catch (FirewallException $firewallException) {
            // Every refusal this can hit — a range where an address belongs,
            // an already-blocked client, a backend that will not write —
            // arrives as a FirewallException carrying a message written for
            // an operator. Shown as-is rather than wrapped, because the
            // wrapping would only repeat it less well.
            $symfonyStyle->error($firewallException->getMessage());

            return self::EXIT_ERROR;
        }

        $symfonyStyle->success(sprintf(
            '%s %s.',
            $result['replaced'] ? 'Replaced the block on' : 'Blocked',
            $result['address']
        ));

        $symfonyStyle->table(['Item', 'Value'], [
            ['Expires', $result['expires']],
            // Printed because it is the only way back from an error page to
            // a record: the visitor sees this string and nothing else
            // identifying.
            ['Reference', $result['reference']],
            ['Backend', $this->blockManager->backendClass()],
        ]);

        $this->warnIfEphemeral($symfonyStyle);

        return self::EXIT_OK;
    }

    /**
     * The requested duration in seconds.
     *
     * A non-numeric `--duration` becomes the default hour rather than the
     * `0` that a cast would produce — and `0` means "until somebody lifts
     * it". A typo should not silently create a permanent block.
     */
    private function duration(InputInterface $input): int
    {
        $duration = $input->getOption('duration');

        return is_string($duration) && is_numeric($duration)
            ? max(0, (int) $duration)
            : self::DEFAULT_DURATION;
    }

    /**
     * Say so when the block will not outlive the command.
     *
     * `InMemoryStorage` accepts the write and reports success, and the
     * record is gone when the process exits. Without this the command is
     * indistinguishable from one that worked.
     */
    private function warnIfEphemeral(SymfonyStyle $symfonyStyle): void
    {
        if (!str_contains($this->blockManager->backendClass(), 'InMemoryStorage')) {
            return;
        }

        $symfonyStyle->warning(
            'Storage is in-memory, so this block was discarded the moment it was written and '
            . 'no visitor will ever be refused by it. Configure FileStorage, DatabaseStorage or '
            . 'RedisStorage for a block to mean anything.'
        );
    }
}
