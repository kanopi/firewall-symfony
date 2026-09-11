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
 * Let a client back in.
 *
 * Accepts a range as well as an address, because lifting matches against
 * what is already stored rather than creating a key — `10.0.0.0/8` means
 * "everything in the list inside this range". That asymmetry with
 * `kanopi:firewall:block`, which refuses ranges, is not an inconsistency: a
 * range cannot be *stored* as a block because lookups are exact, but it is
 * exactly the right shape for *finding* blocks to remove.
 *
 * `--all` empties the list. It lifts every address rather than resetting the
 * backend, which would also discard offense history — and that history is
 * what drives escalating bans, so resetting it would quietly reward every
 * address that has ever misbehaved.
 */
final class UnblockCommand extends AbstractFirewallCommand
{
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
            ->setDescription('Lift a firewall block')
            ->addArgument('ip', InputArgument::OPTIONAL, 'The address or CIDR range to lift. Omit it with --all')
            ->addOption('all', null, InputOption::VALUE_NONE, 'Lift every block currently in force')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what would be lifted without lifting it')
            ->addOption(
                'force',
                null,
                InputOption::VALUE_NONE,
                'Required with --all when there is nobody to confirm, such as in a deploy step'
            )
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% 203.0.113.9</info>                  one address
                  <info>%command.full_name% 10.0.0.0/8 --dry-run</info>         rehearse a range
                  <info>%command.full_name% --all --force</info>                empty the list, unattended

                Nothing matching is not an error: "this address is not blocked" is a complete
                answer, and a deploy step that defensively lifts an address should not start
                failing once the address is gone.
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
        $pattern = is_string($ip) ? trim($ip) : '';
        $all = (bool) $input->getOption('all');

        // Refused rather than resolved either way round. Guessing that
        // `--all` wins would empty the list for somebody who typed an
        // address; guessing the address wins would ignore a flag they passed
        // deliberately. Both are worse than asking again.
        if ($all && $pattern !== '') {
            $symfonyStyle->error('Pass either an address or --all, not both.');

            return self::EXIT_CONFIG_UNREADABLE;
        }

        if (!$all && $pattern === '') {
            $symfonyStyle->error('Name an address or range to lift, or pass --all to empty the list.');

            return self::EXIT_CONFIG_UNREADABLE;
        }

        $dryRun = (bool) $input->getOption('dry-run');

        if ($all && !$dryRun) {
            $refusal = $this->confirmClear($input, $symfonyStyle);

            if ($refusal !== null) {
                return $refusal;
            }
        }

        try {
            $lifted = $all
                ? $this->blockManager->clear($dryRun)
                : $this->blockManager->remove($pattern, $dryRun);
        } catch (FirewallException $firewallException) {
            $symfonyStyle->error($firewallException->getMessage());

            return self::EXIT_ERROR;
        }

        if ($lifted === 0) {
            // Not an error. "Nothing matched" is a complete and useful
            // answer to "is this address blocked?", and exiting non-zero
            // would make a deploy step that lifts an address defensively
            // fail once the address is no longer listed.
            $symfonyStyle->success($all
                ? 'The block list is already empty.'
                : sprintf('Nothing in the block list matches %s.', $pattern));

            return self::EXIT_OK;
        }

        $symfonyStyle->success(sprintf(
            '%s %d block%s%s.',
            $dryRun ? 'Would lift' : 'Lifted',
            $lifted,
            $lifted === 1 ? '' : 's',
            $all ? '' : sprintf(' matching %s', $pattern)
        ));

        if ($dryRun) {
            $symfonyStyle->warning('Dry run — nothing was changed.');
        }

        return self::EXIT_OK;
    }

    /**
     * Confirm emptying the list, telling "no" apart from "nobody answered".
     *
     * `SymfonyStyle::confirm()` cannot tell them apart on its own: under
     * `--no-interaction` the question cannot be asked and the default comes
     * back. A default of TRUE would empty the list for a script that never
     * meant to; a default of FALSE gives a deploy step that forgot a flag
     * exactly what a deliberate refusal looks like — no write, and a zero
     * exit that reads as "done".
     *
     * So the three cases are separated:
     *
     *  - Told yes, or given `--force` — proceed.
     *  - Asked and declined — a decision. Say so, and **succeed**: the
     *    operator got what they asked for, and a non-zero exit would make a
     *    person answering "no" look like a broken command.
     *  - Neither, with nobody to ask — refuse, loudly, and fail. Doing
     *    nothing quietly is the outcome that gets mistaken for success.
     *
     * @return int|null
     *   NULL to proceed, or the exit code the command should return.
     */
    private function confirmClear(InputInterface $input, SymfonyStyle $symfonyStyle): ?int
    {
        if ((bool) $input->getOption('force')) {
            return null;
        }

        if (!$input->isInteractive()) {
            $symfonyStyle->error(
                'Refusing to empty the block list: --all was given with nothing to confirm it and '
                . 'no --force. Re-run with --force, or lift addresses individually.'
            );

            return self::EXIT_CONFIG_UNREADABLE;
        }

        if ($symfonyStyle->confirm('Lift every block currently in force?', false)) {
            return null;
        }

        $symfonyStyle->warning('Declined, so the block list was left alone.');

        return self::EXIT_OK;
    }
}
