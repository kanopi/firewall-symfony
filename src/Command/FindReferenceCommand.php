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
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Turn a reference number from a block page back into a client.
 *
 * The firewall shows a blocked visitor a hex reference in its banning
 * message — the `event_id` it recorded with the block. That string is the
 * only thing a caller can read out: the page deliberately tells them nothing
 * about which rule matched or why.
 *
 * Which left support with a reference and no way to use it. The reference
 * appears on the page and in the logs, and nothing indexed it, so answering
 * "why is this customer blocked?" meant grepping logs and hoping the
 * retention window reached back far enough. This is that lookup, against the
 * block list itself.
 *
 * A reference that finds nothing is the ordinary case as often as it is a
 * mistyped one: blocks lapse, and the page the caller is looking at may be
 * cached or from yesterday. The output says so rather than implying the
 * reference was wrong.
 */
final class FindReferenceCommand extends AbstractFirewallCommand
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
            ->setDescription('Find which blocked client a reference number belongs to')
            ->addArgument(
                'reference',
                InputArgument::REQUIRED,
                'The reference from the block page, e.g. 2CB3B1780E3653DE9C7AFA913F3C1A33'
            )
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% 2CB3B1780E3653DE9C7AFA913F3C1A33</info>
                  <info>%command.full_name% 2cb3b178… --format=json</info>

                Exits <comment>1</comment> when nothing carries the reference, so a script can branch on it —
                but read the message first: a miss usually means the block has lapsed, not
                that anybody got the number wrong.
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

        $symfonyStyle = new SymfonyStyle($input, $output);
        $argument = $input->getArgument('reference');
        $reference = strtoupper(trim(is_string($argument) ? $argument : ''));

        try {
            $found = $this->blockManager->findReference($reference);
        } catch (FirewallException $firewallException) {
            // A backend that cannot be enumerated cannot be searched by
            // reference at all. Reported as an error rather than as "not
            // found", because those are different answers and only one of
            // them means the customer is not blocked.
            $symfonyStyle->error($firewallException->getMessage());

            return self::EXIT_ERROR;
        }

        if ($found === null) {
            return $this->reportMiss($printer, $symfonyStyle, $reference);
        }

        $record = $found['record'];

        $details = array_filter([
            'reference' => $this->blockManager->referenceOf($record),
            'found' => 'yes',
            'address' => $found['address'],
            'blocked_by_rule' => $this->blockManager->payloadValue($record, 'plugin'),
            'blocked_at' => $this->blockManager->payloadValue($record, 'timestamp'),
            'expires' => $this->blockManager->recordValue($record, 'expires_at'),
            'offenses' => $this->blockManager->recordValue($record, 'offenses'),
            'request_path' => $this->blockManager->payloadValue($record, 'path'),
            'reason' => $this->blockManager->payloadValue($record, 'reason'),
            'added_by' => $this->blockManager->payloadValue($record, 'blocked_by'),
        ], static fn (string $value): bool => $value !== '');

        $printer->properties($details);

        if (!$printer->isMachineReadable()) {
            $symfonyStyle->writeln(sprintf(
                ' Lift it with: <info>bin/console kanopi:firewall:unblock %s</info>',
                $found['address']
            ));
        }

        return self::EXIT_OK;
    }

    /**
     * Report a reference that matched nothing.
     *
     * Exits non-zero so a script can branch on it, while the message covers
     * the likeliest innocent explanations — because "not found" here usually
     * means the block has lapsed rather than that anybody got it wrong.
     */
    private function reportMiss(ResultPrinter $printer, SymfonyStyle $symfonyStyle, string $reference): int
    {
        $printer->properties(['reference' => $reference, 'found' => 'no']);

        if (!$printer->isMachineReadable()) {
            $symfonyStyle->writeln(
                ' That is expected if the block has since lapsed or been lifted — the list holds'
                . PHP_EOL . ' only what is currently in force. The firewall log keeps the decision for'
                . PHP_EOL . ' longer: search it for the reference to see what matched and when.'
            );
        }

        return self::EXIT_ERROR;
    }
}
