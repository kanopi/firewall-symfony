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
use Symfony\Component\Console\Output\OutputInterface;

/**
 * List the rules the firewall will evaluate, in evaluation order.
 *
 * The list is built from the **merged** configuration, which is the only
 * list that matches what runs: a preset pulled in through `configs:`, a rule
 * added by `kanopi:firewall:rule`, and a rule written in
 * `kanopi_firewall.settings` are all in it, and none of them is in the file
 * an operator is most likely to open. "Where did that rule come from?" is
 * the question this answers, and `kanopi:firewall:status` names the inputs
 * it came from.
 *
 * Ordered by weight rather than by declaration, because weight is what the
 * library sorts on — a list in file order would show a sequence the firewall
 * does not use.
 */
final class RulesCommand extends AbstractFirewallCommand
{
    /**
     * Which fields are shown, and what they are called.
     *
     * @var array<string, string>
     */
    private const COLUMNS = [
        'name' => 'Name',
        'plugin' => 'Plugin',
        'response' => 'Response',
        'weight' => 'Weight',
        'enabled' => 'Enabled',
        'entries' => 'Entries',
    ];

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
            ->setDescription('List the rules the firewall will evaluate, in evaluation order')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name%</info>
                  <info>%command.full_name% --format=json</info>

                <comment>Entries</comment> is how many patterns, addresses or paths a rule carries — a rule with
                none is usually a rule whose source has never been fetched (see
                <comment>kanopi:firewall:sources</comment>).

                Rules the library could not build are not listed as broken here, because this
                reads configuration rather than the running firewall. <comment>kanopi:firewall:health</comment>
                is the one that knows.
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

        $printer->table(self::COLUMNS, $this->configSnapshot->rules());

        return self::EXIT_OK;
    }
}
