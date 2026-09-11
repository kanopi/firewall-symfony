<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * Add and remove rules without editing YAML by hand.
 *
 * Writes to a managed file it owns exclusively, and refuses to change a rule
 * it did not write. Rules declared in your own `firewall.yml` can be listed
 * but not edited, which is the right way round: a command that rewrote a
 * hand-written file would have to preserve its comments, its `%env()%`
 * tokens and its formatting, and would eventually fail to.
 *
 * Run `kanopi:firewall:rule init` once first. That writes the managed file
 * and adds it to the `configs:` list of the first configuration file, which
 * is what makes a rule added later actually live — a rule written somewhere
 * the firewall never reads is worse than no rule, and the script refuses to
 * add one for that reason.
 *
 * ## Why this command alone sees no inline settings
 *
 * Every other wrapper is handed the *effective* configuration, synthesised
 * from `config_files`, the inline `settings` array and the bundle's
 * overrides. This one is handed only the real files, because it edits rather
 * than reports: the managed file is placed beside the first config it is
 * given, so a synthetic file would put it in the temp directory and delete
 * it on exit, and rules that came from `settings` would be offered for
 * editing when nothing can edit them.
 */
final class RuleCommand extends AbstractScriptCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure(): void
    {
        $this
            ->setDescription('Add, remove, enable or disable managed rules')
            ->addArgument(
                'action',
                InputArgument::REQUIRED,
                'init, list, add, remove, disable or enable'
            )
            ->addArgument(
                'rule-name',
                InputArgument::OPTIONAL,
                'The rule to act on, for remove, disable and enable'
            )
            ->addOption('plugin', null, InputOption::VALUE_REQUIRED, 'ip, url, agent, asn, geo, or a class name. Default ip')
            ->addOption('response', null, InputOption::VALUE_REQUIRED, 'block, allow or challenge. Default block')
            ->addOption(
                'rule',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'A config entry for the rule. Required for add. Repeatable'
            )
            ->addOption(
                'ip',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Shorthand for --plugin=ip --rule=VALUE. Repeatable'
            )
            ->addOption(
                'path',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Shorthand for --plugin=url --rule=path:VALUE. Repeatable'
            )
            ->addOption('name', null, InputOption::VALUE_REQUIRED, 'What the log will call the new rule. Default is generated')
            ->addOption('weight', null, InputOption::VALUE_REQUIRED, 'Evaluation order, lower first. Default 0')
            ->addOption('managed', null, InputOption::VALUE_REQUIRED, 'Managed file to write. Default is beside the first config')
            ->addOption('lint', null, InputOption::VALUE_NONE, 'Check the managed file and report what is wrong with it')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Report what would change and write nothing')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Machine-readable output')
            ->setHelp(
                <<<'HELP'
                  <info>%command.full_name% init</info>                             once, before the first add
                  <info>%command.full_name% list</info>
                  <info>%command.full_name% add --ip=203.0.113.9 --name=office</info>
                  <info>%command.full_name% add --path=/xmlrpc.php --response=block</info>
                  <info>%command.full_name% disable office</info>
                  <info>%command.full_name% remove office</info>

                A durable block for one address is <comment>kanopi:firewall:block</comment> instead. That takes
                effect on the next request with no deploy, and lapses on its own; a rule is
                configuration, and is the better answer whenever there is time for one.
                HELP
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function script(): string
    {
        return 'firewall-rule';
    }

    /**
     * {@inheritdoc}
     */
    protected function editsConfiguration(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     *
     * The action, then the rule name. That order is the script's: for
     * `remove`, `disable` and `enable` the first bare word is the action and
     * the second is the rule name, so a name placed after the config paths
     * would be read as another config file and rejected as "Configuration
     * file not found".
     */
    protected function leadingArguments(InputInterface $input): array
    {
        $action = $input->getArgument('action');
        $leading = [is_string($action) ? $action : ''];
        $name = $input->getArgument('rule-name');

        if (is_string($name) && $name !== '') {
            $leading[] = $name;
        }

        return $leading;
    }

    /**
     * {@inheritdoc}
     */
    protected function scriptArguments(InputInterface $input): array
    {
        return $this->forwardOptions(
            $input,
            flags: ['lint', 'dry-run', 'json'],
            values: ['plugin', 'response', 'name', 'weight', 'managed'],
            repeatable: ['rule', 'ip', 'path']
        );
    }
}
