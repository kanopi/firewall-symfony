<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * What every `kanopi:firewall:*` command agrees about.
 *
 * ## The exit codes are a contract, not a detail
 *
 * These are the library's own, and they are the reason a deploy step can
 * gate on a firewall command at all. They are declared here so the native
 * commands — the ones that answer without running a script — return the
 * same numbers for the same conditions as the wrappers do. A `health` that
 * returned 1 for "a rule is not running" while `doctor` returned 2 for the
 * same rule would make the pair unusable in a pipeline.
 *
 * ## Why `--format` and not `--json`
 *
 * The library's scripts take `--json`, and the wrappers forward it
 * unchanged, because their output is the script's. The native commands
 * render their own, so they take Drush's shape instead:
 * `--format=table|json|yaml`. Three formats where the scripts have two is
 * not inconsistency for its own sake — `yaml` is what
 * `kanopi:firewall:config` has to emit, since its subject *is* a YAML
 * document, and having one command take `--format` while its neighbours
 * took `--json` would be the worse split.
 */
abstract class AbstractFirewallCommand extends Command
{
    /**
     * Nothing wrong, or warnings only.
     */
    public const EXIT_OK = 0;

    /**
     * Something configured is not happening, or the action was refused.
     */
    public const EXIT_ERROR = 1;

    /**
     * The configuration could not be read, or the arguments made no sense.
     */
    public const EXIT_CONFIG_UNREADABLE = 2;

    /**
     * Changes are pending — `migrate --dry-run` only, so a deploy can gate
     * on "the schema is not current" without applying anything.
     */
    public const EXIT_PENDING = 3;

    /**
     * Declare `--format`, for a command that renders its own output.
     */
    protected function addFormatOption(): void
    {
        $this->addOption(
            'format',
            null,
            InputOption::VALUE_REQUIRED,
            sprintf('Output format: %s.', implode(', ', ResultPrinter::FORMATS)),
            ResultPrinter::FORMAT_TABLE
        );
    }

    /**
     * The printer for this run, or NULL when `--format` named nothing real.
     *
     * Returning NULL rather than throwing keeps the exit code in the
     * command's hands: a mistyped format is "the arguments made no sense",
     * which is a 2, and an exception escaping to the Application would
     * report it as a 1 — the code a script reads as "the firewall said no".
     */
    protected function printer(InputInterface $input, OutputInterface $output): ?ResultPrinter
    {
        $symfonyStyle = new SymfonyStyle($input, $output);
        $format = $input->getOption('format');

        if (is_string($format) && in_array($format, ResultPrinter::FORMATS, true)) {
            return new ResultPrinter($format, $symfonyStyle);
        }

        $symfonyStyle->error(sprintf(
            'Unknown --format %s. Use one of: %s.',
            is_scalar($format) ? sprintf('"%s"', $format) : 'value',
            implode(', ', ResultPrinter::FORMATS)
        ));

        return null;
    }

    /**
     * The value of a string option, trimmed, or an empty string.
     *
     * @param InputInterface $input
     *   This run's input.
     * @param string $name
     *   The option name.
     */
    protected function text(InputInterface $input, string $name): string
    {
        $value = $input->getOption($name);

        return is_string($value) ? trim($value) : '';
    }
}
