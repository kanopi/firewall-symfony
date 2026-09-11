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
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Base for the wrappers around kanopi/firewall's shipped `bin/` scripts.
 *
 * ## Why a subprocess and not a reimplementation
 *
 * The scripts are between 150 and 640 lines of argument parsing, output
 * formatting and exit-code policy, and most of it is not reachable through a
 * public class — `firewall-check`'s whole reason for existing is the three
 * ways hand-assembling the same call fails quietly. Rewriting them as native
 * `Command` classes would buy nicer help text and cost a 2,500-line fork
 * that drifts from the parent on every release, in the one part of the
 * system an operator reaches for during an incident. The exit codes are part
 * of the contract too — `firewall-migrate` returns 3 for "changes pending"
 * so it can gate a deploy — and reproducing those by hand is exactly the
 * kind of detail a fork loses first.
 *
 * What the wrapper adds over typing `vendor/bin/firewall-doctor` is the part
 * that is actually annoying: the configuration paths. `bin/console` already
 * knows which YAML this application's firewall is built from, so the
 * commands supply it. See EffectiveConfig for why that is more than reading
 * `config_files`.
 *
 * ## Why each script gets its own class
 *
 * This was one class and eight service definitions carrying the
 * differences, on the reasoning that eight near-identical subclasses are
 * eight places to fix the next bug in argument forwarding. What that
 * actually produced was a command whose only documented interface was
 * "everything after `--` is forwarded, try `-- --help`" — so
 * `bin/console kanopi:firewall:check --help` described nothing,
 * `--ip=1.2.3.4` typed without the `--` separator was rejected by Symfony
 * with no hint that the option was real, a typo inside the passthrough
 * reached the script and was ignored, and shell completion had nothing to
 * complete.
 *
 * So the options are declared, per script, and the shared mechanics stay
 * here. The passthrough survives as an escape hatch — `-- --whatever` still
 * reaches the script, which keeps an option added upstream usable before
 * this bundle is updated for it — but it is no longer the only way in.
 */
abstract class AbstractScriptCommand extends AbstractFirewallCommand
{
    /**
     * Config paths given as bare arguments, the way most scripts read them.
     */
    public const CONFIG_BARE = 'bare';

    /**
     * Config paths given as `--config=PATH`, which `firewall-check`
     * requires.
     */
    public const CONFIG_OPTION = 'option';

    /**
     * The script takes no configuration — `firewall-init` writes one.
     */
    public const CONFIG_NONE = 'none';

    /**
     * @param ScriptRunner $scriptRunner
     *   Runs the child process.
     * @param EffectiveConfig $effectiveConfig
     *   Materializes the configuration the listener actually runs.
     */
    public function __construct(
        private readonly ScriptRunner $scriptRunner,
        private readonly EffectiveConfig $effectiveConfig
    ) {
        parent::__construct();

        // Declared here rather than in `configure()`, and the ordering is
        // not cosmetic: Symfony refuses a required argument declared after
        // an array argument, so a `forward` added by the base before the
        // subclass's own `configure()` ran made
        // `kanopi:firewall:rule <action>` a container that would not
        // compile. `Command::__construct()` calls `configure()`, so by the
        // time this line runs every subclass argument is already in place
        // and the array argument lands last however many a subclass
        // declares.
        if ($this->configStyle() !== self::CONFIG_NONE) {
            $this->addOption(
                'config',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Configuration file to use instead of the ones this application is configured with. Repeatable.'
            );
        }

        $this->addArgument(
            'forward',
            InputArgument::IS_ARRAY | InputArgument::OPTIONAL,
            sprintf(
                'Extra options for %s, after a "--" separator. Only needed for an option this '
                . 'command does not declare.',
                $this->script()
            )
        );
    }

    /**
     * The script this command wraps, e.g. `firewall-doctor`.
     */
    abstract protected function script(): string;

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $arguments = array_merge(
            $this->leadingArguments($input),
            $this->scriptArguments($input),
            $this->passthrough($input)
        );

        if ($this->configStyle() === self::CONFIG_NONE) {
            return $this->scriptRunner->run($this->script(), $arguments, $output);
        }

        /** @var array<int, string> $overridden */
        $overridden = $input->getOption('config');

        // An explicit --config is taken at face value: the operator is
        // asking about that file, not about what this application runs.
        [$paths, $temporary] = $overridden !== []
            ? [$overridden, []]
            : $this->effectiveConfig->materialize(!$this->editsConfiguration());

        if ($paths === []) {
            return $this->reportNoConfig($output);
        }

        try {
            return $this->scriptRunner->run(
                $this->script(),
                array_merge($arguments, $this->formatPaths($paths)),
                $output
            );
        } finally {
            // `finally`, so a script that throws, times out or is killed
            // still does not leave a file carrying a resolved
            // `challenge.secret` behind.
            $this->effectiveConfig->discard($temporary);
        }
    }

    /**
     * How this script wants to be told where its configuration is.
     *
     * @return string
     *   One of the CONFIG_* constants.
     */
    protected function configStyle(): string
    {
        return self::CONFIG_BARE;
    }

    /**
     * Does this command write configuration rather than report on it?
     *
     * TRUE means it sees only the real files on disk. `firewall-rule` places
     * its managed file beside the first config it is given and offers rules
     * for editing by name, so a synthetic file would put the managed file in
     * the temp directory and list rules nothing can edit.
     */
    protected function editsConfiguration(): bool
    {
        return false;
    }

    /**
     * Arguments that must come before everything else.
     *
     * `firewall-rule` reads its action from the first bare word and its rule
     * name from the second, so those cannot follow the options or the config
     * paths.
     *
     * @param InputInterface $input
     *   This run's input.
     *
     * @return array<int, string>
     *   Bare words, in order.
     */
    protected function leadingArguments(InputInterface $input): array
    {
        return [];
    }

    /**
     * The options to forward, built from the ones this run was given.
     *
     * Abstract rather than defaulted to an empty list: every wrapper has
     * options worth declaring, and a base implementation returning nothing
     * would be a silent way for a new one to forward none of them.
     *
     * @param InputInterface $input
     *   This run's input.
     *
     * @return array<int, string>
     *   Arguments for the script.
     */
    abstract protected function scriptArguments(InputInterface $input): array;

    /**
     * Build a forwarding list from the options that were actually given.
     *
     * Symfony Console reports every declared option, set or not, so
     * forwarding them blindly would hand the script `--json` when the
     * operator did not ask for it and change its output format.
     *
     * @param InputInterface $input
     *   This run's input.
     * @param array<int, string> $flags
     *   Boolean option names, forwarded when true.
     * @param array<int, string> $values
     *   Value option names, forwarded when non-empty.
     * @param array<int, string> $repeatable
     *   Array option names, forwarded once per value.
     *
     * @return array<int, string>
     *   Arguments for the script.
     */
    protected function forwardOptions(
        InputInterface $input,
        array $flags = [],
        array $values = [],
        array $repeatable = []
    ): array {
        $arguments = [];

        foreach ($flags as $flag) {
            if ((bool) $input->getOption($flag)) {
                $arguments[] = '--' . $flag;
            }
        }

        foreach ($values as $name) {
            $value = $input->getOption($name);

            if (is_string($value) && $value !== '') {
                $arguments[] = '--' . $name . '=' . $value;
            }
        }

        foreach ($repeatable as $name) {
            $items = $input->getOption($name);

            // Narrowed in the `foreach` subject rather than by an early
            // `continue`: an option declared VALUE_IS_ARRAY always yields an
            // array, so a separate guard would be a branch nothing can
            // reach.
            foreach (is_array($items) ? $items : [] as $item) {
                if (is_string($item) && $item !== '') {
                    $arguments[] = '--' . $name . '=' . $item;
                }
            }
        }

        return $arguments;
    }

    /**
     * Anything given after `--`.
     *
     * @param InputInterface $input
     *   This run's input.
     *
     * @return array<int, string>
     *   Arguments for the script, untouched.
     */
    private function passthrough(InputInterface $input): array
    {
        /** @var array<int, string> $forwarded */
        $forwarded = $input->getArgument('forward');

        return $forwarded;
    }

    /**
     * Render paths the way this script wants them.
     *
     * @param array<int, string> $paths
     *   Configuration file paths.
     *
     * @return array<int, string>
     *   Arguments to append.
     */
    private function formatPaths(array $paths): array
    {
        if ($this->configStyle() === self::CONFIG_OPTION) {
            return array_map(static fn (string $path): string => '--config=' . $path, $paths);
        }

        return $paths;
    }

    /**
     * There is nothing to report on.
     *
     * Reached when no `config_files` are set and — for a command that edits
     * configuration — no real file exists to edit. Synthesising one from the
     * bundle's defaults instead would produce a command that appears to work
     * and reports on a firewall with no rules.
     */
    private function reportNoConfig(OutputInterface $output): int
    {
        $errorOutput = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;

        $errorOutput->writeln(sprintf(
            '<error>%s needs a configuration file, and kanopi_firewall.config_files is empty.</error>',
            $this->script()
        ));
        $errorOutput->writeln('');
        $errorOutput->writeln('Either add the path there, or pass one: <info>--config=config/firewall.yml</info>.');

        if ($this->editsConfiguration()) {
            $errorOutput->writeln(
                'This command writes configuration, so it needs a real file — '
                . '<comment>kanopi_firewall.settings</comment> is a container array and nothing can edit it.'
            );
        }

        return self::EXIT_CONFIG_UNREADABLE;
    }
}
