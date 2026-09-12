<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Firewall;

use Kanopi\Firewall\Utility\Config;

/**
 * The merged library configuration, read the way the firewall reads it.
 *
 * ## Why this is not "just read the YAML"
 *
 * What the firewall enforces is never one file. It is the bundle's
 * `config_files` and inline `settings`, merged in order, plus whatever
 * `configs:` includes those files pull in — presets, environment overlays —
 * plus the bundle's own overrides applied last. Reporting on any single
 * input tells an operator about a fragment of the thing they asked about.
 *
 * `Config::load()` is the library's own merge, cache and override pass, so
 * asking it is the only way to be sure that `kanopi:firewall:status` and the
 * request path agree about what is configured. The alternative — a parser
 * here — would be a second implementation of the merge rules, and the first
 * `configs:` include or `%env()%` token would make it disagree.
 *
 * ## Why there is no list of includes
 *
 * `configs:` inside a configuration file pulls in presets and overlays, and
 * "which preset did that rule come from?" is a question worth answering. It
 * cannot be answered from here: the library resolves those includes while
 * loading and **removes the key** from the merged result, so by the time
 * this class has a document there is nothing left that names them. An
 * include declared in the bundle's inline `settings` array is not resolved
 * at all, so reporting that one would be worse than reporting nothing — it
 * would name a file that contributed nothing.
 *
 * What is left is honest and nearly as useful: `kanopi:firewall:status`
 * names the inputs the bundle declared, and `kanopi:firewall:config` prints
 * what they became, includes and all.
 *
 * ## Load errors are part of the answer
 *
 * Loading is lenient: an input that cannot be read contributes nothing and
 * the firewall starts on what is left. That is the failure mode worth
 * shouting about, because it is invisible — one `%env()%` token naming an
 * unset variable discards the whole file rather than that one value, and a
 * firewall with no rules answers every request by allowing it. So the
 * errors the loader recorded are collected here and surfaced by
 * `kanopi:firewall:status` and the doctor.
 *
 * @phpstan-type RuleRow array{
 *     name: string,
 *     plugin: string,
 *     response: string,
 *     weight: int,
 *     enabled: bool,
 *     entries: int
 * }
 */
final class ConfigSnapshot
{
    /**
     * Memoized merge. One `Config::load()` per process.
     *
     * @var array<string, mixed>|null
     */
    private ?array $config = null;

    /**
     * Load errors recorded while producing `$config`.
     *
     * @var array<int, string>
     */
    private array $errors = [];

    /**
     * @param array<int, string|array<string, mixed>> $configs
     *   The same config inputs handed to `Firewall::create()`.
     * @param array<string, mixed> $overrides
     *   The same overrides.
     */
    public function __construct(
        private readonly array $configs,
        private readonly array $overrides
    ) {
    }

    /**
     * The whole merged configuration.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        if ($this->config !== null) {
            return $this->config;
        }

        // Cleared first, then read: the list is static on the library and
        // accumulates across every load in the process, so without this the
        // errors reported would include ones another component caused.
        Config::clearLoadErrors();

        /** @var array<string, mixed> $config */
        $config = Config::load($this->configs, $this->overrides);

        $this->errors = array_map(
            static fn (array $error): string => sprintf('%s: %s', $error['file'], $error['message']),
            Config::getLoadErrors()
        );

        return $this->config = $config;
    }

    /**
     * Inputs that failed to load, as sentences.
     *
     * @return array<int, string>
     *   Empty when every input contributed.
     */
    public function loadErrors(): array
    {
        $this->all();

        return $this->errors;
    }

    /**
     * The rules the firewall will evaluate, in evaluation order.
     *
     * Ordered by `weight` here rather than left in declaration order,
     * because weight is what the library sorts on and a list in file order
     * would show an operator a sequence the firewall does not use. Ties keep
     * their declared order, which is also what the library does.
     *
     * @return array<int, RuleRow>
     */
    public function rules(): array
    {
        $plugins = $this->all()['plugins'] ?? null;
        $rows = [];
        $index = 0;

        foreach (is_array($plugins) ? $plugins : [] as $plugin) {
            if (!is_array($plugin)) {
                continue;
            }

            $rows[] = ['order' => $index++, 'row' => $this->ruleRow($plugin)];
        }

        usort(
            $rows,
            static fn (array $a, array $b): int
                => [$a['row']['weight'], $a['order']] <=> [$b['row']['weight'], $b['order']]
        );

        return array_map(static fn (array $entry): array => $entry['row'], $rows);
    }

    /**
     * The configured mode, as the merged configuration states it.
     *
     * This is the library's `global.mode`, which is not the same question as
     * `kanopi_firewall.mode`: the bundle's mode decides whether the listener
     * may act on a verdict, and this one decides what verdict the library
     * reaches. They are reported side by side for that reason — a bundle in
     * `enforce` over a library in `log` blocks nothing, and each half looks
     * correct on its own.
     */
    public function libraryMode(): string
    {
        $global = $this->all()['global'] ?? null;
        $mode = is_array($global) ? ($global['mode'] ?? null) : null;

        return is_string($mode) && $mode !== '' ? $mode : 'block';
    }

    /**
     * Is the firewall configured to refuse everybody?
     *
     * `global.lockdown` is a flag rather than a mode — the modes are the
     * delivery axis (exit, throw, log) and this is a policy one — so it is
     * invisible in every field that reports a mode, and a deployment can sit
     * in lockdown looking perfectly ordinary. Which is the failure worth
     * catching: lockdown is meant to be temporary, and the realistic mistake
     * is nobody noticing it is still on.
     *
     * @return array{active: bool, allowed: int}
     *   Whether it is on, and how many entries the allowlist has. An empty
     *   allowlist with lockdown on refuses everyone including the operator,
     *   which the library's own doctor reports as an error.
     */
    public function lockdown(): array
    {
        $global = $this->all()['global'] ?? null;
        $global = is_array($global) ? $global : [];
        $allowed = $global['lockdown_allow'] ?? null;

        return [
            // `mode: lockdown` is documented shorthand for the flag, so a
            // report reading only the flag would say "off" for a firewall
            // that is refusing every request.
            'active' => ($global['lockdown'] ?? false) === true || ($global['mode'] ?? null) === 'lockdown',
            'allowed' => is_array($allowed) ? count($allowed) : 0,
        ];
    }

    /**
     * The configured storage class, or an empty string when none is set.
     */
    public function storageType(): string
    {
        $storage = $this->all()['storage'] ?? null;
        $type = is_array($storage) ? ($storage['type'] ?? null) : null;

        return is_string($type) ? $type : '';
    }

    /**
     * One `plugins:` entry, flattened for display.
     *
     * @param array<array-key, mixed> $plugin
     *   The entry as the merged configuration carries it.
     *
     * @return RuleRow
     */
    private function ruleRow(array $plugin): array
    {
        $class = is_string($plugin['plugin'] ?? null) ? $plugin['plugin'] : '(none)';
        $metadata = is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];
        $name = $metadata['name'] ?? null;
        $weight = $plugin['weight'] ?? 0;
        $entries = $plugin['config'] ?? null;

        return [
            // Falls back to the short class name, which is what the library
            // logs when a rule carries no `metadata.name` — so the two agree
            // and a name read out of a log can be found in this list.
            'name' => is_string($name) && $name !== '' ? $name : $this->shortName($class),
            'plugin' => $class,
            'response' => is_string($plugin['response'] ?? null) ? $plugin['response'] : 'block',
            'weight' => is_numeric($weight) ? (int) $weight : 0,
            // Absent means enabled, which is the library's own reading: a
            // rule is written to be evaluated, and `enable: false` is how it
            // is parked.
            'enabled' => !array_key_exists('enable', $plugin) || (bool) $plugin['enable'],
            'entries' => is_array($entries) ? count($entries) : 0,
        ];
    }

    /**
     * The last segment of a class name.
     */
    private function shortName(string $class): string
    {
        $position = strrpos($class, '\\');

        return $position === false ? $class : substr($class, $position + 1);
    }
}
