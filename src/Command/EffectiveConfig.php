<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Symfony\Component\Yaml\Yaml;

/**
 * Gives the wrapped scripts the configuration the listener actually runs.
 *
 * ## The bug this exists to fix
 *
 * The scripts are separate processes that read YAML from disk. Half the
 * bundle's configuration is not on disk: `kanopi_firewall.settings` is a PHP
 * array in the container, and everything the bundle decides — the forced
 * mode, the proxy posture, the challenge path and cookie, and any
 * `challenge.secret` set in bundle config — is a PropertyAccess override
 * applied at runtime. Handing the scripts only `config_files` means they
 * diagnose a configuration nobody runs.
 *
 * That is not academic. The README tells you to put `challenge.secret` in
 * `kanopi_firewall.challenge.secret`, typically from an env var. Do that,
 * and `kanopi:firewall:doctor` reported:
 *
 *     ✗ The firewall refuses to start with this configuration
 *         response: challenge plugins are configured but `challenge.secret`
 *         is empty.
 *
 * — about an application that starts and serves challenges perfectly well.
 * A health command that invents a fatal error is worse than no health
 * command, because the next real one gets ignored too.
 *
 * ## How
 *
 * Each inline array is written to a short-lived YAML file and passed
 * alongside the real ones, in the same order, so the library does its own
 * merging exactly as it would at runtime. The overrides go last, as one more
 * file, because "applied after everything else" is what an override is.
 *
 * The files are created by `tempnam()`, which makes them 0600, and deleted
 * in a `finally` — so a resolved secret is readable only by the user running
 * the command, and only while the child process is alive. Writing them
 * somewhere permanent (a cache directory, say) was the alternative; it lost
 * because a secret that outlives the command is a secret somebody has to
 * remember to clean up.
 *
 * ## Two things it does not do
 *
 * **An override is not quite a config file.** `Firewall::create()` applies
 * overrides with PropertyAccess, which *replaces* a value; a config file is
 * merged, which for a list appends. The two differ only for an override
 * whose value is an array — in practice `[challenge][provider_options]` —
 * and only in what the diagnostic commands report, never at runtime.
 *
 * **`kanopi:firewall:rule` does not get this.** That command edits
 * configuration: it appends to a managed file it places beside the first
 * config it was given, and it lists rules as things you can remove by name.
 * Both go wrong when handed a synthetic file — the managed file would land
 * in the temp directory, and rules that came from `settings` would be
 * offered for editing when nothing can edit them.
 */
final class EffectiveConfig
{
    /**
     * @param array<int, string|array<string, mixed>> $libraryConfigs
     *   The bundle's config inputs, in merge order.
     * @param array<string, mixed> $overrides
     *   PropertyAccess bracket paths, as `Firewall::create()` receives them.
     * @param ProxyPosture|null $proxyPosture
     *   Contributes `global.behind_proxy`, which is decided at runtime
     *   rather than baked into the overrides. A console process boots the
     *   kernel, and `Kernel::preBoot()` applies `framework.trusted_proxies`
     *   while doing so — so the posture here is the same one the listener
     *   would see. Without it `kanopi:firewall:doctor` reported
     *   "behind_proxy: unset" for an application that had asserted it.
     */
    public function __construct(
        private readonly array $libraryConfigs,
        private readonly array $overrides,
        private readonly ?ProxyPosture $proxyPosture = null
    ) {
    }

    /**
     * The config paths to hand the script.
     *
     * @param bool $includeInline
     *   FALSE to pass only the real files on disk, for a command that edits
     *   configuration rather than reporting on it.
     *
     * @return array{0: array<int, string>, 1: array<int, string>}
     *   The paths to pass, and the subset of them that must be deleted
     *   afterwards. The second is always a subset of the first, so a caller
     *   that forgets the cleanup leaks a file rather than breaking.
     */
    public function materialize(bool $includeInline = true): array
    {
        $files = array_values(array_filter($this->libraryConfigs, is_string(...)));
        $inline = array_values(array_filter($this->libraryConfigs, is_array(...)));

        // Nothing configured at all. Synthesising a file from the overrides
        // alone would produce a command that "works" against the library's
        // shipped defaults and reports on no rules, which is a worse answer
        // than the one the caller gives for an empty list.
        if ($files === [] && ($inline === [] || !$includeInline)) {
            return [$files, []];
        }

        if (!$includeInline) {
            return [$files, []];
        }

        // Beside the first real config when there is one. Relative paths in
        // the library's YAML — `storage.config.storage_file` and friends —
        // resolve against the directory of the file that declared them, so
        // a temp file in /tmp would silently point the diagnostics at a
        // different storage file than the application uses.
        $directory = $files === [] ? null : dirname($files[0]);

        $paths = $files;
        $temporary = [];

        foreach ($inline as $settings) {
            $paths[] = $temporary[] = $this->write($settings, $directory);
        }

        $overrides = array_merge($this->overrides, $this->proxyPosture?->overrides() ?? []);

        if ($overrides !== []) {
            $paths[] = $temporary[] = $this->write($this->expand($overrides), $directory);
        }

        return [$paths, $temporary];
    }

    /**
     * Delete the files `materialize()` created.
     *
     * @param array<int, string> $temporary
     *   The second element it returned.
     */
    public function discard(array $temporary): void
    {
        foreach ($temporary as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    /**
     * Turn PropertyAccess bracket paths back into the nested array they
     * address.
     *
     * `['[global][mode]' => 'exception']` becomes
     * `['global' => ['mode' => 'exception']]`.
     *
     * @param array<string, mixed> $overrides
     *   Bracket paths.
     *
     * @return array<string, mixed>
     *   The same values, nested.
     */
    private function expand(array $overrides): array
    {
        $expanded = [];

        foreach ($overrides as $path => $value) {
            preg_match_all('/\[([^\[\]]*)\]/', $path, $matches);

            // Anything that is not wholly bracket segments is left out
            // rather than guessed at. PropertyAccess would reject it at
            // runtime too, and a half-parsed path would put the value
            // somewhere it does not belong — which is worse in a file whose
            // whole job is to reproduce the real configuration.
            if ($matches[1] === [] || implode('', $matches[0]) !== $path) {
                continue;
            }

            $expanded = $this->nest($expanded, $matches[1], $value);
        }

        return $expanded;
    }

    /**
     * Set one value at a path of keys, creating the levels above it.
     *
     * Recursive rather than a reference walk. The reference version was
     * shorter and could not be checked: `$cursor = &$target[$segment]` makes
     * every level `mixed` to a static analyser, so a typo in the walk would
     * have been invisible.
     *
     * @param array<string, mixed> $target
     *   What has been built so far.
     * @param non-empty-list<string> $segments
     *   The remaining key path.
     * @param mixed $value
     *   The value to set at the end of it.
     *
     * @return array<string, mixed>
     *   $target with the value set.
     */
    private function nest(array $target, array $segments, mixed $value): array
    {
        $segment = array_shift($segments);

        if ($segments === []) {
            $target[$segment] = $value;

            return $target;
        }

        // A scalar already sitting where a level has to go is replaced, so
        // two overrides where one is a prefix of the other behave the way
        // PropertyAccess does: last write wins.
        /** @var array<string, mixed> $child */
        $child = isset($target[$segment]) && is_array($target[$segment]) ? $target[$segment] : [];

        $target[$segment] = $this->nest($child, $segments, $value);

        return $target;
    }

    /**
     * Write one configuration array to a short-lived file.
     *
     * @param array<string, mixed> $config
     *   The configuration to write.
     * @param string|null $directory
     *   Preferred location, so relative paths inside it keep their meaning.
     *   Falls back to the system temp directory when it is absent or not
     *   writable, which is the ordinary case on a read-only deployment.
     *
     * @return string
     *   The path written.
     *
     * @throws \RuntimeException
     *   When no file could be created anywhere. Failing loudly beats running
     *   the script against a partial configuration and reporting on it as
     *   though it were the whole one.
     */
    private function write(array $config, ?string $directory): string
    {
        $target = $directory !== null && is_dir($directory) && is_writable($directory)
            ? $directory
            : sys_get_temp_dir();

        // tempnam() creates the file 0600, which is the point: these can
        // carry a resolved `challenge.secret`.
        $path = tempnam($target, 'kanopi-firewall-effective-');

        // @codeCoverageIgnoreStart
        // Not reachable from a test, and kept anyway. `tempnam()` already
        // falls back to the system temp directory when the directory it is
        // given is missing or unwritable, so reaching FALSE means even that
        // failed — a full or read-only /tmp. There is no way to arrange that
        // from inside the suite without breaking the machine running it, and
        // the alternative to this guard is passing FALSE to
        // `file_put_contents()` and letting the script read a file called
        // "".
        if ($path === false) {
            throw new \RuntimeException(sprintf(
                'Could not write the effective firewall configuration to %s.',
                $target
            ));
        }

        // @codeCoverageIgnoreEnd

        file_put_contents($path, Yaml::dump($config, 8));

        return $path;
    }
}
