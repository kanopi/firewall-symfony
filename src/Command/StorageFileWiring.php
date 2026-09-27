<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

/**
 * Gives a new file-storage configuration a block list that every worker shares.
 *
 * The starter file `firewall-init` writes stores blocks at
 * `%env(default:/tmp/firewall-blocked.data:FIREWALL_STORAGE_FILE)%`, and
 * nothing in a Symfony application defines that variable. So every install
 * ends up in `/tmp`, which is cleared on reboot and on some hosts is private
 * to each process.
 *
 * ## Why three files and not one line in `.env`
 *
 * `.env` is committed, so it cannot hold an absolute path. A relative one
 * does work when the YAML reads it — the library resolves a relative
 * `storage_file` against the directory of the file that declares it — but
 * then the value means `../var/…` from wherever `firewall.yml` happens to
 * live, which a Flex recipe cannot know, and it means nothing at all to a
 * configuration written inline under `kanopi_firewall.settings`, which has
 * no file to be relative to and falls back to the working directory:
 * `public/` for the web server, the project root for `bin/console`, and two
 * block lists. DoctrineBundle's `DATABASE_URL` pattern avoids all of it:
 * `.env` carries `%kernel.project_dir%`, and the container resolves it
 * through `%env(resolve:…)%` in `kanopi_firewall.storage_file`.
 *
 * Those two halves only work together. A `%kernel.project_dir%` value that
 * reaches the library without the bundle option is used verbatim, so this
 * writes both or neither. It also creates the directory, because the library
 * creates the file but not the directory, and a missing one stops the
 * firewall from starting.
 *
 * ## What it will not do
 *
 * Overwrite anything. An existing `FIREWALL_STORAGE_FILE` in `.env` is the
 * operator's answer and is kept, and an existing `storage_file:` in the
 * bundle config is left alone. A bundle config it cannot confidently edit is
 * reported with the line to add, rather than rewritten.
 */
final class StorageFileWiring
{
    /**
     * The variable the starter configuration already reads.
     */
    public const VARIABLE = 'FIREWALL_STORAGE_FILE';

    /**
     * What `.env` gets. Flex's own markers, so a recipe and this command
     * write the same block and each recognizes the other's.
     */
    public const ENV_BLOCK = <<<'ENV'
        ###> kanopi/firewall-symfony ###
        # The firewall's block list. Outside public/, writable by the web user, and
        # the same file for every worker and for bin/console -- which is why it is
        # resolved against the project directory rather than written relative.
        FIREWALL_STORAGE_FILE="%kernel.project_dir%/var/firewall/blocked.data"
        ###< kanopi/firewall-symfony ###
        ENV;

    /**
     * What the bundle configuration gets.
     */
    public const STORAGE_FILE_LINE = "storage_file: '%env(resolve:FIREWALL_STORAGE_FILE)%'";

    /**
     * @param string $projectDir
     *   `%kernel.project_dir%`.
     */
    public function __construct(private readonly string $projectDir)
    {
    }

    /**
     * Wire `.env`, `var/firewall/` and the bundle config.
     *
     * @param string $firewallYml
     *   The file `firewall-init` just wrote, as it was given to the script.
     * @param string $workingDirectory
     *   What a relative `$firewallYml` is relative to.
     *
     * @return array<int, string>
     *   One line per thing done or deliberately not done, for the operator.
     */
    public function apply(string $firewallYml, string $workingDirectory): array
    {
        return [
            $this->wireEnv(),
            $this->createDirectory(),
            $this->wireBundleConfig($this->absolute($firewallYml, $workingDirectory)),
        ];
    }

    /**
     * Add the variable to `.env`, unless it is already there.
     */
    private function wireEnv(): string
    {
        $file = $this->projectDir . '/.env';
        $contents = is_file($file) ? (string) file_get_contents($file) : '';

        if (preg_match('/^\s*(export\s+)?' . self::VARIABLE . '=/m', $contents) === 1) {
            return sprintf('.env already defines %s; left as it is.', self::VARIABLE);
        }

        $separator = $contents === '' || str_ends_with($contents, "\n") ? '' : "\n";
        $gap = $contents === '' ? '' : "\n";
        if (@file_put_contents($file, $contents . $separator . $gap . self::ENV_BLOCK . "\n") === false) {
            return sprintf("Could not write %s. Add this to it:\n%s", $file, self::ENV_BLOCK);
        }

        return sprintf('Added %s to .env.', self::VARIABLE);
    }

    /**
     * Create `var/firewall/`, which the library will not.
     */
    private function createDirectory(): string
    {
        $directory = $this->projectDir . '/var/firewall';

        if (is_dir($directory)) {
            return 'var/firewall/ already exists.';
        }

        if (!@mkdir($directory, 0775, true) && !is_dir($directory)) {
            return sprintf('Could not create %s. Create it, writable by the web user.', $directory);
        }

        return 'Created var/firewall/.';
    }

    /**
     * Point `kanopi_firewall.storage_file` at the variable.
     *
     * @param string $firewallYml
     *   Absolute path of the generated configuration.
     */
    private function wireBundleConfig(string $firewallYml): string
    {
        $file = $this->projectDir . '/config/packages/kanopi_firewall.yaml';

        if (!is_file($file)) {
            if (!is_dir(dirname($file)) && !@mkdir(dirname($file), 0775, true) && !is_dir(dirname($file))) {
                return sprintf('Could not create %s. Add %s under kanopi_firewall:.', $file, self::STORAGE_FILE_LINE);
            }

            $written = @file_put_contents($file, sprintf(
                "kanopi_firewall:\n    config_files:\n        - '%s'\n    %s\n",
                $this->projectRelative($firewallYml),
                self::STORAGE_FILE_LINE
            ));

            if ($written === false) {
                return sprintf('Could not write %s. Add %s under kanopi_firewall:.', $file, self::STORAGE_FILE_LINE);
            }

            return 'Wrote config/packages/kanopi_firewall.yaml, listing the new file and the storage path.';
        }

        $contents = (string) file_get_contents($file);

        if (preg_match('/^\s+storage_file\s*:/m', $contents) === 1) {
            return 'config/packages/kanopi_firewall.yaml already sets storage_file; left as it is.';
        }

        // Only the plain shape: a `kanopi_firewall:` key on a line of its
        // own. Anything cleverer — flow style, an anchor, a `when@` block —
        // is reported rather than guessed at.
        if (preg_match('/^kanopi_firewall:[ \t]*\R(?<indent>[ \t]+)\S/m', $contents, $match, PREG_OFFSET_CAPTURE) !== 1) {
            return sprintf(
                'Add this under kanopi_firewall: in config/packages/kanopi_firewall.yaml: %s',
                self::STORAGE_FILE_LINE
            );
        }

        $indent = $match['indent'][0];
        $offset = $match['indent'][1];
        $written = @file_put_contents(
            $file,
            substr($contents, 0, $offset) . $indent . self::STORAGE_FILE_LINE . "\n" . substr($contents, $offset)
        );

        if ($written === false) {
            return sprintf('Could not write %s. Add %s under kanopi_firewall:.', $file, self::STORAGE_FILE_LINE);
        }

        return 'Added storage_file to config/packages/kanopi_firewall.yaml.';
    }

    /**
     * A path as absolute, against the directory the script ran in.
     */
    private function absolute(string $path, string $workingDirectory): string
    {
        return str_starts_with($path, '/') || preg_match('~^[A-Za-z]:[\\\\/]~', $path) === 1
            ? $path
            : rtrim($workingDirectory, '/\\') . '/' . $path;
    }

    /**
     * A path under the project as `%kernel.project_dir%/…`, so the bundle
     * config is portable; any other path as it is.
     */
    private function projectRelative(string $path): string
    {
        $root = rtrim($this->projectDir, '/\\') . '/';

        return str_starts_with($path, $root) ? '%kernel.project_dir%/' . substr($path, strlen($root)) : $path;
    }
}
