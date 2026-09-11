<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Command;

use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Yaml\Yaml;

/**
 * Renders a command's answer as a table, as JSON, or as YAML.
 *
 * ## Why this exists at all
 *
 * Drush hands every command `--format=table|json|yaml|…` for free, because
 * Consolidation's output formatters sit between the command and the
 * terminal. Symfony Console has no equivalent: a command writes, and what it
 * writes is what arrives. So the read-only commands here would each have
 * grown their own `if ($json)` branch, and they would have disagreed about
 * the shape — which is the thing a script consuming them cannot tolerate.
 *
 * One printer instead, with two shapes and three formats:
 *
 *  - `properties()` for one subject with many fields, which is a two-column
 *    table for a person and a flat object for a script.
 *  - `table()` for many subjects with the same fields, which is a table for
 *    a person and a list of objects for a script.
 *
 * ## Why the machine formats never carry decoration
 *
 * `isMachineReadable()` exists so a command can suppress its prose — the
 * "lift it with…" hint, the warning about in-memory storage — rather than
 * emitting it alongside the JSON. A hint is worth more than it costs to a
 * person and is a parse error to everything else, and a monitoring probe
 * that has to strip lines before decoding is a probe that breaks on the next
 * release that adds one.
 */
final class ResultPrinter
{
    /**
     * A table for a person.
     */
    public const FORMAT_TABLE = 'table';

    /**
     * JSON, pretty-printed. The format a script should ask for.
     */
    public const FORMAT_JSON = 'json';

    /**
     * YAML, which is also the shape the firewall's own configuration takes.
     */
    public const FORMAT_YAML = 'yaml';

    /**
     * Everything `--format` accepts.
     */
    public const FORMATS = [self::FORMAT_TABLE, self::FORMAT_JSON, self::FORMAT_YAML];

    /**
     * @param string $format
     *   One of the FORMAT_* constants.
     * @param SymfonyStyle $symfonyStyle
     *   Where the output goes.
     */
    public function __construct(
        private readonly string $format,
        private readonly SymfonyStyle $symfonyStyle
    ) {
    }

    /**
     * Is something other than a person reading this?
     *
     * TRUE for `json` and `yaml`, so a command can skip the prose that would
     * make its output undecodable.
     */
    public function isMachineReadable(): bool
    {
        return $this->format !== self::FORMAT_TABLE;
    }

    /**
     * One subject, many fields.
     *
     * @param array<string, mixed> $values
     *   Field name to value, in the order they should be shown.
     * @param array{0: string, 1: string} $headers
     *   Column headings for the table form.
     */
    public function properties(array $values, array $headers = ['Item', 'Value']): void
    {
        if ($this->isMachineReadable()) {
            $this->dump($values);

            return;
        }

        $rows = [];

        foreach ($values as $item => $value) {
            $rows[] = [$this->humanize($item), $this->scalarize($value)];
        }

        $this->symfonyStyle->table($headers, $rows);
    }

    /**
     * Many subjects, the same fields.
     *
     * @param array<string, string> $headers
     *   Field key to column heading. The keys select and order the fields, so
     *   a row may carry more than is shown.
     * @param array<int, array<string, mixed>> $rows
     *   The subjects.
     */
    public function table(array $headers, array $rows): void
    {
        if ($this->isMachineReadable()) {
            $this->dump(array_map(
                static fn (array $row): array => array_intersect_key($row, $headers),
                $rows
            ));

            return;
        }

        if ($rows === []) {
            // Said rather than shown as an empty table, which reads as a
            // rendering failure. "Nothing to list" is a complete answer.
            $this->symfonyStyle->writeln(' <fg=gray>Nothing to list.</>');

            return;
        }

        $this->symfonyStyle->table(
            array_values($headers),
            array_map(
                fn (array $row): array => array_map(
                    $this->scalarize(...),
                    array_values(array_replace(array_fill_keys(array_keys($headers), null), array_intersect_key($row, $headers)))
                ),
                $rows
            )
        );
    }

    /**
     * A whole structure, for the formats that can carry one.
     *
     * Used for `kanopi:firewall:config`, whose subject is a nested document
     * rather than a row of fields. In `table` format it prints the YAML,
     * because there is no table that can represent arbitrary nesting and a
     * flattened one would be a worse YAML document than YAML.
     *
     * @param array<array-key, mixed> $data
     *   The structure to print.
     */
    public function dump(array $data): void
    {
        $this->symfonyStyle->writeln(
            $this->format === self::FORMAT_JSON
                ? (string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
                : rtrim(Yaml::dump($data, 8, 2)),
            OutputInterface::OUTPUT_RAW
        );
    }

    /**
     * A field key as a column label.
     *
     * The keys are snake_case because that is what the machine formats
     * should carry — a JSON consumer keying on `"Library version"` is one
     * renamed label away from breaking — and a person should not have to
     * read them that way. So one set of keys, humanized on the way to the
     * table: `library_version` becomes "Library version".
     */
    private function humanize(string $key): string
    {
        return ucfirst(str_replace('_', ' ', $key));
    }

    /**
     * A value as one cell of a table.
     *
     * Booleans become yes/no rather than `1` and the empty string, which is
     * how a `false` renders otherwise — indistinguishable from a missing
     * value in the one place an operator is reading for exactly that
     * difference.
     */
    private function scalarize(mixed $value): string
    {
        return match (true) {
            is_bool($value) => $value ? 'yes' : 'no',
            is_scalar($value) => (string) $value,
            $value === null => '',
            // One per line rather than comma-joined. Symfony's table sizes
            // its columns to the widest cell, so three config paths on one
            // line produced a 400-column table that wrapped in the terminal
            // and was unreadable in a CI log. A cell may hold newlines, and
            // a list of paths or of failure messages is exactly what wants
            // them.
            is_array($value) => implode(PHP_EOL, array_map($this->scalarize(...), $value)),
            default => '(not printable)',
        };
    }
}
