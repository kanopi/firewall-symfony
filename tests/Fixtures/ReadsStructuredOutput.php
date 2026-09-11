<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

/**
 * Reads a field out of a command's machine-readable output, with a type.
 *
 * Every `--format=json` assertion starts from `json_decode()`, and a report
 * starts from an `array<string, mixed>`. Indexing either gives `mixed`, so a
 * bare `$report['healthy']` is both unanalysable and a silent pass when the
 * key is misspelled — the assertion compares two nulls and agrees.
 *
 * These walk a path and insist on a type, failing the test with the document
 * in the message when either is wrong. Which makes the failure say "there is
 * no `errors` key" instead of "expected 1, got 0".
 */
trait ReadsStructuredOutput
{
    /**
     * Decode a command's JSON output.
     *
     * @param string $json
     *   What the command printed.
     *
     * @return array<array-key, mixed>
     *   The document.
     */
    private function decode(string $json): array
    {
        $decoded = json_decode(trim($json), true);

        if (!is_array($decoded)) {
            self::fail(sprintf('Not a JSON document: %s', $json));
        }

        return $decoded;
    }

    /**
     * A string at a path.
     *
     * @param array<array-key, mixed> $data
     *   The document.
     * @param int|string ...$keys
     *   The path to walk.
     */
    private function text(array $data, int|string ...$keys): string
    {
        $value = $this->at($data, ...$keys);

        if (!is_string($value)) {
            self::fail(sprintf('%s is not a string: %s', $this->path($keys), get_debug_type($value)));
        }

        return $value;
    }

    /**
     * A list at a path.
     *
     * @param array<array-key, mixed> $data
     *   The document.
     * @param int|string ...$keys
     *   The path to walk.
     *
     * @return array<array-key, mixed>
     *   Whatever was there.
     */
    private function listAt(array $data, int|string ...$keys): array
    {
        $value = $this->at($data, ...$keys);

        if (!is_array($value)) {
            self::fail(sprintf('%s is not a list: %s', $this->path($keys), get_debug_type($value)));
        }

        return $value;
    }

    /**
     * Whatever is at a path, having checked that something is.
     *
     * @param array<array-key, mixed> $data
     *   The document.
     * @param int|string ...$keys
     *   The path to walk.
     */
    private function at(array $data, int|string ...$keys): mixed
    {
        $value = $data;

        foreach ($keys as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                self::fail(sprintf(
                    'No %s in %s',
                    $this->path($keys),
                    (string) json_encode($data, JSON_UNESCAPED_SLASHES)
                ));
            }

            $value = $value[$key];
        }

        return $value;
    }

    /**
     * A path, for a message.
     *
     * @param array<array-key, int|string> $keys
     *   The path that was walked.
     */
    private function path(array $keys): string
    {
        return implode('.', array_map(strval(...), $keys));
    }
}
