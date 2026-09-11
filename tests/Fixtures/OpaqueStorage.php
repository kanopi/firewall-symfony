<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

use Kanopi\Firewall\Storage\AbstractStorageBase;

/**
 * A backend that cannot be enumerated.
 *
 * Storage only has to answer "is this one key blocked". Listing, searching
 * by pattern and searching by reference all need
 * `QueryableStorageInterface`, which a custom backend — a cache with no
 * key-space scan, an HTTP service — has no way to provide.
 *
 * It matters because the failure is silent: a non-queryable backend returns
 * an empty list from every read, so a lift reports "0 removed" and a
 * reference lookup reports "not found", and both read as answers rather
 * than as an inability to answer. That is what BlockManager refuses to do,
 * and this is what it refuses with.
 */
final class OpaqueStorage extends AbstractStorageBase
{
    /**
     * Records, keyed the way the real backends key them.
     *
     * @var array<string, array<string, mixed>>
     */
    private array $records = [];

    /**
     * {@inheritdoc}
     *
     * @param array<array-key, mixed> $value
     *   The record, as the interface leaves it untyped.
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        $this->records[$key] = ['value' => $value, 'expire' => $expire];

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * Refuses when `storage.config.refuse_deletes` is set, which is the
     * shape of a read-only replica or a database user without DELETE: the
     * key is still there afterwards, and a command that reported the lift as
     * done would be telling an operator a customer is back in when they are
     * not.
     */
    public function delete(string $key): bool
    {
        if (($this->config['refuse_deletes'] ?? false) === true) {
            return false;
        }

        unset($this->records[$key]);

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->records[$key] ?? $default;
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        $this->records = [];

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function exists(string $key): bool
    {
        return array_key_exists($key, $this->records);
    }

    /**
     * {@inheritdoc}
     */
    public function expire(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function recordOffense(string $key): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        return 0;
    }
}
