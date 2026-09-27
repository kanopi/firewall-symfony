<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

use Kanopi\Firewall\Storage\BestEffortEnumerationInterface;
use Kanopi\Firewall\Storage\InMemoryStorage;

/**
 * A backend whose index has lost part of itself, and says so.
 *
 * The shape of `MemcachedStorage` on a bad day: it cannot list its keyspace,
 * so it answers range searches from an index of its own, and a shard of that
 * index can go missing while the records it pointed at are still there. Every
 * exact-address read still answers from the record; every enumeration answers
 * truthfully and incompletely.
 *
 * Standing in for the real thing because the real thing needs a Memcached
 * server, and what is under test is not Memcached but what the bundle does
 * with `enumerationGap()` — which is the same question for any backend that
 * implements it.
 *
 * `storage.config`:
 *
 *  - `gap`: what `enumerationGap()` returns. NULL, or absent, for a healthy
 *    index.
 *  - `lost`: addresses still stored, and blocked, that no enumeration finds.
 */
final class GappyStorage extends InMemoryStorage implements BestEffortEnumerationInterface
{
    /**
     * {@inheritdoc}
     */
    public function enumerationGap(): ?string
    {
        $gap = $this->config['gap'] ?? null;

        return is_string($gap) ? $gap : null;
    }

    /**
     * {@inheritdoc}
     *
     * Everything the parent finds, less what the index has lost.
     */
    public function find(string $pattern): array
    {
        return array_diff_key(parent::find($pattern), array_flip($this->lost()));
    }

    /**
     * {@inheritdoc}
     *
     * Deletes only what `find()` can see, which is what an index-driven
     * backend does: a record the index has lost is not a key it can name.
     */
    public function deleteMatching(array $patterns): int
    {
        $deleted = 0;

        foreach ($patterns as $pattern) {
            foreach (array_keys($this->find($pattern)) as $address) {
                $deleted += $this->delete((string) $address) ? 1 : 0;
            }
        }

        return $deleted;
    }

    /**
     * @return array<int, string>
     *   The addresses the index has lost.
     */
    private function lost(): array
    {
        $lost = $this->config['lost'] ?? [];

        return is_array($lost) ? array_values(array_filter($lost, is_string(...))) : [];
    }
}
