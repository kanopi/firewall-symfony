<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

use Kanopi\Firewall\Storage\InMemoryStorage;

/**
 * A backend that answers questions and will not write.
 *
 * The real shape of this is a Redis replica accepting reads while refusing
 * writes, or a database user without INSERT on the block table. Both report
 * a clean connection and then quietly fail to record a block, which is the
 * one outcome `kanopi:firewall:block` must not report as success.
 */
final class RefusingStorage extends InMemoryStorage
{
    /**
     * {@inheritdoc}
     *
     * @param array<array-key, mixed> $value
     *   The record, as the interface leaves it untyped.
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        return false;
    }
}
