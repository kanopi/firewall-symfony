<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\DataCollector;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A rule with a stable class name.
 *
 * A PHPUnit double would work, except that the collector records
 * `$plugin::class` and a double's generated name changes between runs —
 * which would make the assertion untestable rather than merely awkward.
 */
final class StubPlugin implements PluginInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'stub-rule';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'A rule that exists so the collector has something to name.';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return 403;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(?Request $request = null): int
    {
        return 3600;
    }
}
