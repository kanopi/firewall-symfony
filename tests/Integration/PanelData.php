<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Integration;

/**
 * The `collector` variable the panel template reads.
 *
 * A stand-in for `FirewallDataCollector` so a case the collector cannot
 * currently produce — an unreachable Redis backend, a live panic file —
 * can still be put through the template. Constructing those for real would
 * mean a Redis server and a writable panic path, and the template does not
 * care where the array came from.
 */
final class PanelData
{
    /**
     * @param array<string, mixed> $data
     *   What `FirewallDataCollector::getData()` would have returned.
     */
    public function __construct(private readonly array $data)
    {
    }

    /**
     * {@see \Kanopi\FirewallBundle\DataCollector\FirewallDataCollector::getData()}
     *
     * @return array<string, mixed>
     *   Panel data.
     */
    public function getData(): array
    {
        return $this->data;
    }
}
