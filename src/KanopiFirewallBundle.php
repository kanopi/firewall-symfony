<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle;

use Kanopi\FirewallBundle\DependencyInjection\KanopiFirewallExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * kanopi/firewall as a Symfony bundle.
 *
 * Not to be confused with `security.firewalls`, which SecurityBundle has
 * owned since Symfony 2 and which means an authentication zone. This one
 * refuses hostile traffic. Everything the bundle registers is prefixed
 * `kanopi_firewall` so the two are never ambiguous in a config directory, a
 * `debug:container` listing or a stack trace.
 */
final class KanopiFirewallBundle extends Bundle
{
    /**
     * {@inheritdoc}
     *
     * Named explicitly rather than left to Bundle's convention-based lookup,
     * which would search `DependencyInjection/KanopiFirewallExtension` by
     * deriving the name from the bundle class. It finds the right class
     * either way; saying so removes a reflection call from every container
     * build and makes the link greppable.
     */
    public function getContainerExtension(): KanopiFirewallExtension
    {
        if (!$this->extension instanceof KanopiFirewallExtension) {
            $this->extension = new KanopiFirewallExtension();
        }

        return $this->extension;
    }
}
