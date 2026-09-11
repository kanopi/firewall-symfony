<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit;

use Kanopi\FirewallBundle\DependencyInjection\KanopiFirewallExtension;
use Kanopi\FirewallBundle\KanopiFirewallBundle;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(KanopiFirewallBundle::class)]
final class KanopiFirewallBundleTest extends TestCase
{
    public function testItSuppliesItsOwnExtension(): void
    {
        $bundle = new KanopiFirewallBundle();

        self::assertInstanceOf(KanopiFirewallExtension::class, $bundle->getContainerExtension());
    }

    public function testTheExtensionIsBuiltOnce(): void
    {
        $bundle = new KanopiFirewallBundle();

        self::assertSame($bundle->getContainerExtension(), $bundle->getContainerExtension());
    }

    public function testTheTemplateNamespaceIsUnambiguous(): void
    {
        // `@KanopiFirewall/...`, not `@Firewall/...`: SecurityBundle's
        // firewalls are a different thing entirely.
        self::assertSame('KanopiFirewallBundle', (new KanopiFirewallBundle())->getName());
    }
}
