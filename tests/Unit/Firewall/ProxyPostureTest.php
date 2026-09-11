<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(ProxyPosture::class)]
final class ProxyPostureTest extends TestCase
{
    /**
     * `Request::setTrustedProxies()` is static process state, so it has to
     * be put back or the next test inherits it.
     *
     * @var array<array-key, string>
     */
    private array $originalProxies = [];

    /**
     * The header set that was in force before the test.
     *
     * @var int<0, 63>
     */
    private int $originalHeaders = 0;

    protected function setUp(): void
    {
        $this->originalProxies = Request::getTrustedProxies();

        // `getTrustedHeaderSet()` is typed `int` and `setTrustedProxies()`
        // wants the bitmask range back, so the round trip needs narrowing.
        $headers = Request::getTrustedHeaderSet();
        $this->originalHeaders = $headers >= 0 && $headers <= 63 ? $headers : Request::HEADER_X_FORWARDED_FOR;
    }

    protected function tearDown(): void
    {
        Request::setTrustedProxies($this->originalProxies, $this->originalHeaders);
    }

    public function testAnExplicitTrueIsAssertedWhateverSymfonySays(): void
    {
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        self::assertSame(['[global][behind_proxy]' => true], (new ProxyPosture(true))->overrides());
    }

    public function testAnExplicitFalseIsAssertedWhateverSymfonySays(): void
    {
        Request::setTrustedProxies(['192.0.2.1'], Request::HEADER_X_FORWARDED_FOR);

        self::assertSame(['[global][behind_proxy]' => false], (new ProxyPosture(false))->overrides());
    }

    public function testAutoAssertsAProxyWhenTheKernelHasAppliedOne(): void
    {
        Request::setTrustedProxies(['192.0.2.1'], Request::HEADER_X_FORWARDED_FOR);

        self::assertSame(['[global][behind_proxy]' => true], (new ProxyPosture())->overrides());
    }

    public function testAutoAssertsNothingWhenNoProxyIsConfigured(): void
    {
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        // Deliberately not `false`. "Nobody configured proxies" and "there
        // is no proxy" are indistinguishable here, and guessing the second
        // would silence the warning that exists to catch the first.
        self::assertSame([], (new ProxyPosture('auto'))->overrides());
    }
}
