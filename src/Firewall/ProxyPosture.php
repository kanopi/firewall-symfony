<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Firewall;

use Symfony\Component\HttpFoundation\Request;

/**
 * Answers the library's `global.behind_proxy` question from what Symfony
 * already knows.
 *
 * ## Why the library asks
 *
 * Every rule reads `$request->getClientIp()`, and HttpFoundation only
 * consults `X-Forwarded-For` once `Request::setTrustedProxies()` has been
 * called. Behind a CDN with that unset, every visitor arrives as the CDN's
 * address: allowlists match nobody and a per-IP rate limit counts the whole
 * internet into one bucket. The library cannot see whether a proxy is
 * actually in front of it — that is a deployment fact — so it asks, and
 * warns on every request while the question is open.
 *
 * Asking a Symfony application twice would be the wrong answer to that.
 * `framework.trusted_proxies` already carries it.
 *
 * ## Why this is resolved at runtime and not while the container is built
 *
 * The first version of this was a compiler pass reading the
 * `kernel.trusted_proxies` parameter, on the reasoning that a pass runs
 * after every extension and can therefore see it. It ran, and it was wrong:
 * FrameworkBundle's *default* for that parameter is the literal string
 * `%env(default::SYMFONY_TRUSTED_PROXIES)%`, which is unresolvable at build
 * time and non-empty at a glance. Every application that had never
 * configured a proxy would have been told it had one, silencing the exact
 * warning the setting exists to raise.
 *
 * `Kernel::preBoot()` calls `Request::setTrustedProxies()` while building
 * the container, which is before any `kernel.request` listener runs and
 * therefore before this is ever consulted. So by the time the firewall is
 * built, the resolved list is sitting in HttpFoundation and can simply be
 * read. Nothing is inferred, and the env placeholder resolves itself.
 *
 * ## What `auto` does not conclude
 *
 * A non-empty list means a proxy was named, so `behind_proxy: true` is
 * asserted and the library's warning stops. An empty list concludes
 * **nothing** and asserts nothing. Reading it as "no proxy" and silencing
 * the warning is tempting and is the wrong direction to fail in: "nobody
 * configured proxies" and "there is no proxy" are indistinguishable from
 * here, and only one of them is safe. An operator who knows there is
 * nothing in front of the deployment says so with
 * `kanopi_firewall.behind_proxy: false`, which is the supported way to
 * silence it.
 */
final class ProxyPosture
{
    /**
     * @param bool|string $configured
     *   `kanopi_firewall.behind_proxy`: TRUE or FALSE to assert the fact
     *   directly, or the string `auto` to take it from Symfony.
     */
    public function __construct(private readonly bool|string $configured = 'auto')
    {
    }

    /**
     * The `global.behind_proxy` override, if there is one to make.
     *
     * @return array<string, mixed>
     *   Empty when the posture is genuinely unknown, which leaves the
     *   library's own per-request warning in place.
     */
    public function overrides(): array
    {
        if (is_bool($this->configured)) {
            return ['[global][behind_proxy]' => $this->configured];
        }

        return Request::getTrustedProxies() === [] ? [] : ['[global][behind_proxy]' => true];
    }
}
