<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Http;

/**
 * The `challenge:` block of the merged library configuration, as the bundle
 * needs it to render an interstitial and mint a pass cookie.
 *
 * A read-only carrier so the resolver's YAML work happens once and the
 * renderer takes a typed value rather than digging through a nested array
 * with `?? ''` at every level.
 */
final class ChallengeSettings
{
    /**
     * @param string $secret
     *   `challenge.secret`. Empty when no challenge plugins are configured.
     * @param string $provider
     *   `challenge.provider` — the default, used for any rule that names none.
     * @param string $path
     *   `challenge.path`, where the interstitial POSTs.
     * @param string $cookieName
     *   `challenge.cookie_name`. Empty disables cookie delivery.
     * @param string $headerName
     *   `challenge.header_name`. Empty disables the localStorage/XHR path.
     * @param string $audience
     *   `challenge.audience`, defaulted to the provider name by the library.
     * @param array<string, mixed> $providerOptions
     *   `challenge.provider_options`, in either the flat or per-name shape.
     */
    public function __construct(
        public readonly string $secret,
        public readonly string $provider,
        public readonly string $path,
        public readonly string $cookieName,
        public readonly string $headerName,
        public readonly string $audience,
        public readonly array $providerOptions
    ) {
    }
}
