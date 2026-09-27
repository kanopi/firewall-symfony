<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Firewall;

/**
 * The overrides as they should reach the library, once the container has
 * resolved them.
 *
 * `challenge.secret`, `provider` and `audience` are written down only when
 * they are set, so a `firewall.yml` that already carries a secret keeps it.
 * The extension can only check that at compile time, and at compile time
 * `'%env(FIREWALL_CHALLENGE_SECRET)%'` is a placeholder, not a value. So an
 * environment that leaves the variable empty — exactly what a committed
 * `.env` does, following Symfony's own `APP_SECRET` — produced an override of
 * `''`. That replaced the YAML's secret with nothing, and every challenge rule
 * failed to start.
 *
 * An empty secret, provider or audience is never a value anybody meant, so
 * it is read as "not set" here, where the value is finally known.
 */
final class LibraryOverrides
{
    /**
     * The keys the extension writes only when bundle config sets them.
     */
    public const CONDITIONAL = ['[challenge][secret]', '[challenge][provider]', '[challenge][audience]'];

    /**
     * Drop a conditional override that resolved to nothing.
     *
     * @param array<string, mixed> $overrides
     *   As the container resolved them.
     *
     * @return array<string, mixed>
     *   Ready for the library.
     */
    public static function resolved(array $overrides): array
    {
        foreach (self::CONDITIONAL as $key) {
            if (array_key_exists($key, $overrides) && in_array($overrides[$key], [null, ''], true)) {
                unset($overrides[$key]);
            }
        }

        return $overrides;
    }
}
