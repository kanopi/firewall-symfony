<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Http;

use Kanopi\Firewall\Utility\Config;

/**
 * Reads the merged `challenge:` block, and refuses one wiring the bundle
 * cannot serve.
 *
 * ## Why this loads the config a second time
 *
 * The pass cookie. When a visitor solves a challenge the bundle sets the
 * cookie that carries the token, and it has to use the name the library will
 * look for — which may have been set in the user's own `firewall.yml` rather
 * than in bundle config, and which the built `Firewall` does not expose.
 *
 * The alternative was to require it in `kanopi_firewall.challenge.*` and
 * ignore the YAML. It lost because "point at the firewall.yml you already
 * have" is the main reason to use a bundle at all, and silently ignoring half
 * of that file is a worse surprise than one extra config load.
 *
 * The cost is small and off the hot path. `Config::load()` caches on the file
 * set, so the second call reuses the parse from `Firewall::create()`, and
 * this only runs when a challenge is actually being solved — which is rare by
 * construction.
 *
 * ## What used to be here
 *
 * Until kanopi/firewall 2.26.0 this class did much more, and refused much
 * more. The bundle rendered the interstitial itself, so it needed the
 * provider, the secret and the submit path from here — and it **refused to
 * start** for any rule carrying `metadata.challenge_provider`, because the
 * signed `provider_token` such a rule needs was produced by a `protected`
 * method over a `private const` prefix on a `final` class. Rendering without
 * it was not a degraded experience but a silent permanent lockout.
 *
 * `ChallengeRequiredException::renderInterstitial()` ended all of that: the
 * exception holds the provider the firewall chose and the context it built.
 * The renderer, the cache warmer that raised the refusal at `cache:clear`,
 * and the refusal itself are gone, and per-rule providers are supported. See
 * kanopi/firewall#311, which was reported from this package.
 */
final class ChallengeConfigResolver
{
    /**
     * Memoized result. One resolve per process, however many challenges.
     */
    private ?ChallengeSettings $settings = null;

    /**
     * @param array<int, string|array<string, mixed>> $configs
     *   The same config inputs handed to `Firewall::create()`.
     * @param array<string, mixed> $overrides
     *   The same overrides.
     */
    public function __construct(
        private readonly array $configs,
        private readonly array $overrides
    ) {
    }

    /**
     * The challenge block, with the library's own defaults applied.
     */
    public function resolve(): ChallengeSettings
    {
        if ($this->settings instanceof ChallengeSettings) {
            return $this->settings;
        }

        /** @var array<string, mixed> $config */
        $config = Config::load($this->configs, $this->overrides);

        /** @var array<string, mixed> $challenge */
        $challenge = isset($config['challenge']) && is_array($config['challenge']) ? $config['challenge'] : [];

        $provider = $this->stringValue($challenge, 'provider', 'math');
        /** @var array<string, mixed> $providerOptions */
        $providerOptions = is_array($challenge['provider_options'] ?? null) ? $challenge['provider_options'] : [];

        // Mirrors the library: an empty audience defaults to the provider
        // name, so a `math` token is not accepted by an `altcha` instance.
        // Getting this wrong would mint tokens the firewall then rejects.
        $audience = trim($this->stringValue($challenge, 'audience', ''));

        return $this->settings = new ChallengeSettings(
            $this->stringValue($challenge, 'secret', ''),
            $provider,
            $this->stringValue($challenge, 'path', '/_firewall/challenge'),
            $this->stringValue($challenge, 'cookie_name', 'fw_challenge_pass'),
            $this->stringValue($challenge, 'header_name', 'X-Firewall-Challenge'),
            $audience === '' ? $provider : $audience,
            $providerOptions
        );
    }

    /**
     * Read a scalar from the challenge block, falling back to the library's
     * own default when it is absent or not a string.
     *
     * @param array<string, mixed> $challenge
     *   The challenge block.
     * @param string $key
     *   Key to read.
     * @param string $default
     *   The library's default for that key.
     */
    private function stringValue(array $challenge, string $key, string $default): string
    {
        // `array_key_exists` and not `??`, so this agrees with the library
        // about a key written with nothing after it. `Firewall` reaches these
        // through `(string) ($challengeConfig[$key] ?? '')` *after*
        // `array_replace` has already put the shipped defaults underneath, so
        // an explicit null there reads as "disabled", not "default". Treating
        // it as the default here would leave the bundle setting a pass cookie
        // under a name the library never looks for.
        $value = array_key_exists($key, $challenge) ? $challenge[$key] : $default;

        return is_scalar($value) ? (string) $value : '';
    }
}
