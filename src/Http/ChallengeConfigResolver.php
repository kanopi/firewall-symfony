<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Http;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\PluginConfigNormalizer;

/**
 * Reads the merged `challenge:` block, and refuses one wiring the bundle
 * cannot serve.
 *
 * ## Why this loads the config a second time
 *
 * In `exception` mode the library throws `ChallengeRequiredException` *before*
 * it renders anything, so the bundle owns the interstitial — and to build one
 * it needs the secret, the provider, the submit path and the cookie name.
 * Those may have been set in the user's own `firewall.yml` rather than in
 * bundle config, and the built `Firewall` does not expose them.
 *
 * The alternative was to require them in `kanopi_firewall.challenge.*` and
 * ignore the YAML. It lost because "point at the firewall.yml you already
 * have" is the main reason to use a bundle at all, and silently ignoring half
 * of that file is a worse surprise than one extra config load.
 *
 * The cost is small and off the hot path. `Config::load()` caches on the file
 * set, so the second call reuses the parse from `Firewall::create()`, and
 * this only runs when a challenge is actually being rendered — which is rare
 * by construction, and already the most expensive response the firewall
 * produces.
 *
 * ## The wiring that is refused
 *
 * A rule may name its own provider with `metadata.challenge_provider`. When
 * one does, the library scopes the pass token to whichever provider actually
 * served the challenge, and the interstitial has to carry a **signed**
 * `provider_token` back so the submission handler verifies against the right
 * one. That signature is `Firewall::signProviderName()` — `protected`, over a
 * `private const` prefix — with no public equivalent.
 *
 * Rendering without the field is not a degraded experience, it is a lockout:
 * the submission is verified by `challenge.provider` instead, the minted
 * token carries that provider's name, the rule that named a different one
 * rejects it, and the visitor is served the same interstitial forever with
 * nothing in the logs calling it an error. So this refuses to start instead,
 * and `KanopiFirewallCacheWarmer` runs the check at `cache:clear` so the
 * refusal lands at deploy rather than on a visitor.
 *
 * Reproducing the signature here — the prefix string is knowable — was the
 * other option. It lost on the project's constraint that nothing
 * framework-specific goes back into the library and, more practically, on
 * what breaks if the library ever changes that private constant: the field
 * would fail its signature check, `resolveSubmissionProvider()` would refuse
 * the submission, and we would be back at the same silent lockout with a
 * green test suite.
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
     *
     * @throws ConfigurationException
     *   When any challenge rule names its own provider.
     */
    public function resolve(): ChallengeSettings
    {
        if ($this->settings instanceof ChallengeSettings) {
            return $this->settings;
        }

        /** @var array<string, mixed> $config */
        $config = Config::load($this->configs, $this->overrides);

        $this->assertNoPerRuleProviders($config);

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
     * Refuse a configuration whose challenge rules name their own providers.
     *
     * @param array<string, mixed> $config
     *   The merged library configuration.
     *
     * @throws ConfigurationException
     *   Naming every rule that does it, so the fix does not need a search.
     */
    private function assertNoPerRuleProviders(array $config): void
    {
        /** @var array<string, mixed> $normalized */
        $normalized = PluginConfigNormalizer::normalize($config);
        $plugins = is_array($normalized['plugins'] ?? null) ? $normalized['plugins'] : [];
        $offenders = [];

        foreach ($plugins as $plugin) {
            if (!is_array($plugin)) {
                continue;
            }

            $metadata = $plugin['metadata'] ?? [];

            // Guarded with its own `continue` rather than folded into the
            // ternary below. Everything here comes out of hand-edited YAML
            // and is `mixed`, and narrowing once, explicitly, is the only
            // shape that reads the same to every PHPStan in the supported
            // range — the clever one-liner was accepted by the current
            // version and rejected by the floor.
            if (!is_array($metadata)) {
                continue;
            }

            $named = $metadata['challenge_provider'] ?? null;

            if (!is_string($named) || $named === '') {
                continue;
            }

            $ruleName = $metadata['name'] ?? null;
            $class = $plugin['plugin'] ?? null;

            $offenders[] = sprintf(
                '%s (metadata.challenge_provider: %s)',
                match (true) {
                    is_string($ruleName) => $ruleName,
                    is_string($class) => $class,
                    default => '?',
                },
                $named
            );
        }

        if ($offenders === []) {
            return;
        }

        throw new ConfigurationException(sprintf(
            'kanopi/firewall-symfony cannot serve per-rule challenge providers, and refusing to start beats '
            . 'locking a visitor out: %s. In `exception` mode the bundle renders the interstitial, and it has '
            . 'no supported way to sign the `provider_token` field that tells the submission handler which '
            . 'provider to verify against — so a solved challenge would be verified by `challenge.provider`, '
            . 'the pass token would carry the wrong provider name, and the rule would challenge again forever. '
            . 'Remove `metadata.challenge_provider` and let `challenge.provider` serve every rule. Tracked '
            . 'upstream as kanopi/firewall#311: there is no public equivalent of '
            . 'Firewall::signProviderName().',
            implode(', ', $offenders)
        ));
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
