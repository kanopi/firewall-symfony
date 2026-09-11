<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\CacheWarmer;

use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use Symfony\Component\HttpKernel\CacheWarmer\CacheWarmerInterface;

/**
 * Moves the one unsupported challenge wiring from "a visitor discovers it"
 * to "the deploy stops".
 *
 * `ChallengeConfigResolver` refuses a configuration whose rules name their
 * own challenge providers, because the bundle cannot sign the field that
 * makes such a solution verifiable and the visitor would be locked out with
 * nothing in the logs saying so. Left to the resolver alone, that refusal
 * would first fire on the first request that trips a challenge rule — which
 * could be weeks after the deploy that introduced it.
 *
 * `cache:clear` runs on every deploy, so this is where the check belongs.
 *
 * It warms nothing, which is a slight abuse of the interface. The
 * alternatives were a compiler pass (cannot: the config is YAML on disk that
 * the container build has no business reading, and env placeholders in it
 * are not resolved yet) and a `kanopi:firewall:doctor` check (cannot: that
 * is the upstream script's, and nothing framework-specific goes back into
 * the library). A warmer runs at exactly the right moment with the
 * container already built, and `isOptional()` false is the interface's own
 * way of saying "this one is not a nicety".
 */
final class ChallengeConfigWarmer implements CacheWarmerInterface
{
    public function __construct(private readonly ChallengeConfigResolver $challengeConfigResolver)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function isOptional(): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     *
     * @return array<int, string>
     *   Always empty: no class is preloaded by this.
     *
     * @throws \Kanopi\Firewall\Exception\ConfigurationException
     *   When a challenge rule names its own provider. Failing `cache:clear`
     *   fails the deploy, which is the intent.
     */
    public function warmUp(string $cacheDir, ?string $buildDir = null): array
    {
        $this->challengeConfigResolver->resolve();

        return [];
    }
}
