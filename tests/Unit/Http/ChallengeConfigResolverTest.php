<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Http;

use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use Kanopi\FirewallBundle\Http\ChallengeSettings;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ChallengeConfigResolver::class)]
#[CoversClass(ChallengeSettings::class)]
final class ChallengeConfigResolverTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    public function testItReadsTheChallengeBlockFromTheYaml(): void
    {
        $settings = (new ChallengeConfigResolver([self::CONFIG . 'challenge.yml'], []))->resolve();

        self::assertSame('test-secret-not-for-production-use', $settings->secret);
        self::assertSame('math', $settings->provider);
        self::assertSame('/_firewall/challenge', $settings->path);
        self::assertSame('fw_challenge_pass', $settings->cookieName);
        self::assertSame('X-Firewall-Challenge', $settings->headerName);
        self::assertSame([], $settings->providerOptions);
    }

    public function testAnEmptyAudienceDefaultsToTheProviderName(): void
    {
        // Mirrors the library, which scopes a token to the provider that
        // issued it. Getting this wrong mints tokens the firewall rejects.
        $settings = (new ChallengeConfigResolver([self::CONFIG . 'challenge.yml'], []))->resolve();

        self::assertSame('math', $settings->audience);
    }

    public function testAnExplicitAudienceIsKept(): void
    {
        $settings = (new ChallengeConfigResolver(
            [self::CONFIG . 'challenge.yml'],
            ['[challenge][audience]' => '  eu-west  ']
        ))->resolve();

        self::assertSame('eu-west', $settings->audience);
    }

    public function testOverridesBeatTheYaml(): void
    {
        $settings = (new ChallengeConfigResolver(
            [self::CONFIG . 'challenge.yml'],
            ['[challenge][cookie_name]' => 'custom_pass', '[challenge][path]' => '/verify']
        ))->resolve();

        self::assertSame('custom_pass', $settings->cookieName);
        self::assertSame('/verify', $settings->path);
    }

    public function testTheLibraryDefaultsApplyWhenNothingDeclaresAChallenge(): void
    {
        $settings = (new ChallengeConfigResolver([self::CONFIG . 'allow.yml'], []))->resolve();

        self::assertSame('', $settings->secret);
        self::assertSame('math', $settings->provider);
        self::assertSame('/_firewall/challenge', $settings->path);
    }

    public function testAKeyWrittenWithNothingAfterItMeansDisabled(): void
    {
        // The library reads these through `?? ''` after its own defaults
        // have been merged underneath, so an explicit null is "off", not
        // "default". Disagreeing would have the bundle set a pass cookie
        // under a name the library never looks for.
        $settings = (new ChallengeConfigResolver(
            [self::CONFIG . 'challenge.yml', ['challenge' => ['cookie_name' => null]]],
            []
        ))->resolve();

        self::assertSame('', $settings->cookieName);
    }

    public function testANonScalarValueFallsBackToDisabled(): void
    {
        $settings = (new ChallengeConfigResolver(
            [self::CONFIG . 'challenge.yml', ['challenge' => ['header_name' => ['not', 'a', 'string']]]],
            []
        ))->resolve();

        self::assertSame('', $settings->headerName);
    }

    public function testProviderOptionsSurviveAndNonArraysDoNot(): void
    {
        $withOptions = (new ChallengeConfigResolver(
            [self::CONFIG . 'challenge.yml', ['challenge' => ['provider_options' => ['widget_src' => '/w.js']]]],
            []
        ))->resolve();
        $withNonsense = (new ChallengeConfigResolver(
            [self::CONFIG . 'challenge.yml', ['challenge' => ['provider_options' => 'nope']]],
            []
        ))->resolve();

        self::assertSame(['widget_src' => '/w.js'], $withOptions->providerOptions);
        self::assertSame([], $withNonsense->providerOptions);
    }

    public function testItResolvesOnce(): void
    {
        $resolver = new ChallengeConfigResolver([self::CONFIG . 'challenge.yml'], []);

        self::assertSame($resolver->resolve(), $resolver->resolve());
    }

    public function testARuleNamingItsOwnProviderIsNoLongerRefused(): void
    {
        // This configuration was a hard refusal until kanopi/firewall
        // 2.26.0: the bundle rendered the interstitial and could not sign
        // the `provider_token` such a rule needs, so the alternative to
        // refusing was a visitor challenged forever. The exception renders
        // itself now, so the resolver has no opinion about it.
        $resolver = new ChallengeConfigResolver([self::CONFIG . 'per-rule-provider.yml'], []);

        $settings = $resolver->resolve();

        self::assertSame('math', $settings->provider, 'still the default for rules that name none');
    }

    public function testMalformedPluginEntriesAreIgnoredRatherThanFatal(): void
    {
        // `plugins:` is hand-edited YAML, and a stray scalar or an empty
        // metadata block is an ordinary mistake. The library skips those
        // too; refusing to start over one would be a worse failure than
        // the one this check exists to prevent.
        $resolver = new ChallengeConfigResolver([[
            'plugins' => [
                'a bare string',
                ['plugin' => 'Kanopi\\Firewall\\Plugins\\Url', 'metadata' => 'not an array'],
                ['plugin' => 'Kanopi\\Firewall\\Plugins\\Url', 'metadata' => ['challenge_provider' => '']],
                ['plugin' => 'Kanopi\\Firewall\\Plugins\\Url'],
            ],
        ]], []);

        self::assertSame('math', $resolver->resolve()->provider);
    }
}
