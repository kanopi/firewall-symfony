<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\CacheWarmer;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\FirewallBundle\CacheWarmer\ChallengeConfigWarmer;
use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ChallengeConfigWarmer::class)]
final class ChallengeConfigWarmerTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    public function testItIsNotOptional(): void
    {
        // `cache:clear` runs on every deploy, and this is the only moment
        // the unsupported wiring can be caught before a visitor finds it.
        self::assertFalse($this->warmer('challenge.yml')->isOptional());
    }

    public function testAGoodConfigurationWarmsNothingAndSaysSo(): void
    {
        self::assertSame([], $this->warmer('challenge.yml')->warmUp('/tmp', '/tmp'));
    }

    public function testAMissingConfigFilePassesBecauseTheLibraryLoadsLeniently(): void
    {
        // A file that does not exist contributes no rules, so there are no
        // per-rule providers to refuse. Whether that empty ruleset should
        // itself be fatal is `global.require_config`, not this check.
        self::assertSame([], $this->warmer('does-not-exist.yml')->warmUp('/tmp', '/tmp'));
    }

    public function testItFailsTheDeployOnAPerRuleChallengeProvider(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/gated-by-recaptcha/');

        $this->warmer('per-rule-provider.yml')->warmUp('/tmp', '/tmp');
    }

    /**
     * A warmer over a fixture configuration.
     */
    private function warmer(string $fixture): ChallengeConfigWarmer
    {
        return new ChallengeConfigWarmer(new ChallengeConfigResolver([self::CONFIG . $fixture], []));
    }
}
