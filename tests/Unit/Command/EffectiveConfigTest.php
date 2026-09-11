<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Kanopi\FirewallBundle\Command\EffectiveConfig;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;

#[CoversClass(EffectiveConfig::class)]
final class EffectiveConfigTest extends TestCase
{
    /**
     * A directory standing in for the application's `config/`.
     */
    private string $configDir = '';

    protected function setUp(): void
    {
        $this->configDir = sys_get_temp_dir() . '/kanopi-effective-config-' . bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->configDir);
        touch($this->configDir . '/firewall.yml');
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->configDir);
    }

    public function testRealFilesArePassedThroughUntouched(): void
    {
        $real = $this->configDir . '/firewall.yml';

        [$paths, $temporary] = (new EffectiveConfig([$real], []))->materialize();

        self::assertSame([$real], $paths);
        self::assertSame([], $temporary);
    }

    public function testInlineSettingsBecomeAFileInMergeOrder(): void
    {
        $real = $this->configDir . '/firewall.yml';

        [$paths, $temporary] = (new EffectiveConfig(
            [$real, ['global' => ['banning_status_code' => 429]]],
            []
        ))->materialize();

        self::assertCount(2, $paths);
        self::assertSame($real, $paths[0], 'the real file first, so the library merges as it would at runtime');
        self::assertSame([$paths[1]], $temporary);
        self::assertSame(['global' => ['banning_status_code' => 429]], Yaml::parseFile($paths[1]));
    }

    public function testOverridesAreExpandedAndGoLast(): void
    {
        $real = $this->configDir . '/firewall.yml';

        [$paths] = (new EffectiveConfig([$real], [
            '[global][mode]' => 'exception',
            '[global][behind_proxy]' => false,
            '[challenge][secret]' => 's3cret',
        ]))->materialize();

        self::assertCount(2, $paths);
        self::assertSame([
            'global' => ['mode' => 'exception', 'behind_proxy' => false],
            'challenge' => ['secret' => 's3cret'],
        ], Yaml::parseFile($paths[1]));
    }

    public function testASecretInBundleConfigReachesTheScripts(): void
    {
        // The bug this class exists for: `doctor` reported "the firewall
        // refuses to start … challenge.secret is empty" about an
        // application that starts and serves challenges perfectly well,
        // because the secret was in bundle config rather than the YAML.
        [$paths] = (new EffectiveConfig(
            [$this->configDir . '/firewall.yml'],
            ['[challenge][secret]' => 'from-an-env-var']
        ))->materialize();

        /** @var array{challenge: array{secret: string}} $written */
        $written = Yaml::parseFile($paths[1]);

        self::assertSame('from-an-env-var', $written['challenge']['secret']);
    }

    public function testGeneratedFilesLandBesideTheFirstRealConfig(): void
    {
        // Relative paths in the library's YAML resolve against the
        // directory of the file that declared them, so a temp file in /tmp
        // would point the diagnostics at a different storage file.
        [$paths] = (new EffectiveConfig(
            [$this->configDir . '/firewall.yml'],
            ['[global][mode]' => 'exception']
        ))->materialize();

        // realpath on both sides: macOS resolves the temp directory through
        // a /private symlink, which is not what this test is about.
        self::assertSame(realpath($this->configDir), realpath(dirname($paths[1])));
    }

    public function testGeneratedFilesFallBackToTheTempDirectory(): void
    {
        // A read-only deployment is the ordinary case, not an edge one.
        [$paths] = (new EffectiveConfig(
            ['/definitely/not/a/directory/firewall.yml'],
            ['[global][mode]' => 'exception']
        ))->materialize();

        self::assertSame(realpath(sys_get_temp_dir()), realpath(dirname($paths[1])));
    }

    public function testGeneratedFilesAreReadableOnlyByTheirOwner(): void
    {
        [$paths, $temporary] = (new EffectiveConfig(
            [$this->configDir . '/firewall.yml'],
            ['[challenge][secret]' => 's3cret']
        ))->materialize();

        self::assertSame('0600', substr(sprintf('%o', fileperms($paths[1])), -4));
        self::assertNotSame([], $temporary);
    }

    public function testDiscardRemovesEverythingItMade(): void
    {
        $effectiveConfig = new EffectiveConfig(
            [$this->configDir . '/firewall.yml', ['global' => []]],
            ['[global][mode]' => 'exception']
        );

        [, $temporary] = $effectiveConfig->materialize();
        self::assertCount(2, $temporary);

        $effectiveConfig->discard($temporary);

        foreach ($temporary as $path) {
            self::assertFileDoesNotExist($path);
        }
    }

    public function testDiscardToleratesAFileThatIsAlreadyGone(): void
    {
        $effectiveConfig = new EffectiveConfig([$this->configDir . '/firewall.yml'], []);

        $effectiveConfig->discard(['/tmp/kanopi-firewall-never-existed']);

        $this->expectNotToPerformAssertions();
    }

    public function testNothingIsSynthesizedWhenNothingIsConfigured(): void
    {
        // Overrides alone would produce a command that appears to work and
        // reports on a firewall with no rules.
        [$paths, $temporary] = (new EffectiveConfig([], ['[global][mode]' => 'exception']))->materialize();

        self::assertSame([], $paths);
        self::assertSame([], $temporary);
    }

    public function testEditingCommandsSeeOnlyTheRealFiles(): void
    {
        $real = $this->configDir . '/firewall.yml';

        [$paths, $temporary] = (new EffectiveConfig(
            [$real, ['global' => []]],
            ['[global][mode]' => 'exception']
        ))->materialize(false);

        self::assertSame([$real], $paths);
        self::assertSame([], $temporary);
    }

    public function testEditingCommandsGetNothingWhenThereIsNoRealFile(): void
    {
        [$paths, $temporary] = (new EffectiveConfig([['global' => []]], []))->materialize(false);

        self::assertSame([], $paths);
        self::assertSame([], $temporary);
    }

    public function testAMalformedOverridePathIsLeftOutRatherThanGuessedAt(): void
    {
        // PropertyAccess would reject it at runtime too, and a half-parsed
        // path would put the value somewhere it does not belong — in a file
        // whose entire job is to reproduce the real configuration.
        [$paths] = (new EffectiveConfig([$this->configDir . '/firewall.yml'], [
            'global.mode' => 'exception',
            '[global]trailing' => 'nope',
            '' => 'nothing',
            '[global][banning_status_code]' => 429,
        ]))->materialize();

        self::assertSame(['global' => ['banning_status_code' => 429]], Yaml::parseFile($paths[1]));
    }

    public function testTheProxyPostureIsPassedThroughToTheScripts(): void
    {
        // Without this, `kanopi:firewall:doctor` reported "Config asserts
        // behind_proxy: unset" for an application whose bundle config said
        // otherwise — the posture is decided at runtime, so it is not in
        // the overrides parameter the container holds.
        [$paths] = (new EffectiveConfig(
            [$this->configDir . '/firewall.yml'],
            [],
            new ProxyPosture(false)
        ))->materialize();

        self::assertSame(['global' => ['behind_proxy' => false]], Yaml::parseFile($paths[1]));
    }

    public function testAnUnknownProxyPostureContributesNothing(): void
    {
        [$paths, $temporary] = (new EffectiveConfig(
            [$this->configDir . '/firewall.yml'],
            [],
            new ProxyPosture('auto')
        ))->materialize();

        // Nothing asserted, so nothing written — the library keeps warning,
        // which is the right answer while the posture is genuinely unknown.
        self::assertSame([$this->configDir . '/firewall.yml'], $paths);
        self::assertSame([], $temporary);
    }

    public function testAScalarInThePathOfANestedOverrideIsOverwritten(): void
    {
        // Two overrides where one is a prefix of the other. Last write
        // wins, matching PropertyAccess.
        [$paths] = (new EffectiveConfig([$this->configDir . '/firewall.yml'], [
            '[challenge]' => 'scalar',
            '[challenge][secret]' => 's3cret',
        ]))->materialize();

        self::assertSame(['challenge' => ['secret' => 's3cret']], Yaml::parseFile($paths[1]));
    }
}
