<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\DependencyInjection;

use Kanopi\FirewallBundle\DependencyInjection\Configuration;
use Kanopi\FirewallBundle\DependencyInjection\KanopiFirewallExtension;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;

#[CoversClass(KanopiFirewallExtension::class)]
#[CoversClass(Configuration::class)]
final class KanopiFirewallExtensionTest extends TestCase
{
    public function testTheAliasIsVendorQualified(): void
    {
        // SecurityBundle already owns `firewall`, and there it means an
        // authentication zone. Sharing the word in one config directory is
        // a trap that springs while somebody is debugging access control.
        self::assertSame('kanopi_firewall', (new KanopiFirewallExtension())->getAlias());
    }

    public function testItSuppliesItsOwnConfiguration(): void
    {
        $extension = new KanopiFirewallExtension();

        self::assertInstanceOf(Configuration::class, $extension->getConfiguration([], new ContainerBuilder()));
    }

    public function testEveryServiceIdIsVendorQualified(): void
    {
        $container = $this->load([]);

        foreach (array_keys($container->getDefinitions()) as $id) {
            if ($id === 'service_container') {
                continue;
            }

            self::assertStringStartsWith('kanopi_firewall.', $id);
        }
    }

    #[DataProvider('provideModes')]
    public function testTheBundleModeSelectsALibraryModeThatCannotExit(string $mode, string $library): void
    {
        $overrides = $this->overrides($this->load(['mode' => $mode]));

        // `block` is unreachable by construction: it is the mode that calls
        // exit(), which inside a kernel skips kernel.terminate and, under a
        // worker runtime, takes the worker with it.
        self::assertSame($library, $overrides['[global][mode]']);
        self::assertNotSame('block', $overrides['[global][mode]']);
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideModes(): iterable
    {
        yield 'enforce' => ['enforce', 'exception'];
        yield 'observe' => ['observe', 'log'];
        yield 'disabled' => ['disabled', 'exception'];
    }

    public function testSettingTheModeByHandIsRefusedRatherThanIgnored(): void
    {
        $this->expectException(InvalidArgumentException::class);
        // Discarding it silently would be worse: `[global][mode]: block`
        // would look honoured, and the failure it causes is one nobody
        // would trace back to a config key.
        $this->expectExceptionMessageMatches('/kanopi_firewall\.mode/');

        $this->load(['overrides' => ['[global][mode]' => 'block']]);
    }

    public function testConfigFilesAndInlineSettingsAreMergedInThatOrder(): void
    {
        $container = $this->load([
            'config_files' => ['/etc/firewall.yml', '/etc/extra.yml'],
            'settings' => ['global' => ['banning_status_code' => 429]],
        ]);

        self::assertSame(
            ['/etc/firewall.yml', '/etc/extra.yml', ['global' => ['banning_status_code' => 429]]],
            $container->getParameter(KanopiFirewallExtension::PARAM_CONFIGS)
        );
    }

    public function testEmptySettingsContributeNothingToTheMerge(): void
    {
        $container = $this->load(['config_files' => ['/etc/firewall.yml']]);

        self::assertSame(['/etc/firewall.yml'], $container->getParameter(KanopiFirewallExtension::PARAM_CONFIGS));
    }

    public function testTheChallengeKeysTheBundleActsOnAreAlwaysWrittenDown(): void
    {
        // The listener and the response factory hold these as plain
        // strings; that is only safe because the library cannot be reading
        // different ones.
        $overrides = $this->overrides($this->load([]));

        self::assertSame('/_firewall/challenge', $overrides['[challenge][path]']);
        self::assertSame('fw_challenge_pass', $overrides['[challenge][cookie_name]']);
        self::assertSame('X-Firewall-Challenge', $overrides['[challenge][header_name]']);
    }

    public function testUnsetChallengeKeysLeaveTheYamlAlone(): void
    {
        // Pointing at an existing firewall.yml is the main reason to use a
        // bundle, so a secret already in that file must not be clobbered.
        $overrides = $this->overrides($this->load([]));

        self::assertArrayNotHasKey('[challenge][secret]', $overrides);
        self::assertArrayNotHasKey('[challenge][provider]', $overrides);
        self::assertArrayNotHasKey('[challenge][audience]', $overrides);
        self::assertArrayNotHasKey('[challenge][provider_options]', $overrides);
    }

    public function testSetChallengeKeysBeatTheYaml(): void
    {
        $overrides = $this->overrides($this->load([
            'challenge' => [
                'secret' => 's3cret',
                'provider' => 'altcha',
                'audience' => 'eu-west',
                'provider_options' => ['widget_src' => '/w.js'],
            ],
        ]));

        self::assertSame('s3cret', $overrides['[challenge][secret]']);
        self::assertSame('altcha', $overrides['[challenge][provider]']);
        self::assertSame('eu-west', $overrides['[challenge][audience]']);
        self::assertSame(['widget_src' => '/w.js'], $overrides['[challenge][provider_options]']);
    }

    public function testTheProxyPostureIsPassedThroughForRuntimeResolution(): void
    {
        self::assertSame('auto', $this->load([])->getParameter(KanopiFirewallExtension::PARAM_BEHIND_PROXY));
        self::assertFalse($this->load(['behind_proxy' => false])->getParameter(KanopiFirewallExtension::PARAM_BEHIND_PROXY));
        self::assertTrue($this->load(['behind_proxy' => true])->getParameter(KanopiFirewallExtension::PARAM_BEHIND_PROXY));
    }

    public function testTheListenerPriorityOutranksTheRouter(): void
    {
        // Below RouterListener's 32 and the challenge path is a 404 before
        // this listener ever sees it, which locks a challenged visitor out
        // permanently.
        self::assertSame(250, $this->load([])->getParameter('kanopi_firewall.listener.priority'));
        self::assertSame(500, $this->load(['listener' => ['priority' => 500]])->getParameter('kanopi_firewall.listener.priority'));
    }

    public function testTheProfilerFollowsDebugByDefault(): void
    {
        self::assertFalse($this->load([], debug: false)->hasDefinition('kanopi_firewall.data_collector'));
        self::assertTrue($this->load([], debug: true)->hasDefinition('kanopi_firewall.data_collector'));
    }

    public function testTheProfilerCanBeForcedEitherWay(): void
    {
        self::assertTrue($this->load(['profiler' => ['enabled' => true]], debug: false)->hasDefinition('kanopi_firewall.data_collector'));
        self::assertFalse($this->load(['profiler' => ['enabled' => false]], debug: true)->hasDefinition('kanopi_firewall.data_collector'));
    }

    public function testCommandsCanBeRemovedEntirely(): void
    {
        $withCommands = $this->load([]);
        $without = $this->load(['commands' => ['enabled' => false]]);

        self::assertTrue($withCommands->hasDefinition('kanopi_firewall.command.doctor'));
        self::assertFalse($without->hasDefinition('kanopi_firewall.command.doctor'));
    }

    public function testTheBinDirectoryDefaultsToComposersAndIsOverridable(): void
    {
        self::assertSame('/app/vendor/bin', $this->load([])->getParameter('kanopi_firewall.commands.bin_dir'));
        self::assertSame(
            '/opt/bin',
            $this->load(['commands' => ['bin_dir' => '/opt/bin']])->getParameter('kanopi_firewall.commands.bin_dir')
        );
    }

    public function testLoggingIsForcedOffWithoutMonologBundle(): void
    {
        // There is no `monolog.logger.<channel>` service to inject, and a
        // container that will not compile is a worse answer than no bridge.
        self::assertSame('off', $this->load([])->getParameter('kanopi_firewall.logging.mode'));
        self::assertSame('replace', $this->load([], withMonolog: true)->getParameter('kanopi_firewall.logging.mode'));
    }

    public function testTheMonologChannelIsPrependedWhenLoggingIsOn(): void
    {
        $container = $this->container(withMonolog: true);
        $container->registerExtension(new StubMonologExtension());
        $container->prependExtensionConfig('kanopi_firewall', ['logging' => ['channel' => 'audit']]);

        (new KanopiFirewallExtension())->prepend($container);

        // A channel that is not declared falls back to the default handler
        // stack, so an operator who set up a dedicated firewall log would
        // get nothing in it and nothing saying why.
        self::assertSame([['channels' => ['audit']]], $container->getExtensionConfig('monolog'));
    }

    public function testNothingIsPrependedWhenLoggingIsOff(): void
    {
        $container = $this->container(withMonolog: true);
        $container->registerExtension(new StubMonologExtension());
        $container->prependExtensionConfig('kanopi_firewall', ['logging' => ['mode' => 'off']]);

        (new KanopiFirewallExtension())->prepend($container);

        self::assertSame([], $container->getExtensionConfig('monolog'));
    }

    public function testNothingIsPrependedWithoutMonologBundle(): void
    {
        $container = $this->container();
        $container->registerExtension(new StubMonologExtension());

        (new KanopiFirewallExtension())->prepend($container);

        self::assertSame([], $container->getExtensionConfig('monolog'));
    }

    public function testAnInvalidModeIsRejectedByTheSchema(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->load(['mode' => 'block']);
    }

    public function testSettingsMustBeAnArray(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/must be an array/');

        $this->load(['settings' => 'firewall.yml']);
    }

    public function testProviderOptionsMustBeAnArray(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/must be an array/');

        $this->load(['challenge' => ['provider_options' => 'nope']]);
    }

    /**
     * Load the extension into a fresh container.
     *
     * @param array<string, mixed> $config
     *   The `kanopi_firewall` block.
     */
    private function load(array $config, bool $debug = false, bool $withMonolog = false): ContainerBuilder
    {
        $container = $this->container($debug, $withMonolog);
        (new KanopiFirewallExtension())->load([$config], $container);

        return $container;
    }

    /**
     * A container with the kernel parameters an extension can rely on.
     */
    private function container(bool $debug = false, bool $withMonolog = false): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.debug', $debug);
        $container->setParameter('kernel.project_dir', '/app');
        $container->setParameter('kernel.bundles', $withMonolog ? ['MonologBundle' => 'M'] : []);

        return $container;
    }

    /**
     * The library overrides the extension produced.
     *
     * @return array<string, mixed>
     *   As `Firewall::create()` would receive them.
     */
    private function overrides(ContainerBuilder $container): array
    {
        /** @var array<string, mixed> $overrides */
        $overrides = $container->getParameter(KanopiFirewallExtension::PARAM_OVERRIDES);

        return $overrides;
    }
}
