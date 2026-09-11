<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

/**
 * Turns `kanopi_firewall` configuration into the two arrays
 * `Firewall::create()` takes, plus the services around them.
 *
 * The translation is the interesting part, and it is one-way on purpose:
 * everything the bundle decides is written into the library's `overrides`,
 * which are applied last and beat anything in the YAML. That is how a setting
 * ends up with exactly one home even though there are two config formats in
 * play.
 *
 * @phpstan-import-type BundleConfig from Configuration
 * @phpstan-import-type CookieOptions from Configuration
 */
final class KanopiFirewallExtension extends Extension implements PrependExtensionInterface
{
    /**
     * Parameter holding the merged config inputs for `Firewall::create()`.
     */
    public const PARAM_CONFIGS = 'kanopi_firewall.library_configs';

    /**
     * Parameter holding the PropertyAccess overrides for `Firewall::create()`.
     */
    public const PARAM_OVERRIDES = 'kanopi_firewall.library_overrides';

    /**
     * Parameter holding the configured `behind_proxy` posture.
     *
     * Passed to `ProxyPosture`, which resolves `auto` at runtime — see the
     * note there for why it cannot be resolved while the container is
     * built.
     */
    public const PARAM_BEHIND_PROXY = 'kanopi_firewall.behind_proxy';

    /**
     * Library modes, keyed by the bundle mode that selects them.
     *
     * `block` is absent, and that is the point — see
     * FirewallRequestListener.
     */
    private const LIBRARY_MODES = [
        'enforce' => 'exception',
        'observe' => 'log',
        // `disabled` never reaches evaluate(), so the mode it would run in is
        // moot; `exception` keeps the firewall constructible for the console
        // commands and the profiler without any chance of an exit().
        'disabled' => 'exception',
    ];

    /**
     * {@inheritdoc}
     */
    public function getAlias(): string
    {
        return Configuration::ROOT;
    }

    /**
     * {@inheritdoc}
     *
     * @param array<int, array<string, mixed>> $config
     *   Raw, unprocessed configuration arrays.
     */
    public function getConfiguration(array $config, ContainerBuilder $container): Configuration
    {
        return new Configuration();
    }

    /**
     * Register the Monolog channel the library will log to.
     *
     * Prepending rather than documenting a copy-paste: a channel that is not
     * declared silently falls back to the default handler stack, so an
     * operator who set up a dedicated firewall log would get nothing in it
     * and no error saying why.
     *
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container): void
    {
        /** @var array<string, string> $bundles */
        $bundles = $container->getParameter('kernel.bundles');

        if (!array_key_exists('MonologBundle', $bundles)) {
            return;
        }

        /** @var array<int, array<string, mixed>> $configs */
        $configs = $container->getExtensionConfig($this->getAlias());
        /** @var array{logging: array{mode: string, channel: string}} $processed */
        $processed = (new Processor())->process((new Configuration())->getConfigTreeBuilder()->buildTree(), $configs);

        if ($processed['logging']['mode'] === 'off') {
            return;
        }

        $container->prependExtensionConfig('monolog', ['channels' => [$processed['logging']['channel']]]);
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        // `processConfiguration()` is declared as returning a bare `array`,
        // so the shape the tree above guarantees has to be restated for
        // static analysis. It is written once, here, rather than re-asserted
        // at each of the twenty reads below.
        /** @var BundleConfig $config */
        $config = $this->processConfiguration(new Configuration(), $configs);

        $container->setParameter(self::PARAM_CONFIGS, $this->libraryConfigs($config));
        $container->setParameter(self::PARAM_OVERRIDES, $this->libraryOverrides($config));
        $container->setParameter(self::PARAM_BEHIND_PROXY, $config['behind_proxy']);

        $container->setParameter('kanopi_firewall.mode', $config['mode']);
        $container->setParameter('kanopi_firewall.blocked_response', $config['blocked_response']);
        $container->setParameter('kanopi_firewall.on_startup_failure', $config['on_startup_failure']);
        $container->setParameter('kanopi_firewall.listener.priority', $config['listener']['priority']);
        $container->setParameter('kanopi_firewall.listener.only_main_requests', $config['listener']['only_main_requests']);
        $container->setParameter('kanopi_firewall.challenge.path', $config['challenge']['path']);
        $container->setParameter('kanopi_firewall.challenge.cookie', $config['challenge']['cookie']);
        $container->setParameter('kanopi_firewall.profiler.collect_health', $config['profiler']['collect_health']);
        $container->setParameter('kanopi_firewall.logging.mode', $this->loggingMode($config, $container));
        $container->setParameter('kanopi_firewall.logging.channel', $config['logging']['channel']);
        $container->setParameter('kanopi_firewall.commands.bin_dir', $this->binDir($config, $container));
        $container->setParameter('kanopi_firewall.commands.timeout', $config['commands']['timeout']);

        $loader = new PhpFileLoader($container, new FileLocator(dirname(__DIR__) . '/Resources/config'));
        $loader->load('services.php');

        if (!$config['commands']['enabled']) {
            $this->removeTagged($container, 'console.command');
        }

        if (!$this->profilerEnabled($config, $container)) {
            $this->removeTagged($container, 'data_collector');
        }
    }

    /**
     * The config inputs, in merge order.
     *
     * File paths first, then the inline `settings` array, because a bundle
     * config written in `config/packages/kanopi_firewall.yaml` is the more
     * specific statement — it is the file an environment override lands in.
     *
     * @param BundleConfig $config
     *   Processed bundle configuration.
     *
     * @return array<int, string|array<string, mixed>>
     *   Ready for `Firewall::create()`'s first argument.
     */
    private function libraryConfigs(array $config): array
    {
        /** @var array<int, string|array<string, mixed>> $inputs */
        $inputs = array_values($config['config_files']);

        if ($config['settings'] !== []) {
            $inputs[] = $config['settings'];
        }

        return $inputs;
    }

    /**
     * The PropertyAccess overrides, applied after every config input.
     *
     * @param BundleConfig $config
     *   Processed bundle configuration.
     *
     * @return array<string, mixed>
     *   Ready for `Firewall::create()`'s second argument.
     *
     * @throws InvalidArgumentException
     *   When the user tries to set the mode by hand. Silently discarding it
     *   would be worse: `[global][mode]: block` looks like it worked, and
     *   the failure it describes — `exit()` inside a kernel — is one nobody
     *   would connect back to a config key that appeared to be honoured.
     */
    private function libraryOverrides(array $config): array
    {
        $overrides = $config['overrides'];

        if (array_key_exists('[global][mode]', $overrides)) {
            throw new InvalidArgumentException(sprintf(
                '"[global][mode]" cannot be set in kanopi_firewall.overrides; use kanopi_firewall.mode '
                . '(enforce, observe or disabled) instead. The bundle owns this key because the library\'s '
                . '"block" mode calls exit(), which inside a Symfony kernel skips kernel.terminate and, '
                . 'under a worker runtime, takes the worker with it. Requested: %s.',
                var_export($overrides['[global][mode]'], true)
            ));
        }

        $challenge = $config['challenge'];

        // Always written, never conditional: the listener and the response
        // factory hold these three as plain strings, and the whole reason
        // that is safe is that the library cannot be reading different ones.
        $overrides['[global][mode]'] = self::LIBRARY_MODES[$config['mode']];
        $overrides['[challenge][path]'] = $challenge['path'];
        $overrides['[challenge][cookie_name]'] = $challenge['cookie_name'];
        $overrides['[challenge][header_name]'] = $challenge['header_name'];

        // Written only when set, so a `firewall.yml` that already carries a
        // secret keeps working without repeating it in bundle config.
        foreach (['secret', 'provider', 'audience'] as $key) {
            if ($challenge[$key] !== null) {
                $overrides[sprintf('[challenge][%s]', $key)] = $challenge[$key];
            }
        }

        if ($challenge['provider_options'] !== []) {
            $overrides['[challenge][provider_options]'] = $challenge['provider_options'];
        }

        return $overrides;
    }

    /**
     * Whether the profiler panel is wanted.
     *
     * @param BundleConfig $config
     *   Processed bundle configuration.
     */
    private function profilerEnabled(array $config, ContainerBuilder $container): bool
    {
        if (is_bool($config['profiler']['enabled'])) {
            return $config['profiler']['enabled'];
        }

        return (bool) $container->getParameter('kernel.debug');
    }

    /**
     * The effective logging mode.
     *
     * Downgraded to `off` when MonologBundle is absent, because there is then
     * no `monolog.logger.<channel>` service to inject and the alternative is
     * a container that will not compile.
     *
     * @param BundleConfig $config
     *   Processed bundle configuration.
     */
    private function loggingMode(array $config, ContainerBuilder $container): string
    {
        /** @var array<string, string> $bundles */
        $bundles = $container->getParameter('kernel.bundles');

        return array_key_exists('MonologBundle', $bundles) ? $config['logging']['mode'] : 'off';
    }

    /**
     * Where the library's `bin/` scripts are.
     *
     * @param BundleConfig $config
     *   Processed bundle configuration.
     */
    private function binDir(array $config, ContainerBuilder $container): string
    {
        if (is_string($config['commands']['bin_dir'])) {
            return $config['commands']['bin_dir'];
        }

        // Composer's bin-dir is configurable, but a bundle cannot read the
        // application's composer.json at container build time without
        // guessing at its location too. `vendor/bin` is the default and the
        // overwhelming majority; anyone who moved it sets `bin_dir`.
        /** @var string $projectDir */
        $projectDir = $container->getParameter('kernel.project_dir');

        return $projectDir . '/vendor/bin';
    }

    /**
     * Drop every service carrying a tag.
     *
     * Removing beats an `enabled` flag threaded through each service: a
     * command that is not registered cannot appear in `bin/console list`,
     * and a data collector that is not registered costs nothing per request.
     */
    private function removeTagged(ContainerBuilder $container, string $tag): void
    {
        foreach (array_keys($container->findTaggedServiceIds($tag)) as $id) {
            $container->removeDefinition($id);
        }
    }
}
