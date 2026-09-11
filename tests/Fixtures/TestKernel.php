<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

use Kanopi\FirewallBundle\KanopiFirewallBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\MonologBundle\MonologBundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\BundleInterface;
use Symfony\Component\HttpKernel\Kernel;

/**
 * A real kernel, because the interesting failures are wiring failures.
 *
 * The listener's priority relative to the router, the compiler pass seeing
 * `kernel.trusted_proxies`, the Monolog channel actually existing — none of
 * those can be asserted against a hand-built container, and all of them are
 * the kind of thing that silently stops working.
 */
final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param array<string, mixed> $bundleConfig
     *   The `kanopi_firewall` block.
     * @param array<string, mixed> $frameworkConfig
     *   Extra `framework` configuration, merged over the minimum.
     * @param bool $withMonolog
     *   Whether MonologBundle is installed in this application.
     */
    public function __construct(
        private readonly array $bundleConfig = [],
        private readonly array $frameworkConfig = [],
        private readonly bool $withMonolog = false,
        bool $debug = false
    ) {
        parent::__construct('test', $debug);
    }

    /**
     * {@inheritdoc}
     *
     * @return iterable<BundleInterface>
     */
    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new KanopiFirewallBundle();

        if ($this->withMonolog) {
            yield new MonologBundle();
        }
    }

    /**
     * {@inheritdoc}
     *
     * Keyed on the configuration so two kernels in one test run never share
     * a compiled container — which they would otherwise, and the second
     * would silently assert against the first one's wiring.
     */
    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/kanopi-firewall-bundle-tests/' . $this->fingerprint();
    }

    /**
     * {@inheritdoc}
     */
    public function getLogDir(): string
    {
        return $this->getCacheDir() . '/log';
    }

    /**
     * {@inheritdoc}
     */
    public function getProjectDir(): string
    {
        return dirname(__DIR__, 2);
    }

    /**
     * Load the container configuration.
     */
    protected function configureContainer(
        ContainerConfigurator $containerConfigurator,
        LoaderInterface $loader,
        ContainerBuilder $container
    ): void {
        $containerConfigurator->extension('framework', array_replace([
            'secret' => 'kanopi-firewall-bundle-tests',
            'test' => true,
            'http_method_override' => false,
            'php_errors' => ['log' => false],
            'router' => ['utf8' => true, 'resource' => 'kernel::loadRoutes', 'type' => 'service'],
        ], $this->frameworkConfig));

        if ($this->withMonolog) {
            $containerConfigurator->extension('monolog', [
                'handlers' => ['main' => ['type' => 'test', 'level' => 'debug']],
            ]);
        }

        $containerConfigurator->extension('kanopi_firewall', $this->bundleConfig);

        // FrameworkBundle's fallback logger writes to stderr, which turns a
        // deliberate fail-open critical into noise in the test report. What
        // gets logged is asserted in the unit tests, with a logger the test
        // can read.
        $containerConfigurator->services()->set('logger', \Psr\Log\NullLogger::class);

        // Public aliases so tests can reach services the bundle keeps
        // private. Test-only, and the reason they are here rather than in
        // services.php: an application has no business fetching these by id.
        $containerConfigurator->services()
            ->alias('test.kanopi_firewall.firewall_factory', 'kanopi_firewall.firewall_factory')->public()
            ->alias('test.kanopi_firewall.decision_recorder', 'kanopi_firewall.decision_recorder')->public()
            ->alias('test.kanopi_firewall.challenge_config_resolver', 'kanopi_firewall.challenge_config_resolver')->public()
            ->alias('test.kanopi_firewall.response_factory', 'kanopi_firewall.response_factory')->public()
            ->alias('test.kanopi_firewall.request_listener', 'kanopi_firewall.request_listener')->public()
            ->alias('test.kanopi_firewall.proxy_posture', 'kanopi_firewall.proxy_posture')->public();

        // Only present in debug, which is what testTheProfilerPanelIsAbsentOutsideDebug
        // asserts — so the alias has to be conditional too.
        if ($container->getParameter('kernel.debug') === true) {
            $containerConfigurator->services()
                ->alias('test.kanopi_firewall.data_collector', 'kanopi_firewall.data_collector')->public();
        }
    }

    /**
     * One route, so "the router would have claimed this path" is testable.
     */
    protected function configureRoutes(\Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator $routes): void
    {
        $routes->add('home', '/')->controller([$this, 'homeAction']);
        $routes->add('gated', '/gated')->controller([$this, 'homeAction']);
    }

    /**
     * The application behind the firewall.
     */
    public function homeAction(): \Symfony\Component\HttpFoundation\Response
    {
        return new \Symfony\Component\HttpFoundation\Response('application reached');
    }

    /**
     * A stable digest of everything that changes the compiled container.
     */
    private function fingerprint(): string
    {
        return substr(hash('xxh128', serialize([
            $this->bundleConfig,
            $this->frameworkConfig,
            $this->withMonolog,
            $this->debug,
        ])), 0, 16);
    }
}
