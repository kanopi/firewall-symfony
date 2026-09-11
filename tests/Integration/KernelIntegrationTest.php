<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Integration;

use Kanopi\FirewallBundle\Tests\Fixtures\MathChallengeSolver;
use Kanopi\FirewallBundle\Tests\Fixtures\TestKernel;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * The bundle in a real kernel, handling real requests.
 *
 * These are the tests that would catch a regression a unit test cannot see:
 * a listener priority that lets the router claim the challenge path, a
 * compiler pass that stopped running, a service argument that no longer
 * resolves.
 */
#[CoversNothing]
final class KernelIntegrationTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../Fixtures/config/';

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        (new Filesystem())->remove(sys_get_temp_dir() . '/kanopi-firewall-bundle-tests');
    }

    public function testABlockedRequestNeverReachesTheApplication(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'block.yml']]);

        $response = $kernel->handle($this->request('/', '203.0.113.5'));

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('Blocked: 203.0.113.5', $response->getContent());
        self::assertStringNotContainsString('application reached', (string) $response->getContent());
    }

    public function testABlockedResponseIsPlainTextAndUnsniffable(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'block.yml']]);

        $response = $kernel->handle($this->request('/', '203.0.113.5'));

        // The banning message is a template over request data, so the two
        // headers that stop it rendering as markup are part of the contract.
        self::assertSame('text/plain; charset=utf-8', $response->headers->get('Content-Type'));
        self::assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
        self::assertSame('no-store, private', $response->headers->get('Cache-Control'));
    }

    public function testAnUnmatchedRequestReachesTheApplication(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'block.yml']]);

        $response = $kernel->handle($this->request('/', '198.51.100.1'));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application reached', $response->getContent());
    }

    public function testTheChallengePathIsReachedBeforeTheRouterCanClaimIt(): void
    {
        // `/gated` is a real route in the test kernel, so a listener running
        // after RouterListener would never see this request as a challenge —
        // it would be dispatched to the controller instead.
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'challenge.yml']]);

        $response = $kernel->handle($this->request('/gated', '198.51.100.1'));

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('/_firewall/challenge', (string) $response->getContent());
        self::assertStringNotContainsString('application reached', (string) $response->getContent());
        // Symfony's ResponseHeaderBag normalises `no-store` by adding
        // `private`; what matters is that nothing caches the interstitial.
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function testASolvedChallengeSetsThePassCookieAndRedirects(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'challenge.yml']]);

        // Render the interstitial first: the math provider signs the answer
        // into the page, so the solution has to come from a real challenge.
        $interstitial = (string) $kernel->handle($this->request('/gated', '198.51.100.1'))->getContent();
        $solution = MathChallengeSolver::solve($interstitial);

        $submission = Request::create('/_firewall/challenge', 'POST', $solution);
        $submission->server->set('REMOTE_ADDR', '198.51.100.1');

        $response = $kernel->handle($submission);

        self::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode());
        self::assertSame('/gated', $response->headers->get('Location'));

        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies);
        self::assertSame('fw_challenge_pass', $cookies[0]->getName());
        self::assertTrue($cookies[0]->isHttpOnly());
        self::assertTrue($cookies[0]->isSecure());
        self::assertSame('strict', $cookies[0]->getSameSite());
        // The rule declares default_expiration_time: 120, and the library
        // carries that onto the token — so the cookie has to agree.
        self::assertEqualsWithDelta(time() + 120, $cookies[0]->getExpiresTime(), 5.0);
    }

    public function testThePassTokenLetsTheVisitorThrough(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'challenge.yml']]);

        $interstitial = (string) $kernel->handle($this->request('/gated', '198.51.100.1'))->getContent();
        $submission = Request::create('/_firewall/challenge', 'POST', MathChallengeSolver::solve($interstitial));
        $submission->server->set('REMOTE_ADDR', '198.51.100.1');
        $cookie = $kernel->handle($submission)->headers->getCookies()[0];

        $followUp = $this->request('/gated', '198.51.100.1');
        $followUp->cookies->set($cookie->getName(), (string) $cookie->getValue());

        self::assertSame('application reached', $kernel->handle($followUp)->getContent());
    }

    public function testSubRequestsAreNotEvaluatedTwice(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'block.yml']]);

        $response = $kernel->handle($this->request('/', '203.0.113.5'), HttpKernelInterface::SUB_REQUEST);

        self::assertSame('application reached', $response->getContent());
    }

    public function testSubRequestsAreEvaluatedWhenAsked(): void
    {
        $kernel = $this->boot([
            'config_files' => [self::CONFIG . 'block.yml'],
            'listener' => ['only_main_requests' => false],
        ]);

        $response = $kernel->handle($this->request('/', '203.0.113.5'), HttpKernelInterface::SUB_REQUEST);

        self::assertSame(403, $response->getStatusCode());
    }

    public function testObserveModeLetsABlockedRequestThrough(): void
    {
        $kernel = $this->boot([
            'mode' => 'observe',
            'config_files' => [self::CONFIG . 'block.yml'],
        ]);

        $response = $kernel->handle($this->request('/', '203.0.113.5'));

        self::assertSame('application reached', $response->getContent());
    }

    public function testDisabledModeNeverBuildsTheFirewall(): void
    {
        $kernel = $this->boot([
            'mode' => 'disabled',
            // A configuration that throws the moment it is built, so a
            // response proves the firewall was never constructed.
            'config_files' => [self::CONFIG . 'broken-storage.yml'],
        ]);

        self::assertSame('application reached', $kernel->handle($this->request('/'))->getContent());
    }

    public function testTheProfilerPanelReportsTheVerdictAndHealth(): void
    {
        // The collector only runs when the profiler does, so this needs a
        // profiler — not WebProfilerBundle, just FrameworkBundle's.
        $kernel = $this->boot(
            ['config_files' => [self::CONFIG . 'block.yml']],
            ['profiler' => ['enabled' => true, 'collect' => true, 'only_exceptions' => false]],
            false,
            debug: true
        );
        $kernel->handle($this->request('/', '203.0.113.5'));

        /** @var \Kanopi\FirewallBundle\DataCollector\FirewallDataCollector $collector */
        $collector = $this->service($kernel, 'test.kanopi_firewall.data_collector');
        $data = $collector->getData();

        self::assertSame('blocked', $data['verdict']);
        self::assertSame(
            ['name' => 'test-block-ip', 'class' => \Kanopi\Firewall\Plugins\IpAddress::class],
            $data['rule']
        );
        self::assertSame(403, $data['status_code']);
        self::assertSame('exception', $data['mode']);
        self::assertSame([], $data['failed_rules']);
        self::assertSame([], $data['degraded_backends']);
    }

    public function testTheProfilerPanelIsAbsentOutsideDebug(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'allow.yml']]);
        $kernel->boot();

        /** @var \Symfony\Component\DependencyInjection\ContainerInterface $testContainer */
        $testContainer = $kernel->getContainer()->get('test.service_container');

        self::assertFalse($testContainer->has('test.kanopi_firewall.data_collector'));
    }

    public function testFailClosedSurfacesAStartupFailure(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'broken-storage.yml']]);

        $this->expectException(\Kanopi\Firewall\Exception\StorageException::class);

        $kernel->handle($this->request('/'), HttpKernelInterface::MAIN_REQUEST, false);
    }

    public function testFailOpenServesTheRequestUnfiltered(): void
    {
        $kernel = $this->boot([
            'on_startup_failure' => 'fail_open',
            'config_files' => [self::CONFIG . 'broken-storage.yml'],
        ]);

        self::assertSame('application reached', $kernel->handle($this->request('/'))->getContent());
    }

    public function testHttpExceptionModeHandsTheStatusToTheErrorController(): void
    {
        $kernel = $this->boot([
            'blocked_response' => 'http_exception',
            'config_files' => [self::CONFIG . 'block.yml'],
        ]);

        $response = $kernel->handle($this->request('/', '203.0.113.5'));

        // The application's error controller owns the body now; only the
        // status crosses over, which is the whole point of the mode.
        self::assertSame(403, $response->getStatusCode());
    }

    public function testTheListenerRunsBeforeRoutingAndAfterRequestValidation(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'allow.yml']]);
        $kernel->boot();

        /** @var \Symfony\Component\EventDispatcher\EventDispatcherInterface $dispatcher */
        $dispatcher = $this->service($kernel, 'event_dispatcher');
        /** @var \Kanopi\FirewallBundle\EventListener\FirewallRequestListener $listener */
        $listener = $this->service($kernel, 'test.kanopi_firewall.request_listener');

        // Force the lazy listener closures to resolve to their services,
        // or the lookup below compares against a closure and finds nothing.
        $dispatcher->getListeners('kernel.request');
        $priority = $dispatcher->getListenerPriority('kernel.request', [$listener, '__invoke']);

        self::assertSame(250, $priority);
        self::assertGreaterThan(32, $priority, 'must outrank RouterListener or the challenge path is unreachable');
        self::assertLessThan(256, $priority, 'ValidateRequestListener should still reject a malformed Host first');
    }

    #[DataProvider('provideCommandNames')]
    public function testEveryCommandIsRegisteredUnderBothItsNames(string $name): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'allow.yml']]);
        $kernel->boot();

        $application = new \Symfony\Bundle\FrameworkBundle\Console\Application($kernel);

        self::assertTrue($application->has('kanopi:firewall:' . $name), 'the canonical name');
        // `kanopi:firewall:` is 17 characters of prefix, and an incident is
        // not the moment to type it.
        self::assertTrue($application->has('kfw:' . $name), 'the short alias');
    }

    #[DataProvider('provideCommandNames')]
    public function testEveryCommandCanRenderItsOwnHelp(string $name): void
    {
        // `%command.full_name%` in a help string is resolved against the
        // application, so a malformed placeholder throws — and it throws
        // only when somebody asks for help, which no other test does.
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'allow.yml']]);
        $kernel->boot();

        $application = new \Symfony\Bundle\FrameworkBundle\Console\Application($kernel);
        $application->setAutoExit(false);

        $output = new \Symfony\Component\Console\Output\BufferedOutput();
        $status = $application->run(
            new \Symfony\Component\Console\Input\ArrayInput([
                'command' => 'help',
                'command_name' => 'kanopi:firewall:' . $name,
            ]),
            $output
        );

        self::assertSame(0, $status);
        self::assertStringContainsString('kanopi:firewall:' . $name, $output->fetch());
    }

    /**
     * Every command the bundle registers.
     *
     * Listed by hand rather than read off the application, so that a command
     * silently dropped from the service file fails a test instead of
     * shrinking the list it is checked against.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCommandNames(): iterable
    {
        // Wrappers around the library's bin/ scripts.
        yield 'doctor' => ['doctor'];
        yield 'check' => ['check'];
        yield 'blocks' => ['blocks'];
        yield 'rule' => ['rule'];
        yield 'sources' => ['sources'];
        yield 'migrate' => ['migrate'];
        yield 'log-prune' => ['log-prune'];
        yield 'init' => ['init'];

        // Native: there is no script behind any of these.
        yield 'status' => ['status'];
        yield 'health' => ['health'];
        yield 'rules' => ['rules'];
        yield 'config' => ['config'];
        yield 'block' => ['block'];
        yield 'unblock' => ['unblock'];
        yield 'find-reference' => ['find-reference'];
    }

    public function testTheNativeCommandsRunAgainstTheApplicationsOwnConfiguration(): void
    {
        // End to end through the container: the status report reaches the
        // firewall factory, the config snapshot and the block list, and
        // every one of those is built from the bundle's parameters.
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'block.yml']]);
        $kernel->boot();

        $application = new \Symfony\Bundle\FrameworkBundle\Console\Application($kernel);
        $application->setAutoExit(false);

        $output = new \Symfony\Component\Console\Output\BufferedOutput();
        $status = $application->run(
            new \Symfony\Component\Console\Input\ArrayInput([
                'command' => 'kanopi:firewall:status',
                '--format' => 'json',
            ]),
            $output
        );

        $report = json_decode(trim($output->fetch()), true);

        self::assertSame(0, $status);
        self::assertIsArray($report);
        self::assertTrue($report['firewall_started']);
        self::assertSame('exception', $report['library_mode'], 'the mode the bundle forces');
        self::assertSame(1, $report['rules_enabled']);
    }

    public function testCommandsCanBeTurnedOff(): void
    {
        $kernel = $this->boot([
            'config_files' => [self::CONFIG . 'allow.yml'],
            'commands' => ['enabled' => false],
        ]);
        $kernel->boot();

        $application = new \Symfony\Bundle\FrameworkBundle\Console\Application($kernel);

        self::assertFalse($application->has('kanopi:firewall:doctor'));
    }

    public function testTrustedProxiesAreBridgedOntoBehindProxy(): void
    {
        // The kernel applies framework.trusted_proxies during preBoot(), so
        // by the time anything reads the posture the real, env-resolved
        // list is already in HttpFoundation.
        $kernel = $this->boot(
            ['config_files' => [self::CONFIG . 'allow.yml']],
            ['trusted_proxies' => '192.0.2.1', 'trusted_headers' => ['x-forwarded-for']]
        );
        $kernel->boot();

        /** @var \Kanopi\FirewallBundle\Firewall\ProxyPosture $posture */
        $posture = $this->service($kernel, 'test.kanopi_firewall.proxy_posture');

        self::assertSame(['[global][behind_proxy]' => true], $posture->overrides());
    }

    public function testAnUnconfiguredProxyPostureAssertsNothing(): void
    {
        // FrameworkBundle's own default for kernel.trusted_proxies is the
        // unresolved string "%env(default::SYMFONY_TRUSTED_PROXIES)%", which
        // is why this cannot be decided while the container is built: it
        // looks configured and is not.
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        $kernel = $this->boot(['config_files' => [self::CONFIG . 'allow.yml']]);
        $kernel->boot();

        /** @var \Kanopi\FirewallBundle\Firewall\ProxyPosture $posture */
        $posture = $this->service($kernel, 'test.kanopi_firewall.proxy_posture');

        self::assertSame([], $posture->overrides());
    }

    public function testTheMonologChannelIsRegisteredForTheLibrary(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'allow.yml']], [], true);
        $kernel->boot();

        /** @var \Symfony\Component\DependencyInjection\ContainerInterface $testContainer */
        $testContainer = $kernel->getContainer()->get('test.service_container');

        self::assertSame('replace', $kernel->getContainer()->getParameter('kanopi_firewall.logging.mode'));
        self::assertTrue(
            $testContainer->has('monolog.logger.kanopi_firewall'),
            'the prepend() hook has to declare the channel or nothing lands in it'
        );
    }

    public function testCacheWarmupRefusesPerRuleChallengeProviders(): void
    {
        $kernel = $this->boot(['config_files' => [self::CONFIG . 'per-rule-provider.yml']]);

        $this->expectException(\Kanopi\Firewall\Exception\ConfigurationException::class);
        $this->expectExceptionMessageMatches('/gated-by-recaptcha/');

        // Warmers run while the container is being built, so this fires
        // during `cache:clear` on a deploy — which is the entire point of
        // putting the check in one.
        $kernel->boot();
    }

    /**
     * Fetch a service through the test container.
     *
     * `Kernel::getContainer()` is typed to return the framework's
     * `ContainerInterface`, and `test.service_container` is the alias
     * FrameworkBundle exposes so a test can reach services an application
     * has no business fetching by id.
     */
    private function service(TestKernel $kernel, string $id): object
    {
        /** @var \Symfony\Component\DependencyInjection\ContainerInterface $testContainer */
        $testContainer = $kernel->getContainer()->get('test.service_container');
        /** @var object $service */
        $service = $testContainer->get($id);

        return $service;
    }

    /**
     * Boot a kernel with the given configuration.
     *
     * @param array<string, mixed> $bundleConfig
     *   The `kanopi_firewall` block.
     * @param array<string, mixed> $frameworkConfig
     *   Extra `framework` configuration.
     * @param bool $withMonolog
     *   Whether to install MonologBundle.
     */
    private function boot(
        array $bundleConfig,
        array $frameworkConfig = [],
        bool $withMonolog = false,
        bool $debug = false
    ): TestKernel {
        return new TestKernel($bundleConfig, $frameworkConfig, $withMonolog, $debug);
    }

    /**
     * A request from a given address.
     */
    private function request(string $path, string $ip = '198.51.100.1'): Request
    {
        $request = Request::create($path);
        $request->server->set('REMOTE_ADDR', $ip);

        return $request;
    }
}
