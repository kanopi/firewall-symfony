<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Diagnostics;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\FirewallBundle\Diagnostics\IntegrationDoctor;
use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Kanopi\FirewallBundle\Tests\Fixtures\OpaqueStorage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Router;
use Symfony\Component\Routing\RouterInterface;

#[CoversClass(IntegrationDoctor::class)]
final class IntegrationDoctorTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    /**
     * A bin directory that really holds the scripts.
     */
    private const BIN = __DIR__ . '/../../Fixtures/bin';

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        // `checkProxyPosture()` reads what HttpFoundation resolved, which
        // `Kernel::preBoot()` sets globally. A test that asserted one
        // posture would otherwise decide the next one's answer.
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);
    }

    public function testAWellWiredApplicationReportsNoErrors(): void
    {
        $findings = $this->diagnose();

        self::assertSame([], $this->errors($findings));
        self::assertSame('Mode is "enforce"', $findings[0]->title, 'the mode comes first: it invalidates the rest');
    }

    public function testTheModeThatActsOnNothingIsCalledOut(): void
    {
        $disabled = $this->findings($this->diagnose(mode: 'disabled'));

        self::assertSame(Diagnosis::WARNING, $disabled['Mode is "disabled"']->status);
        self::assertStringContainsString('no rule is applied', (string) $disabled['Mode is "disabled"']->detail);
    }

    public function testObserveSaysWhatItDoesAndWhereItDoesNothing(): void
    {
        // The trap is real and invisible: under a CLI-SAPI runtime the
        // library returns early in every mode but `exception`, so observe
        // evaluates nothing there.
        $finding = $this->findings($this->diagnose(mode: 'observe'))['Mode is "observe"'];

        self::assertSame(Diagnosis::WARNING, $finding->status);
        self::assertStringContainsString('RoadRunner', (string) $finding->detail);
    }

    public function testAnApplicationWithNoConfigurationAtAllIsAnError(): void
    {
        // It runs on the library's defaults, which contain no rules, so
        // every request is allowed.
        $finding = $this->findings($this->diagnose(configs: []))['No firewall configuration is declared'];

        self::assertSame(Diagnosis::ERROR, $finding->status);
        self::assertStringContainsString('kanopi:firewall:init', (string) $finding->detail);
    }

    public function testAConfigurationThatDeclaresNoRulesAtAllIsAnError(): void
    {
        // Different from all-parked, and the fix is different: this one
        // needs rules written.
        $configs = [['storage' => ['type' => 'Kanopi\Firewall\Storage\InMemoryStorage'], 'plugins' => []]];

        $finding = $this->findings($this->diagnose(configs: $configs))['The configuration declares no rules'];

        self::assertSame(Diagnosis::ERROR, $finding->status);
    }

    public function testRulesThatAreAllParkedAreAnErrorToo(): void
    {
        // Configuration exists, and nothing is being enforced. Reporting
        // "rules are configured" here would be technically true and useless.
        $configs = [[
            'storage' => ['type' => 'Kanopi\Firewall\Storage\InMemoryStorage'],
            'plugins' => [['plugin' => 'A', 'enable' => false]],
        ]];

        $finding = $this->findings($this->diagnose(configs: $configs))['No rule is enabled'];

        self::assertSame(Diagnosis::ERROR, $finding->status);
        self::assertStringContainsString('`enable: false`', (string) $finding->detail);
    }

    public function testEnabledRulesAreCounted(): void
    {
        $finding = $this->findings($this->diagnose())['Rules are configured'];

        self::assertSame(Diagnosis::OK, $finding->status);
        self::assertStringContainsString('1 of 1 enabled', (string) $finding->detail);
    }

    public function testAnInputThatFailedToLoadIsAnErrorBecauseNothingElseWillSaySo(): void
    {
        $finding = $this->findings(
            $this->diagnose(configs: [self::CONFIG . 'block.yml', self::CONFIG . 'missing.yml'])
        )['1 configuration input(s) failed to load'];

        self::assertSame(Diagnosis::ERROR, $finding->status);
        self::assertStringContainsString('missing.yml', (string) $finding->detail);
        self::assertSame('docs/configuration/loading-and-includes.md', $finding->reference);
    }

    #[DataProvider('providePriorities')]
    public function testThePriorityIsJudgedAgainstTheListenersItHasToBeat(
        int $priority,
        string $status,
        string $titleFragment
    ): void {
        $finding = $this->matching($this->diagnose(priority: $priority), $titleFragment);

        self::assertSame($status, $finding->status);
    }

    /**
     * @return iterable<string, array{0: int, 1: string, 2: string}>
     */
    public static function providePriorities(): iterable
    {
        // Below the router the challenge path 404s before the listener sees
        // the POST, and a challenged visitor can never answer.
        yield 'below the router' => [8, Diagnosis::ERROR, 'is not above the router'];
        yield 'level with the router' => [32, Diagnosis::ERROR, 'is not above the router'];
        yield 'above the router, below the session' => [64, Diagnosis::WARNING, 'below SessionListener'];
        yield 'level with the session' => [128, Diagnosis::WARNING, 'below SessionListener'];
        yield 'the default' => [250, Diagnosis::OK, 'Listener priority is 250'];
    }

    public function testThePriorityErrorNamesThePathThatWouldStopWorking(): void
    {
        $finding = $this->matching($this->diagnose(priority: 8), 'is not above the router');

        self::assertStringContainsString('/_firewall/challenge', (string) $finding->detail);
        self::assertStringContainsString('back to 250', (string) $finding->detail);
    }

    public function testARouteOnTheChallengePathIsReportedBecauseTheControllerStopsBeingCalled(): void
    {
        $collection = new RouteCollection();
        $collection->add('challenge_page', new Route('/_firewall/challenge'));

        $finding = $this->matching(
            $this->diagnose(router: $this->router($collection)),
            'The challenge path is also a route'
        );

        self::assertSame(Diagnosis::WARNING, $finding->status);
        self::assertStringContainsString('challenge_page', (string) $finding->detail);
    }

    public function testAnUnroutedChallengePathIsTheOrdinaryCase(): void
    {
        $collection = new RouteCollection();
        $collection->add('homepage', new Route('/'));

        $finding = $this->matching(
            $this->diagnose(router: $this->router($collection)),
            'The challenge path is not a route'
        );

        self::assertSame(Diagnosis::OK, $finding->status);
    }

    public function testAnApplicationWithNoRouterHasNothingToCollideWith(): void
    {
        $finding = $this->matching($this->diagnose(), 'No router to collide with');

        self::assertSame(Diagnosis::OK, $finding->status);
    }

    public function testAnUnknownProxyPostureIsAWarningRatherThanAnAssumption(): void
    {
        // "Nobody configured proxies" and "there is no proxy" are
        // indistinguishable from here, and only one of them is safe.
        $finding = $this->matching(
            $this->diagnose(proxyPosture: new ProxyPosture('auto')),
            'Nothing says whether this is behind a proxy'
        );

        self::assertSame(Diagnosis::WARNING, $finding->status);
        self::assertStringContainsString('counts the whole internet into one bucket', (string) $finding->detail);
    }

    public function testAnAssertedProxyPostureIsFine(): void
    {
        $finding = $this->matching($this->diagnose(), 'The proxy posture is asserted');

        self::assertSame(Diagnosis::OK, $finding->status);
    }

    public function testTrustedProxiesCountAsAnAssertion(): void
    {
        // The bundle bridges framework.trusted_proxies rather than asking
        // the same question twice, so this is the ordinary way it is set.
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_FOR);

        $finding = $this->matching(
            $this->diagnose(proxyPosture: new ProxyPosture('auto')),
            'The proxy posture is asserted'
        );

        self::assertSame(Diagnosis::OK, $finding->status);
    }

    public function testInMemoryStorageIsAWarningAboutTheCommandsAsWellAsTheRules(): void
    {
        $finding = $this->matching($this->diagnose(), 'Storage is in-memory');

        self::assertSame(Diagnosis::WARNING, $finding->status);
        self::assertStringContainsString('kanopi:firewall:block cannot stop anything', (string) $finding->detail);
    }

    public function testNoStorageTypeAtAllIsWorthSaying(): void
    {
        $finding = $this->matching(
            $this->diagnose(configs: [['plugins' => [['plugin' => 'A']]]]),
            'No storage backend is configured'
        );

        self::assertSame(Diagnosis::WARNING, $finding->status);
    }

    public function testARealBackendIsNamedRatherThanWarnedAbout(): void
    {
        $configs = [[
            'storage' => ['type' => OpaqueStorage::class],
            'plugins' => [['plugin' => 'A']],
        ]];

        $finding = $this->matching($this->diagnose(configs: $configs), 'Storage backend');

        self::assertSame(Diagnosis::OK, $finding->status);
        self::assertSame(OpaqueStorage::class, $finding->detail);
    }

    public function testFailOpenIsStatedRatherThanJudged(): void
    {
        // A deliberate choice, and the right one for some deployments. What
        // is worth knowing is that a broken firewall then looks exactly like
        // no firewall.
        $finding = $this->matching($this->diagnose(onStartupFailure: 'fail_open'), 'fail_open');

        self::assertSame(Diagnosis::WARNING, $finding->status);
        self::assertSame('docs/guides/error-handling.md', $finding->reference);
    }

    public function testFailClosedIsFine(): void
    {
        self::assertSame(Diagnosis::OK, $this->matching($this->diagnose(), 'fail_closed')->status);
    }

    public function testLoggingThatIsOffMeansThereIsNoEvidence(): void
    {
        $finding = $this->matching($this->diagnose(loggingMode: 'off'), 'Firewall logging is off');

        self::assertSame(Diagnosis::WARNING, $finding->status);
        self::assertStringContainsString('symfony/monolog-bundle', (string) $finding->detail);
    }

    public function testLoggingThatIsOnIsNamed(): void
    {
        self::assertSame(
            Diagnosis::OK,
            $this->matching($this->diagnose(), 'Firewall logging is "replace"')->status
        );
    }

    public function testEvaluatingSubRequestsIsReportedAsSpentBudget(): void
    {
        $finding = $this->matching($this->diagnose(onlyMainRequests: false), 'Sub-requests are evaluated too');

        self::assertSame(Diagnosis::WARNING, $finding->status);
        self::assertStringContainsString('four requests', (string) $finding->detail);
    }

    public function testSkippingSubRequestsIsFine(): void
    {
        self::assertSame(Diagnosis::OK, $this->matching($this->diagnose(), 'Sub-requests are skipped')->status);
    }

    public function testScriptsThatAreNotWhereTheBundleLooksKillEveryWrapper(): void
    {
        $finding = $this->matching($this->diagnose(binDir: '/nowhere'), 'bin/ scripts are not where');

        self::assertSame(Diagnosis::ERROR, $finding->status);
        self::assertStringContainsString('commands.bin_dir', (string) $finding->detail);
    }

    public function testScriptsThatAreInstalledAreNamedWithTheirDirectory(): void
    {
        $finding = $this->matching($this->diagnose(), 'bin/ scripts are installed');

        self::assertSame(Diagnosis::OK, $finding->status);
        self::assertSame(self::BIN, $finding->detail);
    }

    /**
     * Run the doctor with one thing changed.
     *
     * @param array<int, string|array<string, mixed>>|null $configs
     *   Config inputs, or NULL for the fixture that is well configured.
     *
     * @return array<int, Diagnosis>
     *   The findings.
     */
    private function diagnose(
        string $mode = 'enforce',
        int $priority = 250,
        bool $onlyMainRequests = true,
        ?string $binDir = null,
        string $loggingMode = 'replace',
        string $onStartupFailure = 'fail_closed',
        ?array $configs = null,
        ?ProxyPosture $proxyPosture = null,
        ?RouterInterface $router = null
    ): array {
        $configs ??= [self::CONFIG . 'block.yml'];

        return (new IntegrationDoctor(
            $mode,
            $priority,
            $onlyMainRequests,
            '/_firewall/challenge',
            $binDir ?? self::BIN,
            $loggingMode,
            $onStartupFailure,
            $configs,
            $proxyPosture ?? new ProxyPosture(false),
            new ConfigSnapshot($configs, []),
            $router
        ))->run();
    }

    /**
     * A router over one route collection.
     */
    private function router(RouteCollection $collection): RouterInterface
    {
        return new Router(
            new class ($collection) implements \Symfony\Component\Config\Loader\LoaderInterface {
                public function __construct(private readonly RouteCollection $collection)
                {
                }

                public function load(mixed $resource, ?string $type = null): mixed
                {
                    return $this->collection;
                }

                public function supports(mixed $resource, ?string $type = null): bool
                {
                    return true;
                }

                public function getResolver(): \Symfony\Component\Config\Loader\LoaderResolverInterface
                {
                    throw new \LogicException('Not needed.');
                }

                public function setResolver(\Symfony\Component\Config\Loader\LoaderResolverInterface $resolver): void
                {
                }
            },
            'routes'
        );
    }

    /**
     * The findings, keyed by title.
     *
     * @param array<int, Diagnosis> $findings
     *   What the doctor reported.
     *
     * @return array<string, Diagnosis>
     *   The same findings, addressable.
     */
    private function findings(array $findings): array
    {
        $keyed = [];

        foreach ($findings as $finding) {
            $keyed[$finding->title] = $finding;
        }

        return $keyed;
    }

    /**
     * The one finding whose title contains a fragment.
     *
     * @param array<int, Diagnosis> $findings
     *   What the doctor reported.
     * @param string $fragment
     *   Part of the title to look for.
     */
    private function matching(array $findings, string $fragment): Diagnosis
    {
        foreach ($findings as $finding) {
            if (str_contains($finding->title, $fragment)) {
                return $finding;
            }
        }

        self::fail(sprintf('No finding titled like "%s". Got: %s', $fragment, implode(
            ', ',
            array_map(static fn (Diagnosis $diagnosis): string => $diagnosis->title, $findings)
        )));
    }

    /**
     * The titles of the findings that are errors.
     *
     * @param array<int, Diagnosis> $findings
     *   What the doctor reported.
     *
     * @return array<int, string>
     *   Their titles.
     */
    private function errors(array $findings): array
    {
        return array_values(array_map(
            static fn (Diagnosis $diagnosis): string => $diagnosis->title,
            array_filter($findings, static fn (Diagnosis $d): bool => $d->status === Diagnosis::ERROR)
        ));
    }
}
