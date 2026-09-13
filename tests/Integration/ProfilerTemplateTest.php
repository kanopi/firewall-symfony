<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Integration;

use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestMarked;
use Kanopi\Firewall\Event\RequestRedirected;
use Kanopi\FirewallBundle\DataCollector\FirewallDataCollector;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Kanopi\FirewallBundle\Tests\Unit\DataCollector\StubPlugin;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\FilesystemLoader;

/**
 * Renders the profiler panel.
 *
 * The template is the one file in the package PHPUnit's coverage cannot see,
 * and a Twig error in it is a 500 in the profiler — discovered by whoever
 * opens the panel, which is somebody already debugging something else. So it
 * is rendered here against real collector output, with every branch the
 * panel has: a block, an unhealthy backend, a live panic switch, an
 * observed-not-enforced decision, and a firewall that never started.
 *
 * WebProfilerBundle is stubbed rather than installed. Two templates from it
 * are referenced, both trivial, and pulling the bundle in as a dependency to
 * assert on our own file's syntax would be a poor trade.
 */
#[CoversNothing]
final class ProfilerTemplateTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../Fixtures/config/';

    public function testTheBlockedPanelRendersEveryFactItHas(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestBlocked(Request::create('/'), new StubPlugin(), 429));

        $html = $this->render($this->collect($recorder));

        self::assertStringContainsString('blocked', $html);
        self::assertStringContainsString('stub-rule', $html);
        self::assertStringContainsString('429', $html);
        // The panel exists partly to keep these two apart in the reader's
        // head, so both headings have to be there even when both are empty.
        self::assertStringContainsString('Rules that failed to build', $html);
        self::assertStringContainsString('Backends running blind', $html);
        self::assertStringContainsString('Every configured rule is constructed', $html);
    }

    public function testAnObservedDecisionSaysItWasNotApplied(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestBlocked(Request::create('/'), new StubPlugin(), 403, false));

        self::assertStringContainsString('recorded, not applied', $this->render($this->collect($recorder)));
    }

    public function testARedirectedRequestShowsWhereItWentAndAMarkedOneShowsItsMark(): void
    {
        // A redirect with no destination and a mark with no name each say
        // nothing at all — the value *is* the decision in both cases.
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestRedirected(Request::create('/moved'), new StubPlugin(), '/notice', 307));

        $html = $this->render($this->collect($recorder));

        self::assertStringContainsString('redirected', $html);
        self::assertStringContainsString('Redirected to', $html);
        self::assertStringContainsString('/notice', $html);

        $recorder = new DecisionRecorder();
        $recorder->record(new RequestMarked(Request::create('/'), new StubPlugin(), 'needs-captcha', 'firewall.marks'));

        $html = $this->render($this->collect($recorder));

        self::assertStringContainsString('marked', $html);
        self::assertStringContainsString('needs-captcha', $html);
    }

    public function testARefusedSolutionShowsItsReason(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new ChallengeFailed(Request::create('/'), 'altcha', 'solution_already_used'));

        $html = $this->render($this->collect($recorder));

        self::assertStringContainsString('challenge failed', $html);
        self::assertStringContainsString('solution_already_used', $html);
        self::assertStringContainsString('altcha', $html);
    }

    public function testAnEmptyPanelRendersRatherThanBlowingUp(): void
    {
        // No decision recorded — a request the firewall never evaluated,
        // which is every sub-request and every request in disabled mode.
        $html = $this->render($this->collect(new DecisionRecorder()));

        self::assertStringContainsString('not evaluated', $html);
        self::assertStringContainsString('none', $html);
    }

    public function testAFirewallThatCouldNotStartIsShownAsAnError(): void
    {
        $html = $this->render($this->collect(new DecisionRecorder(), 'broken-storage.yml', 'fail_open'));

        self::assertStringContainsString('fail_open', $html);
        self::assertStringContainsString('status-error', $html);
    }

    public function testAnActivePanicSwitchIsImpossibleToMiss(): void
    {
        // A panic file nobody removed after the incident is the realistic
        // failure, so the panel says the configured mode is being overridden
        // and names the file to delete.
        $html = $this->render($this->panicData([
            'active' => true,
            'mode' => 'log',
            'path' => '/var/run/firewall/panic',
            'problem' => null,
        ], 'log', 'exception'));

        self::assertStringContainsString('panic switch is active', $html);
        self::assertStringContainsString('/var/run/firewall/panic', $html);
    }

    public function testAPanicFileThatDidNotTakeIsAnError(): void
    {
        $html = $this->render($this->panicData([
            'active' => false,
            'mode' => null,
            'path' => '/var/run/firewall/panic',
            'problem' => 'not a mode: "halt"',
        ], 'exception', 'exception'));

        self::assertStringContainsString('was <strong>not</strong> applied', $html);
        self::assertStringContainsString('not a mode', $html);
    }

    public function testUnhealthyRulesAndBackendsAreListed(): void
    {
        $html = $this->render([
            'verdict' => 'allowed',
            'enforced' => true,
            'rule' => null,
            'status_code' => null,
            'provider' => null,
            'reason' => null,
            'mode' => 'exception',
            'configured_mode' => 'exception',
            'panic_switch' => ['active' => false, 'mode' => null, 'path' => null, 'problem' => null],
            'failed_rules' => [
                ['bucket' => 'block', 'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit:2', 'error' => 'Connection refused'],
            ],
            'degraded_backends' => [
                ['component' => 'rate limit', 'backend' => 'Kanopi\\Firewall\\RateLimitStorage\\RedisRateLimitStorage', 'error' => 'Connection refused'],
            ],
            'error' => null,
        ]);

        self::assertStringContainsString('RateLimit:2', $html);
        self::assertStringContainsString('RedisRateLimitStorage', $html);
        self::assertStringContainsString('Connection refused', $html);
        self::assertStringNotContainsString('Every configured rule is constructed', $html);
    }

    /**
     * Collector data with a given panic switch.
     *
     * @param array{active: bool, mode: string|null, path: string|null, problem: string|null} $panic
     *   The panic switch as the collector flattens it.
     *
     * @return array<string, mixed>
     *   Panel data.
     */
    private function panicData(array $panic, string $mode, string $configuredMode): array
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestBlocked(Request::create('/'), new StubPlugin(), 403));

        return array_replace($this->collect($recorder), [
            'panic_switch' => $panic,
            'mode' => $mode,
            'configured_mode' => $configuredMode,
        ]);
    }

    /**
     * Run the collector over a fixture and hand back what it stored.
     *
     * @return array<string, mixed>
     *   Panel data.
     */
    private function collect(
        DecisionRecorder $recorder,
        string $fixture = 'allow.yml',
        string $onStartupFailure = 'fail_closed'
    ): array {
        $collector = new FirewallDataCollector(
            $recorder,
            new FirewallFactory(
                [self::CONFIG . $fixture],
                ['[global][mode]' => 'exception'],
                new ProxyPosture(false),
                new LoggerBridge('off'),
                $onStartupFailure
            )
        );
        $collector->collect(Request::create('/'), new \Symfony\Component\HttpFoundation\Response());

        return $collector->getData();
    }

    /**
     * Render the panel template against the given data.
     *
     * @param array<string, mixed> $data
     *   What the collector stored.
     */
    private function render(array $data): string
    {
        // Namespaced the way FrameworkBundle namespaces a bundle's
        // templates: `@KanopiFirewall` from the bundle name minus "Bundle".
        $bundleTemplates = new FilesystemLoader();
        $bundleTemplates->addPath(dirname(__DIR__, 2) . '/src/Resources/views', 'KanopiFirewall');

        $twig = new Environment(new ChainLoader([
            $bundleTemplates,
            new ArrayLoader([
                // Enough of WebProfilerBundle to resolve the two references.
                '@WebProfiler/Profiler/layout.html.twig' =>
                    '{% block toolbar %}{% endblock %}{% block menu %}{% endblock %}{% block panel %}{% endblock %}',
                '@WebProfiler/Profiler/toolbar_item.html.twig' => '{{ icon|raw }}{{ text|raw }}',
            ]),
        ]), ['strict_variables' => true]);

        return $twig->render('@KanopiFirewall/Collector/firewall.html.twig', [
            'collector' => new PanelData($data),
        ]);
    }
}
