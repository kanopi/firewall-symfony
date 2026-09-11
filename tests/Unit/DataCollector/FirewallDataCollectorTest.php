<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\DataCollector;

use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Event\DecisionEvent;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\FirewallBundle\DataCollector\FirewallDataCollector;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\VarCloner;

#[CoversClass(FirewallDataCollector::class)]
final class FirewallDataCollectorTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    public function testItIsNamedForTheBundleAndStartsEmpty(): void
    {
        $collector = $this->collector(new DecisionRecorder());

        self::assertSame('kanopi_firewall', $collector->getName());
        self::assertSame([], $collector->getData());
    }

    #[DataProvider('provideVerdicts')]
    public function testEveryDecisionHasAOneWordVerdict(?DecisionEvent $decision, string $verdict): void
    {
        $recorder = new DecisionRecorder();

        if ($decision instanceof DecisionEvent) {
            $recorder->record($decision);
        }

        self::assertSame($verdict, $this->collect($recorder)['verdict']);
    }

    /**
     * @return iterable<string, array{0: DecisionEvent|null, 1: string}>
     */
    public static function provideVerdicts(): iterable
    {
        $request = Request::create('/');
        $plugin = new StubPlugin();

        yield 'nothing announced' => [null, 'not evaluated'];
        yield 'default allow' => [new RequestAllowed($request), 'allowed'];
        yield 'allow rule matched' => [new RequestAllowed($request, $plugin), 'bypassed'];
        yield 'block' => [new RequestBlocked($request, $plugin, 403), 'blocked'];
        yield 'challenge' => [new RequestChallenged($request, $plugin, 'math'), 'challenged'];
        yield 'challenge solved' => [new ChallengeSolved($request, 'math', 60), 'challenge solved'];
        yield 'challenge failed' => [new ChallengeFailed($request, 'math', 'invalid_solution'), 'challenge failed'];
    }

    public function testABlockNamesTheRuleAndTheStatus(): void
    {
        // The exception carries a status and a message, not the rule that
        // matched — the event is the only place that exists.
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestBlocked(Request::create('/'), new StubPlugin(), 429));

        $data = $this->collect($recorder);

        self::assertSame(['name' => 'stub-rule', 'class' => StubPlugin::class], $data['rule']);
        self::assertSame(429, $data['status_code']);
        self::assertTrue($data['enforced']);
    }

    public function testADurableBlockListHitNamesNoRule(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestBlocked(Request::create('/'), null, 403));

        // Not a rule somebody wrote — a ban somebody earned earlier.
        self::assertNull($this->collect($recorder)['rule']);
    }

    public function testAChallengeNamesItsProviderAndItsRule(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestChallenged(Request::create('/'), new StubPlugin(), 'altcha'));

        $data = $this->collect($recorder);

        self::assertSame('altcha', $data['provider']);
        self::assertSame(['name' => 'stub-rule', 'class' => StubPlugin::class], $data['rule']);
    }

    public function testARefusedSolutionCarriesItsReason(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new ChallengeFailed(Request::create('/'), 'altcha', 'solution_already_used'));

        $data = $this->collect($recorder);

        self::assertSame('solution_already_used', $data['reason']);
        self::assertSame('altcha', $data['provider']);
    }

    public function testAnObservedDecisionSaysItWasNotApplied(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestBlocked(Request::create('/'), new StubPlugin(), 403, false));

        self::assertFalse($this->collect($recorder)['enforced']);
    }

    public function testTheModeAndPanicSwitchComeFromTheFirewall(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestAllowed(Request::create('/')));

        $data = $this->collect($recorder);

        self::assertSame('exception', $data['mode']);
        self::assertSame('exception', $data['configured_mode']);
        // Flattened: `getPanicSwitch()` hands back a FirewallMode enum, and
        // the profiler serializes whatever it is given.
        self::assertSame(
            ['active' => false, 'mode' => null, 'path' => null, 'problem' => null],
            $data['panic_switch']
        );
    }

    public function testHealthIsReportedForAnEvaluatedRequest(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestAllowed(Request::create('/')));

        $data = $this->collect($recorder);

        self::assertSame([], $data['failed_rules']);
        self::assertSame([], $data['degraded_backends']);
    }

    public function testHealthIsSkippedOnARequestTheFirewallDidNotEvaluate(): void
    {
        // Both calls build every rule that is not built yet, which is what
        // opens a storage connection. On a request that did no firewall
        // work, that would be the first thing to open them.
        $data = $this->collect(new DecisionRecorder());

        self::assertSame([], $data['failed_rules']);
        self::assertSame('exception', $data['mode'], 'the cheap facts are still reported');
    }

    public function testHealthCanBeTurnedOff(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestAllowed(Request::create('/')));

        $data = $this->collect($recorder, collectHealth: false);

        self::assertSame([], $data['failed_rules']);
        self::assertSame('allowed', $data['verdict']);
    }

    public function testAStartupFailureIsReportedRatherThanRethrown(): void
    {
        // The request has already become an error page under fail_closed;
        // throwing again here would lose the profile that explains why.
        $data = $this->collect(new DecisionRecorder(), fixture: 'broken-storage.yml');

        self::assertIsString($data['error']);
        self::assertStringContainsString('Unable to create file', $data['error']);
        self::assertNull($data['mode']);
    }

    public function testAFailOpenFirewallIsReportedAsAbsent(): void
    {
        $data = $this->collect(
            new DecisionRecorder(),
            fixture: 'broken-storage.yml',
            onStartupFailure: 'fail_open'
        );

        self::assertIsString($data['error']);
        self::assertStringContainsString('fail_open', $data['error']);
    }

    public function testDisabledModeIsReportedWithoutBuildingTheFirewall(): void
    {
        // The fixture throws the instant it is built, so an answer at all
        // proves nothing was built — and `disabled` has no library
        // equivalent, so asking the firewall would have said `exception`.
        $data = $this->collect(new DecisionRecorder(), fixture: 'broken-storage.yml', mode: 'disabled');

        self::assertSame('disabled', $data['mode']);
        self::assertSame('disabled', $data['configured_mode']);
        self::assertNull($data['error']);
        self::assertSame('not evaluated', $data['verdict']);
    }

    public function testResetEmptiesTheCollector(): void
    {
        $collector = $this->collector(new DecisionRecorder());
        $collector->collect(Request::create('/'), new Response());

        $collector->reset();

        self::assertSame([], $collector->getData());
    }

    public function testClonedDataIsUnwrappedForTheTemplate(): void
    {
        // The parent property is typed `array|Data` for collectors that
        // store cloned variables. This one never does, but the narrowing
        // has to hold if anything ever puts one there.
        $collector = $this->collector(new DecisionRecorder());
        $property = new \ReflectionProperty($collector, 'data');
        $property->setValue($collector, (new VarCloner())->cloneVar(['verdict' => 'blocked']));

        self::assertSame(['verdict' => 'blocked'], $collector->getData());
    }

    /**
     * Collect one request and hand back the stored data.
     *
     * @return array<string, mixed>
     *   What the template will read.
     */
    private function collect(
        DecisionRecorder $recorder,
        bool $collectHealth = true,
        string $fixture = 'allow.yml',
        string $onStartupFailure = 'fail_closed',
        string $mode = 'enforce'
    ): array {
        $collector = $this->collector($recorder, $collectHealth, $fixture, $onStartupFailure, $mode);
        $collector->collect(Request::create('/'), new Response());

        return $collector->getData();
    }

    /**
     * A collector over a fixture configuration.
     */
    private function collector(
        DecisionRecorder $recorder,
        bool $collectHealth = true,
        string $fixture = 'allow.yml',
        string $onStartupFailure = 'fail_closed',
        string $mode = 'enforce'
    ): FirewallDataCollector {
        return new FirewallDataCollector(
            $recorder,
            new FirewallFactory(
                [self::CONFIG . $fixture],
                ['[global][mode]' => 'exception'],
                new ProxyPosture(false),
                new LoggerBridge('off'),
                $onStartupFailure
            ),
            $mode,
            $collectHealth
        );
    }
}
