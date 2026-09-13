<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\EventListener;

use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\DecisionEvent;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(DecisionRecorder::class)]
final class DecisionRecorderTest extends TestCase
{
    public function testItSubscribesToEveryDecisionEventTheLibraryShips(): void
    {
        // Read off the library rather than written out here, and that is the
        // point of the test. The recorder subscribes by FQCN — the name
        // Symfony dispatches an object under when it carries none of its own
        // — so a decision event nobody subscribed to is not an error
        // anywhere: the profiler simply reports "not evaluated" for a request
        // the firewall acted on. kanopi/firewall 2.26.0 added three at once,
        // which is what made a hand-written list here worth replacing.
        $shipped = [];

        foreach ((array) glob($this->eventDirectory() . '/*.php') as $file) {
            $class = 'Kanopi\\Firewall\\Event\\' . basename((string) $file, '.php');

            if (class_exists($class) && is_subclass_of($class, DecisionEvent::class)) {
                $shipped[] = $class;
            }
        }

        $subscribed = array_keys(DecisionRecorder::getSubscribedEvents());

        sort($shipped);
        sort($subscribed);

        self::assertSame($shipped, $subscribed, 'every decision the library announces has to be recorded');
        self::assertSame(
            ['record'],
            array_values(array_unique(array_values(DecisionRecorder::getSubscribedEvents()))),
            'and all of them through the one method'
        );
    }

    /**
     * Where the library keeps its decision events.
     */
    private function eventDirectory(): string
    {
        $file = (new \ReflectionClass(DecisionEvent::class))->getFileName();

        self::assertIsString($file);

        return dirname($file);
    }

    public function testItStartsEmpty(): void
    {
        $recorder = new DecisionRecorder();

        self::assertNull($recorder->getDecision());
        self::assertNull($recorder->getChallengedProvider());
    }

    public function testItRemembersTheLastDecision(): void
    {
        $recorder = new DecisionRecorder();
        $first = new RequestAllowed(Request::create('/'));
        $second = new RequestBlocked(Request::create('/'), null, 403);

        $recorder->record($first);
        $recorder->record($second);

        self::assertSame($second, $recorder->getDecision());
    }

    public function testItExposesTheChallengedProvider(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestChallenged(
            Request::create('/'),
            $this->createStub(PluginInterface::class),
            'altcha'
        ));

        self::assertSame('altcha', $recorder->getChallengedProvider());
    }

    public function testAnyOtherDecisionHasNoChallengedProvider(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new ChallengeSolved(Request::create('/'), 'math', 60));

        self::assertNull($recorder->getChallengedProvider());
    }

    public function testResetForgetsTheDecision(): void
    {
        $recorder = new DecisionRecorder();
        $recorder->record(new RequestAllowed(Request::create('/')));

        $recorder->reset();

        // Under a worker runtime the container outlives the request, and a
        // stale verdict is worse than none: it would pick a challenge
        // provider for the wrong visitor.
        self::assertNull($recorder->getDecision());
    }
}
