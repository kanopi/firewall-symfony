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
    public function testItSubscribesToEveryDecisionEvent(): void
    {
        // Subscribed by FQCN, because that is the name Symfony dispatches
        // an object under when it carries none of its own.
        self::assertSame([
            RequestAllowed::class => 'record',
            RequestBlocked::class => 'record',
            RequestChallenged::class => 'record',
            ChallengeSolved::class => 'record',
            ChallengeFailed::class => 'record',
        ], DecisionRecorder::getSubscribedEvents());
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
