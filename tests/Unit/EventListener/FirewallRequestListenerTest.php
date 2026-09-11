<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\EventListener;

use Kanopi\Firewall\Exception\StorageException;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\EventListener\FirewallRequestListener;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use Kanopi\FirewallBundle\Http\ChallengeRenderer;
use Kanopi\FirewallBundle\Http\FirewallResponseFactory;
use Kanopi\FirewallBundle\Tests\Fixtures\MathChallengeSolver;
use Kanopi\FirewallBundle\Tests\Fixtures\RecordingLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

#[CoversClass(FirewallRequestListener::class)]
final class FirewallRequestListenerTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    public function testDisabledModeNeverTouchesTheFirewall(): void
    {
        // The fixture throws the instant it is built, so a request that
        // survives proves nothing was built.
        $event = $this->handle('/', '203.0.113.5', 'broken-storage.yml', mode: 'disabled');

        self::assertNull($event->getResponse());
    }

    public function testSubRequestsAreSkipped(): void
    {
        $event = $this->handle('/', '203.0.113.5', 'block.yml', requestType: HttpKernelInterface::SUB_REQUEST);

        // Same client, same headers, same verdict — and evaluating it again
        // would charge every per-IP rate limit twice for one page.
        self::assertNull($event->getResponse());
    }

    public function testSubRequestsCanBeEvaluatedOnRequest(): void
    {
        $event = $this->handle(
            '/',
            '203.0.113.5',
            'block.yml',
            onlyMainRequests: false,
            requestType: HttpKernelInterface::SUB_REQUEST
        );

        self::assertSame(403, $this->response($event)->getStatusCode());
    }

    public function testABlockBecomesAResponse(): void
    {
        $event = $this->handle('/', '203.0.113.5', 'block.yml');

        self::assertSame(403, $this->response($event)->getStatusCode());
        self::assertSame('Blocked: 203.0.113.5', $this->response($event)->getContent());
        // setResponse() stops propagation, so no session, no routing and no
        // authentication happen for traffic that is not getting through.
        self::assertTrue($event->isPropagationStopped());
    }

    public function testAnAllowedRequestSetsNoResponse(): void
    {
        $event = $this->handle('/', '198.51.100.1', 'block.yml');

        self::assertNull($event->getResponse());
    }

    public function testAChallengeBecomesAnInterstitial(): void
    {
        $event = $this->handle('/gated', '198.51.100.1', 'challenge.yml');

        self::assertSame(Response::HTTP_OK, $this->response($event)->getStatusCode());
        self::assertStringContainsString('challenge_answer', (string) $this->response($event)->getContent());
    }

    public function testASolvedChallengeBecomesARedirect(): void
    {
        $listener = $this->listener('challenge.yml');
        $interstitial = $this->dispatch($listener, Request::create('/gated'));
        $submission = Request::create(
            '/_firewall/challenge',
            'POST',
            MathChallengeSolver::solve((string) $this->response($interstitial)->getContent())
        );

        $event = $this->dispatch($listener, $submission);

        self::assertSame(Response::HTTP_SEE_OTHER, $this->response($event)->getStatusCode());
        self::assertSame('/gated', $this->response($event)->headers->get('Location'));
    }

    public function testARejectedSolutionServesTheInterstitialAgain(): void
    {
        $listener = $this->listener('challenge.yml');
        $submission = Request::create('/_firewall/challenge', 'POST', [
            'challenge_state' => 'forged',
            'challenge_answer' => '7',
        ]);

        $event = $this->dispatch($listener, $submission);

        // The library deliberately does not distinguish "solve this" from
        // "you were wrong" — telling a bot which is free information — so
        // the same document answers both.
        self::assertSame(Response::HTTP_OK, $this->response($event)->getStatusCode());
        self::assertStringContainsString('challenge_answer', (string) $this->response($event)->getContent());
    }

    public function testObserveModeNeverRefusesARequest(): void
    {
        $event = $this->handle('/', '203.0.113.5', 'block.yml', mode: 'observe');

        // Honest about what this proves: PHPUnit runs on the `cli` SAPI, so
        // the library short-circuits before evaluating anything and this
        // asserts only that observe mode cannot produce a response. That
        // observe mode actually *evaluates* is proven in
        // Integration\WebSapiObserveModeTest, which serves the same
        // configuration over `php -S`.
        self::assertNull($event->getResponse());
    }

    public function testObserveModeNeverForwardsAChallengeSubmission(): void
    {
        // The POST interception in `evaluate()` runs before the mode is
        // consulted, so in the library's `log` mode this path still calls
        // exit(). Nothing legitimate is being challenged in observe mode,
        // so nothing legitimate is being submitted.
        $event = $this->dispatch(
            $this->listener('challenge.yml', mode: 'observe'),
            Request::create('/_firewall/challenge', 'POST')
        );

        self::assertNull($event->getResponse());
    }

    public function testObserveModeStillEvaluatesOtherPosts(): void
    {
        $event = $this->dispatch(
            $this->listener('challenge.yml', mode: 'observe'),
            Request::create('/gated', 'POST')
        );

        self::assertNull($event->getResponse());
    }

    public function testObserveModeSaysSoOnceWhenItCannotObserveAnything(): void
    {
        // PHPUnit runs on the CLI SAPI, which is exactly the condition:
        // `evaluate()` returns early for every mode but `exception`, so
        // observe mode under RoadRunner or Swoole evaluates nothing.
        $logger = new RecordingLogger();
        $listener = $this->listener('block.yml', mode: 'observe', logger: $logger);

        $this->dispatch($listener, Request::create('/'));
        $this->dispatch($listener, Request::create('/'));

        self::assertTrue($logger->has('warning', 'no request is being evaluated'));
        self::assertCount(1, $logger->records, 'once per process, not once per request');
    }

    public function testEnforceModeSaysNothingAboutTheCliSapi(): void
    {
        // `exception` mode is exempt from the short-circuit, so there is
        // nothing to warn about.
        $logger = new RecordingLogger();

        $this->dispatch($this->listener('block.yml', logger: $logger), Request::create('/'));

        self::assertSame([], $logger->records);
    }

    public function testAFailOpenStartupFailureLetsTheRequestThrough(): void
    {
        $event = $this->handle('/', '203.0.113.5', 'broken-storage.yml', onStartupFailure: 'fail_open');

        self::assertNull($event->getResponse());
    }

    public function testAFailClosedStartupFailureIsNotSwallowed(): void
    {
        $this->expectException(StorageException::class);

        $this->handle('/', '203.0.113.5', 'broken-storage.yml');
    }

    public function testTheRecorderIsClearedBeforeEachEvaluation(): void
    {
        $recorder = new DecisionRecorder();
        $listener = $this->listener('block.yml', recorder: $recorder);

        $this->dispatch($listener, $this->request('/', '203.0.113.5'));
        self::assertInstanceOf(\Kanopi\Firewall\Event\RequestBlocked::class, $recorder->getDecision());

        $this->dispatch($listener, $this->request('/', '198.51.100.1'));
        self::assertInstanceOf(\Kanopi\Firewall\Event\RequestAllowed::class, $recorder->getDecision());
    }

    /**
     * The response the listener set, asserting that it set one.
     */
    private function response(RequestEvent $event): Response
    {
        $response = $event->getResponse();

        self::assertInstanceOf(Response::class, $response);

        return $response;
    }

    /**
     * Build a listener, dispatch one request through it, return the event.
     */
    private function handle(
        string $path,
        string $ip,
        string $fixture,
        string $mode = 'enforce',
        bool $onlyMainRequests = true,
        string $onStartupFailure = 'fail_closed',
        int $requestType = HttpKernelInterface::MAIN_REQUEST
    ): RequestEvent {
        return $this->dispatch(
            $this->listener($fixture, $mode, $onlyMainRequests, $onStartupFailure),
            $this->request($path, $ip),
            $requestType
        );
    }

    /**
     * Run one request through a listener.
     */
    private function dispatch(
        FirewallRequestListener $listener,
        Request $request,
        int $requestType = HttpKernelInterface::MAIN_REQUEST
    ): RequestEvent {
        $event = new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            $requestType
        );

        $listener($event);

        return $event;
    }

    /**
     * A listener over a fixture configuration.
     */
    private function listener(
        string $fixture,
        string $mode = 'enforce',
        bool $onlyMainRequests = true,
        string $onStartupFailure = 'fail_closed',
        ?DecisionRecorder $recorder = null,
        ?RecordingLogger $logger = null
    ): FirewallRequestListener {
        $recorder ??= new DecisionRecorder();
        $dispatcher = new \Symfony\Component\EventDispatcher\EventDispatcher();
        $dispatcher->addSubscriber($recorder);

        $configs = [self::CONFIG . $fixture];
        $overrides = ['[global][mode]' => $mode === 'observe' ? 'log' : 'exception'];
        $resolver = new ChallengeConfigResolver($configs, $overrides);

        return new FirewallRequestListener(
            new FirewallFactory(
                $configs,
                $overrides,
                new ProxyPosture(false),
                new LoggerBridge('off'),
                $onStartupFailure,
                null,
                $dispatcher
            ),
            new FirewallResponseFactory(
                new ChallengeRenderer($resolver, $recorder),
                $resolver,
                $recorder,
                ['path' => '/', 'domain' => null, 'secure' => true, 'http_only' => true, 'same_site' => 'strict']
            ),
            $recorder,
            $mode,
            '/_firewall/challenge',
            $onlyMainRequests,
            $logger
        );
    }

    /**
     * A request from a given address.
     */
    private function request(string $path, string $ip): Request
    {
        $request = Request::create($path);
        $request->server->set('REMOTE_ADDR', $ip);

        return $request;
    }
}
