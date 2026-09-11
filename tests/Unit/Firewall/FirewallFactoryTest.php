<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\Firewall\Exception\StorageException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Kanopi\FirewallBundle\Tests\Fixtures\RecordingLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;

#[CoversClass(FirewallFactory::class)]
final class FirewallFactoryTest extends TestCase
{
    /**
     * Fixture configuration directory.
     */
    private const CONFIG = __DIR__ . '/../../Fixtures/config/';

    private Logger $originalLibraryLogger;

    protected function setUp(): void
    {
        $this->originalLibraryLogger = LoggingFactory::logger();
    }

    protected function tearDown(): void
    {
        LoggingFactory::setLogger($this->originalLibraryLogger);
    }

    public function testItBuildsAFirewallInTheModeItWasGiven(): void
    {
        $firewall = $this->factory()->get();

        self::assertInstanceOf(Firewall::class, $firewall);
        self::assertSame(FirewallMode::Exception, $firewall->getMode());
    }

    public function testTheFirewallIsBuiltOnceAndReused(): void
    {
        $factory = $this->factory();

        self::assertSame($factory->get(), $factory->get());
    }

    public function testTheProxyPostureIsMergedIntoTheOverrides(): void
    {
        $handler = new TestHandler();
        LoggingFactory::setLogger(new Logger('firewall', [$handler]));

        // behind_proxy: false is the assertion that silences the library's
        // "trusted proxies are not configured" warning, so its absence from
        // the log is what proves the override arrived.
        $this->factory(overrides: [], posture: new ProxyPosture(false))->get();

        self::assertFalse($handler->hasRecordThatContains('trusted', \Monolog\Level::Warning));
    }

    public function testTheLoggerBridgeIsAppliedOnlyAfterCreate(): void
    {
        $applicationHandler = new TestHandler();

        $this->factory(bridge: new LoggerBridge('replace', new Logger('app', [$applicationHandler])))->get();

        LoggingFactory::logger()->warning('after create');

        // `Firewall::create()` installs its own logger unconditionally, so a
        // bridge applied any earlier than this would simply be overwritten.
        self::assertTrue($applicationHandler->hasWarningThatContains('after create'));
    }

    public function testFailClosedRethrowsAStartupFailure(): void
    {
        $factory = $this->factory('broken-storage.yml');

        $this->expectException(StorageException::class);

        $factory->get();
    }

    public function testFailOpenReturnsNullAndSaysSoAtCritical(): void
    {
        $logger = new RecordingLogger();
        $factory = $this->factory('broken-storage.yml', onStartupFailure: 'fail_open', logger: $logger);

        self::assertNull($factory->get());
        self::assertTrue($logger->has('critical', 'unfiltered'));
    }

    public function testFailOpenWithoutALoggerStillReturnsNull(): void
    {
        self::assertNull($this->factory('broken-storage.yml', onStartupFailure: 'fail_open')->get());
    }

    public function testAFailedBuildIsNotRetried(): void
    {
        $logger = new RecordingLogger();
        $factory = $this->factory('broken-storage.yml', onStartupFailure: 'fail_open', logger: $logger);

        $factory->get();
        $factory->get();

        // Retrying a refused connection on every request turns a filtering
        // outage into a latency outage.
        self::assertCount(1, $logger->records);
    }

    public function testTheDispatcherIsHandedToTheLibrary(): void
    {
        $dispatcher = new EventDispatcher();
        $seen = [];
        $dispatcher->addListener(
            \Kanopi\Firewall\Event\RequestAllowed::class,
            static function (\Kanopi\Firewall\Event\RequestAllowed $event) use (&$seen): void {
                $seen[] = $event->getRequest()->getPathInfo();
            }
        );

        $firewall = $this->factory(dispatcher: $dispatcher)->get();
        self::assertInstanceOf(Firewall::class, $firewall);
        $firewall->evaluate(\Symfony\Component\HttpFoundation\Request::create('/hello'));

        // Symfony's dispatcher is PSR-14, so it goes straight into
        // create()'s third argument with no adapter in between.
        self::assertSame(['/hello'], $seen);
    }

    /**
     * A factory over a fixture configuration.
     *
     * @param array<string, mixed> $overrides
     *   Library overrides.
     */
    private function factory(
        string $fixture = 'allow.yml',
        array $overrides = ['[global][mode]' => 'exception'],
        ?ProxyPosture $posture = null,
        ?LoggerBridge $bridge = null,
        string $onStartupFailure = 'fail_closed',
        ?RecordingLogger $logger = null,
        ?EventDispatcher $dispatcher = null
    ): FirewallFactory {
        return new FirewallFactory(
            [self::CONFIG . $fixture],
            $overrides + ['[global][mode]' => 'exception'],
            $posture ?? new ProxyPosture(false),
            $bridge ?? new LoggerBridge('off'),
            $onStartupFailure,
            $logger,
            $dispatcher
        );
    }
}
