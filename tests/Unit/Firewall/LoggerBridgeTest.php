<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(LoggerBridge::class)]
final class LoggerBridgeTest extends TestCase
{
    /**
     * `LoggingFactory` is a static holder shared by the whole process, so
     * every test here has to put back what it found.
     */
    private Logger $originalLibraryLogger;

    protected function setUp(): void
    {
        $this->originalLibraryLogger = LoggingFactory::logger();
    }

    protected function tearDown(): void
    {
        LoggingFactory::setLogger($this->originalLibraryLogger);
    }

    public function testOffLeavesTheLibraryLoggerAlone(): void
    {
        $library = $this->libraryLogger();

        (new LoggerBridge('off', new Logger('app', [new TestHandler()])))->apply();

        self::assertSame($library, LoggingFactory::logger());
        self::assertCount(1, LoggingFactory::logger()->getHandlers());
    }

    public function testNoMonologLoggerBehavesAsOff(): void
    {
        $library = $this->libraryLogger();

        (new LoggerBridge('replace'))->apply();

        self::assertSame($library, LoggingFactory::logger());
    }

    public function testReplaceSwapsInTheApplicationLogger(): void
    {
        $this->libraryLogger();
        $application = new Logger('app', [new TestHandler()]);

        (new LoggerBridge('replace', $application))->apply();

        self::assertSame($application, LoggingFactory::logger());
    }

    public function testMergeKeepsTheLibraryHandlersAndAddsTheApplicationOnes(): void
    {
        $libraryHandler = new TestHandler();
        LoggingFactory::setLogger(new Logger('firewall', [$libraryHandler]));
        $applicationHandler = new TestHandler();

        (new LoggerBridge('merge', new Logger('app', [$applicationHandler])))->apply();

        LoggingFactory::logger()->warning('audit line');

        // Both, which is the point: a DatabaseHandler retained as the audit
        // trail survives, and the line also reaches the application's stack.
        self::assertTrue($libraryHandler->hasWarningThatContains('audit line'));
        self::assertTrue($applicationHandler->hasWarningThatContains('audit line'));
    }

    public function testMergeIsIdempotent(): void
    {
        LoggingFactory::setLogger(new Logger('firewall', [new TestHandler()]));
        $bridge = new LoggerBridge('merge', new Logger('app', [new TestHandler()]));

        $bridge->apply();
        $bridge->apply();

        // Two applies would otherwise attach the same handler twice, and
        // every line in the audit trail would appear twice with it.
        self::assertCount(2, LoggingFactory::logger()->getHandlers());
    }

    /**
     * Install a known library logger and hand it back.
     */
    private function libraryLogger(): Logger
    {
        $logger = new Logger('firewall', [new TestHandler()]);
        LoggingFactory::setLogger($logger);

        return $logger;
    }
}
