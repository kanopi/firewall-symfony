<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Integration;

use Kanopi\Firewall\Event\RequestBlocked;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\PhpExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * `observe` mode on a SAPI that is not `cli`.
 *
 * Trap #2 in the brief, and the reason this test is worth a subprocess:
 * `Firewall::evaluate()` returns TRUE immediately when `PHP_SAPI === 'cli'`
 * for every mode but `exception`. PHPUnit runs on `cli`. So every other
 * `observe` assertion in this suite is satisfied by that short-circuit and
 * proves nothing about `log` mode — a firewall in observe mode could be
 * evaluating nothing at all and the suite would stay green.
 *
 * `php -S` reports `cli-server`, which is a web SAPI as far as that check
 * is concerned, so this is where observe mode can be shown to actually run.
 * The same short-circuit means that under RoadRunner or Swoole, which do
 * serve HTTP from the `cli` SAPI, observe mode evaluates nothing — which is
 * what `FirewallRequestListener` warns about, and what the README says.
 */
#[CoversNothing]
final class WebSapiObserveModeTest extends TestCase
{
    private ?Process $server = null;

    private string $base = '';

    protected function setUp(): void
    {
        $php = (new PhpExecutableFinder())->find(false);

        if ($php === false) {
            self::markTestSkipped('no PHP binary to start a web SAPI with');
        }

        $port = $this->freePort();
        $this->base = sprintf('http://127.0.0.1:%d', $port);
        $this->server = new Process(
            [$php, '-S', '127.0.0.1:' . $port, '-t', __DIR__ . '/../Fixtures/server'],
            __DIR__ . '/../Fixtures/server'
        );
        $this->server->start();

        $this->waitForServer();
    }

    protected function tearDown(): void
    {
        $this->server?->stop();
        (new Filesystem())->remove(sys_get_temp_dir() . '/kanopi-firewall-bundle-tests');
    }

    public function testObserveModeEvaluatesAndReportsWithoutRefusing(): void
    {
        $result = $this->get('?mode=observe&ip=203.0.113.5');

        self::assertSame('cli-server', $result['sapi'], 'the point of the subprocess');
        self::assertSame(200, $result['status']);
        self::assertSame('application reached', $result['body']);
        // Evaluated, and the verdict recorded — this is what the `cli` SAPI
        // short-circuit hides from the rest of the suite.
        self::assertSame(RequestBlocked::class, $result['decision']);
        self::assertFalse($result['enforced'], 'observe records the decision, it does not apply it');
    }

    public function testEnforceModeOnTheSameSapiStillRefuses(): void
    {
        $result = $this->get('?mode=enforce&ip=203.0.113.5');

        self::assertSame(403, $result['status']);
        self::assertSame('Blocked: 203.0.113.5', $result['body']);
        self::assertTrue($result['enforced']);
    }

    /**
     * Fetch and decode one response from the fixture server.
     *
     * @return array<string, mixed>
     *   The JSON the front controller reports.
     */
    private function get(string $query): array
    {
        $body = @file_get_contents($this->base . '/index.php' . $query);

        self::assertIsString($body, 'the fixture server did not answer');

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            // The raw body, because "Syntax error" on its own is useless
            // here: anything the front controller prints — a deprecation
            // from a floor dependency, a warning, a stack trace — lands in
            // front of the JSON, and the body is what says which.
            self::fail(sprintf(
                "the fixture server did not answer with JSON (%s):\n%s",
                $jsonException->getMessage(),
                $body
            ));
        }

        return $decoded;
    }

    /**
     * A port nothing is listening on.
     */
    private function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $errorMessage);

        self::assertIsResource($socket, 'could not reserve a port: ' . (is_string($errorMessage) ? $errorMessage : ''));

        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }

    /**
     * Block until the built-in server answers, or give up.
     */
    private function waitForServer(): void
    {
        for ($attempt = 0; $attempt < 100; ++$attempt) {
            $connection = @fsockopen('127.0.0.1', (int) parse_url($this->base, PHP_URL_PORT), $code, $message, 0.1);

            if (is_resource($connection)) {
                fclose($connection);

                return;
            }

            usleep(50_000);
        }

        self::markTestSkipped('the built-in web server did not come up');
    }
}
