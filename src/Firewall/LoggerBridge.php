<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Firewall;

use Kanopi\Firewall\Logging\LoggingFactory;
use Monolog\Logger;

/**
 * Points the library's audit trail at the application's Monolog channel.
 *
 * The library logs through `LoggingFactory`, a static holder, and
 * `Firewall::create()` overwrites whatever is in it with a logger built from
 * the `logger:` block of the YAML. So this cannot run before `create()` — it
 * would be undone — and it has to accept a concrete `Monolog\Logger` rather
 * than a PSR-3 `LoggerInterface`, because that is what `setLogger()` is typed
 * for. Symfony's own `monolog.logger.<channel>` services are
 * `Symfony\Bridge\Monolog\Logger`, which extends `Monolog\Logger`, so the
 * container can satisfy it; an application using a non-Monolog PSR-3 logger
 * gets `mode: off` and keeps the library's own handlers.
 *
 * Those log lines are the audit trail — "who was blocked, by which rule,
 * when" exists nowhere else — so which handler set wins is a decision worth
 * making explicitly rather than defaulting into.
 */
final class LoggerBridge
{
    /**
     * The library keeps one logger for the whole process, so bridging is
     * idempotent per process and doing it twice under `merge` would attach
     * every handler twice — duplicating every line in the audit trail.
     */
    private bool $applied = false;

    /**
     * @param string $mode
     *   `replace`, `merge` or `off`. See Configuration::loggingNode().
     * @param Logger|null $logger
     *   The application's Monolog channel, or NULL when MonologBundle is not
     *   installed — in which case there is nothing to bridge to and every
     *   mode behaves as `off`.
     */
    public function __construct(
        private readonly string $mode,
        private readonly ?Logger $logger = null
    ) {
    }

    /**
     * Install the bridge. Call immediately after `Firewall::create()`.
     */
    public function apply(): void
    {
        if ($this->applied || $this->mode === 'off' || !$this->logger instanceof Logger) {
            return;
        }

        $this->applied = true;

        if ($this->mode === 'replace') {
            // The application's handlers, formatters and processors wholesale,
            // which also means the profiler's log panel and whatever channel
            // routing monolog.yaml already describes. The cost is that the
            // library's own `logger:` block stops taking effect — including a
            // DatabaseHandler someone configured as their retained audit
            // trail. That is why `merge` exists.
            LoggingFactory::setLogger($this->logger);

            return;
        }

        // merge: keep the library's logger — and therefore its DatabaseHandler,
        // its retention and its channel name — and add the application's
        // handlers to it. Handlers are shared instances, not copies, so a
        // FingersCrossedHandler's buffer is shared with the rest of the
        // application. That is the intent: one buffer, one flush, one story
        // about the request.
        $libraryLogger = LoggingFactory::logger();

        foreach ($this->logger->getHandlers() as $handler) {
            $libraryLogger->pushHandler($handler);
        }
    }
}
