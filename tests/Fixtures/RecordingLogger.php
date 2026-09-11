<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

use Psr\Log\AbstractLogger;

/**
 * A PSR-3 logger that keeps what it was told.
 *
 * psr/log 3 dropped `Psr\Log\Test\TestLogger`, and the two things these
 * tests ask of a logger — "was this said, at this level?" and "how many
 * times?" — are shorter to write than to mock.
 */
final class RecordingLogger extends AbstractLogger
{
    /**
     * @var array<int, array{level: string, message: string, context: array<string, mixed>}>
     */
    public array $records = [];

    /**
     * {@inheritdoc}
     *
     * @param array<string, mixed> $context
     */
    public function log($level, string|\Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => is_scalar($level) ? (string) $level : '',
            'message' => (string) $message,
            'context' => $context,
        ];
    }

    /**
     * Was something said at this level containing this text?
     */
    public function has(string $level, string $needle): bool
    {
        foreach ($this->records as $record) {
            if ($record['level'] === $level && str_contains($record['message'], $needle)) {
                return true;
            }
        }

        return false;
    }
}
