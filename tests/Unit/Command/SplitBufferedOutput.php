<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * A `ConsoleOutputInterface` whose two streams can be read separately.
 *
 * Symfony ships `ConsoleOutput`, which writes to the real terminal, and
 * `BufferedOutput`, which has only one stream. Asserting that a child's
 * stderr stays out of its stdout needs both properties at once.
 */
final class SplitBufferedOutput extends BufferedOutput implements ConsoleOutputInterface
{
    private BufferedOutput $errorOutput;

    public function __construct()
    {
        parent::__construct();

        $this->errorOutput = new BufferedOutput();
    }

    /**
     * {@inheritdoc}
     */
    public function getErrorOutput(): BufferedOutput
    {
        return $this->errorOutput;
    }

    /**
     * {@inheritdoc}
     */
    public function setErrorOutput(OutputInterface $error): void
    {
        if ($error instanceof BufferedOutput) {
            $this->errorOutput = $error;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function section(): \Symfony\Component\Console\Output\ConsoleSectionOutput
    {
        throw new \LogicException('The test output has no sections.');
    }
}
