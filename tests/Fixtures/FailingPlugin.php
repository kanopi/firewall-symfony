<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A rule that cannot be built, the way a real one fails.
 *
 * The library logs a constructor that throws and skips the rule rather than
 * fatalling the request. For a `block` rule that is a fail-open, and a
 * firewall running one rule short looks exactly like a firewall running
 * correctly — which is the condition `kanopi:firewall:health` exists to
 * catch, and therefore the condition a test has to be able to produce.
 *
 * A real one throws because a Redis host is not answering or a storage path
 * lost its permissions. Neither is arrangeable in a unit test, so the
 * message says what it would have said.
 */
final class FailingPlugin implements PluginInterface
{
    /**
     * Declares no parameters, and is still called with two.
     *
     * The plugin manager constructs a rule as `new $class($config,
     * $metadata)`. PHP passes extra arguments to a user-defined constructor
     * without complaint, so the shorter signature is legal — and it is the
     * honest one here, because a constructor that throws on its first line
     * has no use for either.
     */
    public function __construct()
    {
        throw new \RuntimeException('redis at 10.0.0.1:6379 refused the connection');
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'never-built';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'A rule whose constructor throws, so the firewall runs without it.';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return 403;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(?Request $request = null): int
    {
        return 3600;
    }
}
