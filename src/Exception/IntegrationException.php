<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Exception;

use Kanopi\Firewall\Exception\FirewallException;

/**
 * A problem with the bundle itself, rather than with the firewall.
 *
 * Extends the library's own base exception rather than `\RuntimeException`,
 * so an application that already catches `FirewallException` — which the
 * library's documentation says is always safe to catch — keeps catching
 * everything the firewall can throw, including the parts added here. A
 * separate hierarchy would have meant every integrator's existing catch
 * block silently stopped being exhaustive the day they installed this
 * bundle.
 *
 * Thrown for the cases the library cannot see: an address that cannot be
 * blocked because storage keys are exact, a backend that cannot be
 * enumerated, or a write the backend refused.
 */
final class IntegrationException extends FirewallException
{
}
