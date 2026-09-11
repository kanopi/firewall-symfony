<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Fixtures;

use PHPUnit\Framework\Assert;

/**
 * Answers the math interstitial the way a visitor would.
 *
 * The provider signs `answer|expiry` into a hidden field and prints the sum
 * in the page, so a valid solution cannot be constructed — it has to be read
 * out of a real rendered challenge. Which makes this the only way to test
 * the round trip end to end, and the reason it is shared rather than written
 * twice.
 */
final class MathChallengeSolver
{
    /**
     * The form fields that solve a rendered interstitial.
     *
     * @return array<string, string>
     *   Ready to POST to `challenge.path`.
     */
    public static function solve(string $interstitial): array
    {
        if (preg_match('/(\d+)\s*\+\s*(\d+)/', $interstitial, $sum) !== 1) {
            Assert::fail('the math interstitial should print the sum it is asking about');
        }

        $fields = ['challenge_answer' => (string) ((int) $sum[1] + (int) $sum[2])];

        // Carried straight back: the signed state is what makes the answer
        // verifiable, and the redirect and ttl are what the firewall reads
        // to decide where to send the visitor and for how long.
        foreach (['challenge_state', 'redirect_to', 'ttl'] as $field) {
            if (preg_match('/name="' . $field . '"\s+value="([^"]*)"/', $interstitial, $match) === 1) {
                $fields[$field] = $match[1];
            }
        }

        return $fields;
    }
}
