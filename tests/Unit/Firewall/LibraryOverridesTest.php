<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\FirewallBundle\Firewall\LibraryOverrides;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(LibraryOverrides::class)]
final class LibraryOverridesTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideNothing(): iterable
    {
        foreach (LibraryOverrides::CONDITIONAL as $key) {
            yield $key . ' empty' => [$key, ''];
            yield $key . ' null' => [$key, null];
        }
    }

    #[DataProvider('provideNothing')]
    public function testAConditionalOverrideThatResolvedToNothingIsNotSet(string $key, mixed $value): void
    {
        self::assertSame(['[global][mode]' => 'exception'], LibraryOverrides::resolved([
            '[global][mode]' => 'exception',
            $key => $value,
        ]));
    }

    public function testAConditionalOverrideWithAValueIsKept(): void
    {
        $overrides = ['[challenge][secret]' => 's3cret', '[challenge][provider]' => 'altcha', '[challenge][audience]' => 'admin'];

        self::assertSame($overrides, LibraryOverrides::resolved($overrides));
    }

    public function testAnEmptyValueElsewhereIsAnAnswerAndIsKept(): void
    {
        // `cookie_name: ''` disables cookie delivery. Empty is meaningful
        // there, so only the three conditional keys are read as unset.
        $overrides = ['[challenge][cookie_name]' => '', '[global][banning_message]' => ''];

        self::assertSame($overrides, LibraryOverrides::resolved($overrides));
    }
}
