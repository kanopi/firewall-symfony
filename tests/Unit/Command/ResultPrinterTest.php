<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Kanopi\FirewallBundle\Command\ResultPrinter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;

#[CoversClass(ResultPrinter::class)]
final class ResultPrinterTest extends TestCase
{
    public function testATableIsForAPersonAndNamesTheFieldsInWords(): void
    {
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_TABLE);

        $printer->properties(['library_version' => 'v2.24.0', 'enforcing' => true]);

        $display = $output->fetch();
        self::assertStringContainsString('Library version', $display, 'snake_case is humanized');
        self::assertStringContainsString('v2.24.0', $display);
        self::assertStringContainsString('yes', $display, 'a boolean reads as yes, not as 1');
    }

    public function testJsonKeepsTheKeysAScriptIsWrittenAgainst(): void
    {
        // The humanized labels are a rendering detail. A probe keying on
        // `"Library version"` would break the day a column was renamed, so
        // the machine formats carry the raw keys.
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_JSON);

        $printer->properties(['library_version' => 'v2.24.0', 'enforcing' => true]);

        self::assertSame(
            ['library_version' => 'v2.24.0', 'enforcing' => true],
            json_decode(trim($output->fetch()), true)
        );
    }

    public function testYamlIsTheOtherMachineFormat(): void
    {
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_YAML);

        $printer->properties(['mode' => 'enforce']);

        self::assertSame('mode: enforce', trim($output->fetch()));
    }

    public function testOnlyTheTableFormatIsForAPerson(): void
    {
        // What a command reads to decide whether its prose — the "lift it
        // with…" hint — would be a parse error to whatever is reading.
        self::assertFalse($this->printer(ResultPrinter::FORMAT_TABLE)[0]->isMachineReadable());
        self::assertTrue($this->printer(ResultPrinter::FORMAT_JSON)[0]->isMachineReadable());
        self::assertTrue($this->printer(ResultPrinter::FORMAT_YAML)[0]->isMachineReadable());
    }

    public function testRowsAreShownInTheDeclaredColumnOrderAndNothingElse(): void
    {
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_TABLE);

        $printer->table(
            ['name' => 'Name', 'response' => 'Response'],
            [['response' => 'block', 'name' => 'office', 'weight' => -100]]
        );

        $display = $output->fetch();
        self::assertStringContainsString('office', $display);
        self::assertStringContainsString('block', $display);
        self::assertStringNotContainsString('-100', $display, 'a field no column asked for stays out');
        self::assertLessThan(
            strpos($display, 'Response'),
            (int) strpos($display, 'Name'),
            'columns follow the declared order, not the row order'
        );
    }

    public function testAMissingFieldLeavesAnEmptyCellRatherThanShiftingTheRow(): void
    {
        // Without the fill, a row missing one field would render its
        // remaining values one column to the left — a table that reads
        // perfectly and is wrong.
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_TABLE);

        $printer->table(
            ['name' => 'Name', 'response' => 'Response', 'weight' => 'Weight'],
            [['name' => 'office', 'weight' => 5]]
        );

        self::assertMatchesRegularExpression('/office\s+\|?\s+\|?\s+5/', $output->fetch());
    }

    public function testRowsInAMachineFormatAreAListOfTheSelectedFields(): void
    {
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_JSON);

        $printer->table(
            ['name' => 'Name'],
            [['name' => 'office', 'weight' => -100], ['name' => 'xmlrpc', 'weight' => 0]]
        );

        self::assertSame(
            [['name' => 'office'], ['name' => 'xmlrpc']],
            json_decode(trim($output->fetch()), true)
        );
    }

    public function testAnEmptyListIsSaidRatherThanDrawn(): void
    {
        // An empty table reads as a rendering failure. "Nothing to list" is
        // a complete answer.
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_TABLE);

        $printer->table(['name' => 'Name'], []);

        self::assertStringContainsString('Nothing to list', $output->fetch());
    }

    public function testAnEmptyListStaysAnEmptyListForAScript(): void
    {
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_JSON);

        $printer->table(['name' => 'Name'], []);

        self::assertSame([], json_decode(trim($output->fetch()), true));
    }

    public function testDumpPrintsYamlWhenNobodyAskedForAMachineFormat(): void
    {
        // `kanopi:firewall:config`'s subject is a nested document. There is
        // no table that can hold one, and a flattened one would be a worse
        // YAML document than YAML.
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_TABLE);

        $printer->dump(['global' => ['mode' => 'exception']]);

        self::assertSame("global:\n  mode: exception", trim($output->fetch()));
    }

    public function testValuesThatAreNotStringsStillRenderAsCells(): void
    {
        [$printer, $output] = $this->printer(ResultPrinter::FORMAT_TABLE);

        $printer->properties([
            'off' => false,
            'nothing' => null,
            'list' => ['a', 'b'],
            'nested' => [['deep' => true]],
            'object' => new \stdClass(),
        ]);

        $display = $output->fetch();
        self::assertStringContainsString('no', $display);
        // One per line: Symfony sizes a column to its widest cell, and a
        // comma-joined list of config paths produced a table that wrapped.
        // Matched with a newline between them rather than on the cell text,
        // because the table pads every cell out to the column width.
        self::assertStringNotContainsString('a, b', $display);
        self::assertMatchesRegularExpression('/\ba\s+\n\s+b\b/', $display);
        self::assertStringContainsString('(not printable)', $display, 'an object says so rather than throwing');
    }

    /**
     * A printer and the buffer it writes to.
     *
     * @return array{0: ResultPrinter, 1: BufferedOutput}
     */
    private function printer(string $format): array
    {
        $output = new BufferedOutput();

        return [new ResultPrinter($format, new SymfonyStyle(new ArrayInput([]), $output)), $output];
    }
}
