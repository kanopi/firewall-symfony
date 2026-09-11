<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Firewall;

use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Utility\BlockList;
use Kanopi\FirewallBundle\Exception\IntegrationException;
use Kanopi\FirewallBundle\Firewall\BlockManager;
use Kanopi\FirewallBundle\Tests\Fixtures\OpaqueStorage;
use Kanopi\FirewallBundle\Tests\Fixtures\RefusingStorage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(BlockManager::class)]
final class BlockManagerTest extends TestCase
{
    public function testAnAddressGoesOnTheListAndComesBackOut(): void
    {
        $blocks = $this->manager();

        $result = $blocks->add('198.51.100.9', 600, 'Scraping /api');

        self::assertSame('198.51.100.9', $result['address']);
        self::assertFalse($result['replaced']);
        self::assertMatchesRegularExpression('/^[0-9A-F]{32}$/', $result['reference'], 'the shape the firewall generates');
        self::assertCount(1, $blocks->all());
    }

    public function testABlockWithNoDurationSaysSoRatherThanShowingADate(): void
    {
        // `0` is the library's "no expiry", not "expired at the epoch".
        self::assertSame('never', $this->manager()->add('198.51.100.9', 0)['expires']);
    }

    public function testANegativeDurationCannotOutliveTheEpoch(): void
    {
        self::assertSame('never', $this->manager()->add('198.51.100.9', -60)['expires']);
    }

    public function testThePayloadIsReadableFromEitherShapeTheLibraryReturns(): void
    {
        // `isBlocked()` returns the payload flat and `all()` returns it
        // wrapped under `value`. Same record, same backend. A caller should
        // not have to know which read produced what it is holding.
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600, 'Scraping /api');

        self::assertSame(
            $blocks->payloadValue($blocks->lookup('198.51.100.9'), 'reason'),
            $blocks->payloadValue($blocks->all()['198.51.100.9'], 'reason')
        );
        self::assertSame(
            $blocks->referenceOf($blocks->lookup('198.51.100.9')),
            $blocks->referenceOf($blocks->all()['198.51.100.9'])
        );
    }

    public function testTheReasonIsStoredAlongsideWhatTheFirewallItselfRecords(): void
    {
        // The payload is built by the backend so a hand-written record
        // carries the same keys as one a rule wrote; the note is added
        // afterwards because nothing in the library reads it.
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600, 'Scraping /api');

        $record = $blocks->lookup('198.51.100.9');

        self::assertSame('Scraping /api', $blocks->payloadValue($record, 'reason'));
        self::assertSame('kanopi:firewall:block', $blocks->payloadValue($record, 'blocked_by'));
    }

    public function testNoReasonMeansNoReasonFieldAtAll(): void
    {
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600);

        self::assertSame('', $blocks->payloadValue($blocks->lookup('198.51.100.9'), 'reason'));
    }

    public function testReBlockingIsRefusedRatherThanSilentlyKeepingTheOldExpiry(): void
    {
        // `set()` on an existing key replaces the payload and keeps the
        // original expiry, which is the opposite of what an operator typing
        // a longer --duration expects.
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 60);

        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/already blocked.*--force/s');

        $blocks->add('198.51.100.9', 86400);
    }

    public function testForcingLiftsTheOldBlockSoTheNewDurationApplies(): void
    {
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 60);

        $result = $blocks->add('198.51.100.9', 86400, 'longer', force: true);

        self::assertTrue($result['replaced']);
        self::assertCount(1, $blocks->all(), 'replaced, not duplicated');
    }

    public function testARangeIsRefusedWithTheRuleThatWouldHaveWorked(): void
    {
        // Storage keys are the client IP verbatim and `isBlocked()` is an
        // exact lookup, so a range would sit in the list looking
        // authoritative and match no visitor ever.
        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/is a range.*kanopi:firewall:rule add --ip=10\.0\.0\.0\/8/s');

        $this->manager()->add('10.0.0.0/8', 600);
    }

    #[DataProvider('provideNonAddresses')]
    public function testSomethingThatIsNotAnAddressIsRefused(string $input): void
    {
        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/is not a valid IP address/');

        $this->manager()->add($input, 600);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonAddresses(): iterable
    {
        yield 'empty' => [''];
        yield 'a hostname' => ['example.com'];
        yield 'a typo' => ['203.0.113.999'];
    }

    public function testABackendThatWillNotWriteIsReportedRatherThanReportedAsSuccess(): void
    {
        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/refused to record a block for 198\.51\.100\.9/');

        $this->manager(RefusingStorage::class)->add('198.51.100.9', 600);
    }

    public function testLiftingTakesARangeEvenThoughBlockingWillNot(): void
    {
        // Not an inconsistency: lifting matches against what is already
        // stored rather than creating a key.
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600);
        $blocks->add('198.51.100.10', 600);

        self::assertSame(2, $blocks->remove('198.51.100.0/24'));
        self::assertSame([], $blocks->all());
    }

    public function testADryRunCountsWhatWouldGoAndRemovesNothing(): void
    {
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600);

        self::assertSame(1, $blocks->remove('198.51.100.9', dryRun: true));
        self::assertCount(1, $blocks->all());
    }

    public function testNothingMatchingIsZeroRatherThanAnError(): void
    {
        self::assertSame(0, $this->manager()->remove('203.0.113.1'));
    }

    public function testClearingEmptiesTheList(): void
    {
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600);
        $blocks->add('198.51.100.10', 600);

        self::assertSame(2, $blocks->clear());
        self::assertSame([], $blocks->all());
    }

    public function testClearingCountsWithoutRemovingForADryRun(): void
    {
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600);

        self::assertSame(1, $blocks->clear(dryRun: true));
        self::assertCount(1, $blocks->all());
    }

    public function testClearingAnEmptyListIsNotAnError(): void
    {
        self::assertSame(0, $this->manager()->clear());
    }

    public function testAReferenceLeadsBackToTheAddressItWasIssuedFor(): void
    {
        // The only thing a support caller can read off the block page.
        $blocks = $this->manager();
        $reference = $blocks->add('198.51.100.9', 600)['reference'];

        $found = $blocks->findReference(strtolower($reference));

        self::assertNotNull($found);
        self::assertSame('198.51.100.9', $found['address']);
        self::assertSame($reference, $blocks->referenceOf($found['record']));
    }

    public function testAReferenceNobodyIssuedFindsNothing(): void
    {
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600);

        self::assertNull($blocks->findReference('0123456789ABCDEF0123456789ABCDEF'));
    }

    public function testAnEmptyReferenceIsNotSearchedFor(): void
    {
        // Otherwise it would match the first record with no `event_id`.
        self::assertNull($this->manager()->findReference('   '));
    }

    public function testAnAddressThatIsNotBlockedLooksUpAsNothing(): void
    {
        self::assertNull($this->manager()->lookup('203.0.113.1'));
    }

    public function testABackendThatCannotBeEnumeratedRefusesRatherThanAnsweringEmpty(): void
    {
        // "0 removed" and "not found" read as answers. They are not: they
        // are the backend being unable to look.
        $blocks = $this->manager(OpaqueStorage::class);

        $operations = [
            fn (): mixed => $blocks->all(),
            fn (): mixed => $blocks->clear(),
            fn (): mixed => $blocks->remove('198.51.100.0/24'),
            fn (): mixed => $blocks->findReference('0123456789ABCDEF0123456789ABCDEF'),
        ];

        foreach ($operations as $operation) {
            try {
                $operation();
                self::fail('the operation should have refused');
            } catch (IntegrationException $integrationException) {
                self::assertStringContainsString('cannot be queried', $integrationException->getMessage());
                self::assertStringContainsString(OpaqueStorage::class, $integrationException->getMessage());
            }
        }

        self::assertFalse($blocks->isQueryable());
    }

    public function testOneAddressCanStillBeLiftedOnABackendThatCannotBeListed(): void
    {
        // Enumeration is only needed to turn a pattern into keys. Deleting
        // one key is something every backend can do, so the narrowest and
        // most common lift is not taken away by an unusual backend.
        $blocks = $this->manager(OpaqueStorage::class);
        $blocks->add('198.51.100.9', 600);

        self::assertNotNull($blocks->lookup('198.51.100.9'));
        self::assertSame(1, $blocks->remove('198.51.100.9', dryRun: true));
        self::assertNotNull($blocks->lookup('198.51.100.9'), 'a dry run removes nothing');
        self::assertSame(1, $blocks->remove('198.51.100.9'));
        self::assertNull($blocks->lookup('198.51.100.9'));
    }

    public function testLiftingAnAddressThatIsNotThereIsZeroOnAnOpaqueBackendToo(): void
    {
        self::assertSame(0, $this->manager(OpaqueStorage::class)->remove('198.51.100.9'));
    }

    public function testABackendThatRefusesTheDeleteReportsNothingLifted(): void
    {
        // A read-only replica, or a user without DELETE. Reporting 1 here
        // would tell an operator a customer is back in when they are not.
        $blocks = $this->manager(OpaqueStorage::class, ['refuse_deletes' => true]);
        $blocks->add('198.51.100.9', 600);

        self::assertSame(0, $blocks->remove('198.51.100.9'));
        self::assertNotNull($blocks->lookup('198.51.100.9'));
    }

    public function testTheBackendIsNamedSoAMessageCanNameIt(): void
    {
        self::assertSame(InMemoryStorage::class, $this->manager()->backendClass());
        self::assertTrue($this->manager()->isQueryable());
    }

    public function testRecordFieldsAreReadFromWhereTheyActuallyLive(): void
    {
        // `expires_at` and `offenses` sit beside the payload rather than
        // inside it. A reader keyed on the wrong path reports nothing,
        // which is indistinguishable from a field that is not set.
        $blocks = $this->manager();
        $blocks->add('198.51.100.9', 600);
        $listed = $blocks->all()['198.51.100.9'];

        self::assertNotSame('', $blocks->recordValue($listed, 'expires_at'));
        self::assertSame('', $blocks->recordValue($listed, 'no_such_field'));
        // `isBlocked()` does not carry it, and the accessor says so rather
        // than inventing one.
        self::assertSame('', $blocks->recordValue($blocks->lookup('198.51.100.9'), 'expires_at'));
    }

    public function testARecordThatIsNotARecordIsNotProbedForFields(): void
    {
        // Reached through `find()` on a backend that returns something
        // unexpected. Reporting an empty string beats a TypeError in a
        // support command.
        $blocks = $this->manager();

        self::assertSame('', $blocks->referenceOf('not-a-record'));
        self::assertSame('', $blocks->payloadValue('not-a-record', 'reason'));
        self::assertSame('', $blocks->recordValue('not-a-record', 'expires_at'));
        self::assertSame('', $blocks->payloadValue(['value' => 'not-an-array'], 'reason'));
        self::assertSame('', $blocks->referenceOf(['value' => 'not-an-array']));
    }

    /**
     * A manager over a real BlockList, because that is where the contract
     * this class was written against lives.
     *
     * @param class-string $storage
     *   The backend to configure.
     * @param array<string, mixed> $storageConfig
     *   `storage.config`, for a fixture backend that reads a flag from it.
     */
    private function manager(string $storage = InMemoryStorage::class, array $storageConfig = []): BlockManager
    {
        return new BlockManager(new BlockList([[
            'global' => ['behind_proxy' => false],
            'storage' => ['type' => $storage, 'config' => $storageConfig],
            'logger' => ['handlers' => [['class' => 'Monolog\Handler\NullHandler']]],
            'plugins' => [],
        ]]));
    }
}
