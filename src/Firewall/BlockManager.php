<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Firewall;

use Kanopi\Firewall\Utility\BlockList;
use Kanopi\FirewallBundle\Exception\IntegrationException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Block, unblock and look up clients from `bin/console`.
 *
 * The library's `bin/firewall-block` can list, find, show and lift — it
 * cannot *add*. That is deliberate upstream, where a block is something a
 * rule earns rather than something an operator writes. It is a gap all the
 * same the first time somebody is on the phone reading a reference number
 * off an error page, or a scraper needs stopping before a rule can be
 * written, reviewed and deployed.
 *
 * So these operations are implemented here rather than forwarded to a
 * script, against the library's public API: `BlockList` for reads and lifts,
 * `StorageInterface` for the write. Nothing reaches into internals, which is
 * why they can exist in this bundle at all.
 *
 * ## What was learned about the storage contract
 *
 * Two details decided the shape of this class and neither is guessable:
 *
 * - **`$expire` passed to `set()` is a duration in seconds, not a
 *   timestamp.** The backend adds `time()` itself, and `0` means "no
 *   expiry". Reading it as a timestamp would make every block either
 *   permanent or already expired.
 * - **`set()` on a key that already exists replaces the payload and keeps
 *   the original expiry.** So re-blocking an address cannot extend its ban,
 *   which is the opposite of what an operator typing a longer `--duration`
 *   expects. That is what `$force` is for: it deletes first, so the new
 *   duration actually applies.
 */
final class BlockManager
{
    /**
     * Where the firewall's own payload lives inside a listed record.
     *
     * `QueryableStorageInterface::find()` documents the payload as being
     * carried "alongside" `expire`, which reads as flat. It is not: the
     * payload is nested under `value`, with `expire`, `expires_at` and
     * `offenses` beside it. Established by writing a record and dumping what
     * came back, because a lookup keyed on the wrong path finds nothing and
     * reports "no such reference" — which is indistinguishable from a
     * reference that does not exist.
     *
     * **And the two reads disagree.** `isBlocked()` returns the payload
     * *flat* — `event_id` and `reason` at the top level, no `value`, no
     * `expires_at` — while `find()` and `all()` return it wrapped. Same
     * record, same backend, two shapes, and nothing in the interface says
     * so. Found the same way: a test that read a reason written through
     * `add()` and looked it up through `lookup()` got an empty string. So
     * the accessors below take either shape rather than the caller having to
     * know which read produced the record it is holding.
     */
    private const PAYLOAD = 'value';

    public function __construct(private readonly BlockList $blockList)
    {
    }

    /**
     * Put a client on the block list.
     *
     * @param string $ip
     *   A single address. **Not a CIDR range**: storage keys are the client
     *   IP verbatim and `isBlocked()` is an exact key lookup, so a range
     *   written here would sit in the list looking authoritative and match
     *   no visitor ever. Ranges belong in an `IpAddress` rule, which is
     *   evaluated rather than looked up.
     * @param int $duration
     *   Seconds until it lapses. `0` never lapses.
     * @param string $reason
     *   A note stored with the record, for whoever reads the list next.
     * @param bool $force
     *   Replace an existing block, so a new duration applies.
     *
     * @return array{address: string, expires: string, reference: string, replaced: bool}
     *   What was written.
     *
     * @throws IntegrationException
     *   When the address is not a single valid IP, when the backend cannot
     *   store it, or when a block already exists and $force is FALSE.
     */
    public function add(string $ip, int $duration, string $reason = '', bool $force = false): array
    {
        $address = $this->validateAddress($ip);
        $storage = $this->blockList->storage();
        $existing = $storage->isBlocked($address) !== false;

        if ($existing && !$force) {
            throw new IntegrationException(sprintf(
                '%s is already blocked. Re-blocking would replace the reason and keep the '
                . 'original expiry, because that is what the storage backend does — pass '
                . '--force to lift it and apply the new duration, or run '
                . 'kanopi:firewall:unblock %s first.',
                $address,
                $address
            ));
        }

        if ($existing) {
            $storage->delete($address);
        }

        $request = $this->requestFor($address);
        $reference = $this->generateReference();
        $request->attributes->set('x-request-id', $reference);

        // Built by the backend rather than assembled here, so a record
        // written by hand carries the same keys as one written by a rule and
        // `kanopi:firewall:blocks` renders both identically. The note is
        // added afterwards: it is this bundle's, and nothing in the library
        // reads it.
        $payload = $storage->getStorageData($request, null);
        $payload['blocked_by'] = 'kanopi:firewall:block';

        if ($reason !== '') {
            $payload['reason'] = $reason;
        }

        if (!$storage->set($address, $payload, max(0, $duration))) {
            throw new IntegrationException(sprintf(
                'The storage backend (%s) refused to record a block for %s.',
                $this->backendClass(),
                $address
            ));
        }

        return [
            'address' => $address,
            'expires' => $duration > 0 ? date('c', time() + $duration) : 'never',
            'reference' => $reference,
            'replaced' => $existing,
        ];
    }

    /**
     * Lift every block matching an address or CIDR range.
     *
     * Ranges are fine here, unlike in `add()`: lifting matches against
     * stored addresses rather than creating a key, so `10.0.0.0/8` means
     * "everything in the list that falls inside this range".
     *
     * @param string $pattern
     *   An address or CIDR range.
     * @param bool $dryRun
     *   TRUE counts matches and removes nothing.
     *
     * @return int
     *   How many records went, or would have gone for a dry run.
     *
     * @throws IntegrationException
     *   When the backend cannot be enumerated.
     */
    public function remove(string $pattern, bool $dryRun = false): int
    {
        // One exact address is deletable by key, and every backend can
        // delete by key — enumeration is only needed to turn a pattern into
        // keys. So the narrowest, most common lift works even on a backend
        // that cannot be listed, which is more than either the shipped
        // script or the other integrations manage.
        if (!$this->isQueryable()) {
            return $this->removeExact(trim($pattern), $dryRun);
        }

        if ($dryRun) {
            return count($this->blockList->find($pattern));
        }

        return $this->blockList->lift([$pattern]);
    }

    /**
     * Lift one address by key, for a backend that cannot be enumerated.
     *
     * @param string $address
     *   The address, already trimmed.
     * @param bool $dryRun
     *   TRUE reports what would go without removing it.
     *
     * @return int
     *   1 when the address was blocked, 0 when it was not.
     *
     * @throws IntegrationException
     *   When what was given is a pattern rather than one address, because
     *   resolving a pattern to keys is exactly what this backend cannot do.
     */
    private function removeExact(string $address, bool $dryRun): int
    {
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            $this->assertQueryable();
        }

        if ($this->lookup($address) === null) {
            return 0;
        }

        if ($dryRun) {
            return 1;
        }

        return $this->blockList->storage()->delete($address) ? 1 : 0;
    }

    /**
     * Empty the block list.
     *
     * Implemented as a lift of everything the list reports rather than
     * `StorageInterface::reset()`, which also discards offense history — and
     * that history is what drives escalating bans. An operator clearing
     * blocks after a false positive wants the slate clean, not the
     * escalation ladder reset for every address that has ever misbehaved.
     *
     * @param bool $dryRun
     *   TRUE counts what is listed and removes nothing.
     *
     * @return int
     *   How many records went, or would have gone for a dry run.
     *
     * @throws IntegrationException
     *   When the backend cannot be enumerated.
     */
    public function clear(bool $dryRun = false): int
    {
        $this->assertQueryable();

        $addresses = array_keys($this->blockList->all());

        if ($addresses === [] || $dryRun) {
            return count($addresses);
        }

        return $this->blockList->lift(array_map(strval(...), $addresses));
    }

    /**
     * Find the block a reference number belongs to.
     *
     * The reference is the `event_id` the firewall shows a blocked visitor —
     * the hex string in its banning message. It is what a support caller can
     * read out, and nothing indexes it: it appears on the page and in the
     * logs, so answering "why is this customer blocked?" otherwise means
     * grepping logs and hoping the retention window reaches back far enough.
     *
     * Matched case-insensitively because the firewall renders it uppercase
     * and people retype it however they like.
     *
     * The scan is linear over the whole list, which is the right trade here.
     * The alternative is a second index to keep in step with the library's
     * own storage — more moving parts, and an index that disagrees with the
     * list is worse than a scan. A list large enough for this to hurt has a
     * bigger problem than a slow lookup.
     *
     * @param string $reference
     *   The reference to look for.
     *
     * @return array{address: string, record: array<string, mixed>}|null
     *   NULL when no block carries that reference, which includes the
     *   ordinary case of a reference whose block has since lapsed.
     *
     * @throws IntegrationException
     *   When the backend cannot be enumerated, so a miss would only mean
     *   "could not look".
     */
    public function findReference(string $reference): ?array
    {
        $this->assertQueryable();

        $needle = strtoupper(trim($reference));

        if ($needle === '') {
            return null;
        }

        foreach ($this->blockList->all() as $address => $record) {
            if ($this->referenceOf($record) === $needle) {
                /** @var array<string, mixed> $record */
                return ['address' => (string) $address, 'record' => $record];
            }
        }

        return null;
    }

    /**
     * Every block currently in force, keyed by address.
     *
     * @return array<array-key, mixed>
     *   As the block list reported it.
     *
     * @throws IntegrationException
     *   When the backend cannot be enumerated.
     */
    public function all(): array
    {
        $this->assertQueryable();

        return $this->blockList->all();
    }

    /**
     * One record, by address, or NULL when that address is not blocked.
     *
     * Goes to `isBlocked()` rather than the list, so it answers for a
     * backend that cannot be enumerated as well as one that can — which is
     * the whole point of having it beside `all()`.
     *
     * @param string $ip
     *   The address to look up.
     *
     * @return array<array-key, mixed>|null
     *   The stored record, or NULL. Typed as loosely as the library types
     *   `isBlocked()`, which is the only honest thing to say about it: the
     *   payload is whatever the backend stored, and the accessors on this
     *   class are how it should be read.
     *
     * @throws IntegrationException
     *   When the address is not a single valid IP.
     */
    public function lookup(string $ip): ?array
    {
        $address = $this->validateAddress($ip);
        $record = $this->blockList->storage()->isBlocked($address);

        return $record === false ? null : $record;
    }

    /**
     * The reference stored on a record, uppercased, or an empty string.
     *
     * @param mixed $record
     *   A record as the block list reported it.
     */
    public function referenceOf(mixed $record): string
    {
        $reference = $this->payload($record)['event_id'] ?? null;

        return is_string($reference) ? strtoupper($reference) : '';
    }

    /**
     * One field from a record's payload, as a string.
     *
     * @param mixed $record
     *   A record as the block list reported it.
     * @param string $key
     *   The payload key to read.
     */
    public function payloadValue(mixed $record, string $key): string
    {
        $value = $this->payload($record)[$key] ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * The firewall's payload, from a record of either shape.
     *
     * @param mixed $record
     *   A record as `all()`, `find()` or `lookup()` reported it.
     *
     * @return array<array-key, mixed>
     *   The payload, or an empty array for anything that is not a record.
     */
    private function payload(mixed $record): array
    {
        if (!is_array($record)) {
            return [];
        }

        $nested = $record[self::PAYLOAD] ?? null;

        // Wrapped by `find()` and `all()`, flat from `isBlocked()`. Falling
        // back to the record itself rather than to nothing, because the flat
        // shape *is* the payload.
        return is_array($nested) ? $nested : $record;
    }

    /**
     * One top-level field from a record, as a string.
     *
     * `expires_at` and `offenses` sit beside the payload rather than inside
     * it, so they are read with this rather than `payloadValue()`.
     *
     * @param mixed $record
     *   A record as the block list reported it.
     * @param string $key
     *   The record key to read.
     */
    public function recordValue(mixed $record, string $key): string
    {
        if (!is_array($record)) {
            return '';
        }

        $value = $record[$key] ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * The class actually storing blocks, for a message that names it.
     */
    public function backendClass(): string
    {
        // Indexed without a fallback: `BlockList::backend()` declares a
        // fixed shape, so a `??` here would be a branch nothing can reach.
        return $this->blockList->backend()['class'];
    }

    /**
     * Can the configured backend be enumerated and searched?
     */
    public function isQueryable(): bool
    {
        return $this->blockList->backend()['queryable'];
    }

    /**
     * Refuse the operations that need a backend able to answer questions.
     *
     * A backend that is not queryable returns an empty list from every read
     * — so a lift would report "0 removed" and a lookup "no such
     * reference", both of which read as an answer rather than as an
     * inability to answer.
     *
     * @throws IntegrationException
     *   When the backend cannot be enumerated.
     */
    private function assertQueryable(): void
    {
        if ($this->isQueryable()) {
            return;
        }

        throw new IntegrationException(sprintf(
            'The configured storage backend (%s) cannot be queried, so blocks cannot be '
            . 'listed, searched or lifted from the command line. Use FileStorage, '
            . 'DatabaseStorage or RedisStorage. One address can still be checked with '
            . 'kanopi:firewall:blocks --show=ADDRESS.',
            $this->backendClass()
        ));
    }

    /**
     * @param string $ip
     *   The address as typed.
     *
     * @return string
     *   The same address, trimmed.
     *
     * @throws IntegrationException
     *   When it is not a single valid IP.
     */
    private function validateAddress(string $ip): string
    {
        $address = trim($ip);

        if (filter_var($address, FILTER_VALIDATE_IP) !== false) {
            return $address;
        }

        throw new IntegrationException(sprintf(
            str_contains($address, '/')
                ? '"%s" is a range, and a block is stored under one exact address — a range '
                    . 'here would never match a visitor. Put ranges in an IpAddress rule '
                    . '(bin/console kanopi:firewall:rule add --ip=%s), which is evaluated '
                    . 'rather than looked up.'
                : '"%s" is not a valid IP address.',
            $address,
            $address
        ));
    }

    /**
     * A request carrying the address, for the backend to derive a key from.
     *
     * `getKey()` returns `$request->getClientIp()` verbatim, so REMOTE_ADDR
     * is all this needs. No forwarded headers are set, so trusted-proxy
     * configuration cannot affect what gets keyed — which matters, because
     * an operator blocking an address must get that address and not one
     * derived from a header.
     */
    private function requestFor(string $address): Request
    {
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $address]);
    }

    /**
     * A reference in the same shape the firewall generates.
     *
     * 16 random bytes, hex, uppercase — matching `Firewall::generateId()`,
     * so a reference from a hand-written block is indistinguishable in form
     * from one the firewall issued and can be looked up the same way.
     */
    private function generateReference(): string
    {
        return strtoupper(bin2hex(random_bytes(16)));
    }
}
