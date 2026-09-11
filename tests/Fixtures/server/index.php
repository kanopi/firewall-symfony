<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * A front controller for `php -S`, which reports PHP_SAPI as `cli-server`.
 *
 * This exists for one assertion the rest of the suite cannot make. PHPUnit
 * runs on the `cli` SAPI, and `Firewall::evaluate()` returns TRUE
 * immediately there for every mode but `exception` — so every `observe`
 * test in the suite passes on that short-circuit rather than on the
 * behaviour it names. A web SAPI is the only place `observe` can be shown
 * to actually evaluate anything.
 *
 * It answers with JSON describing what happened, so the test asserting on
 * it does not have to parse HTML.
 */

use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\Tests\Fixtures\TestKernel;
use Symfony\Component\HttpFoundation\Request;

// Nothing but JSON in the body, and diagnostics still visible.
//
// The built-in server has display_errors on, and at the dependency floor a
// third-party deprecation — `EventDispatcherInterface::dispatch()`'s
// implicitly nullable parameter under PHP 8.4 — printed itself in front of
// the JSON. It also arrived before `header()`, so the response then carried
// a "headers already sent" warning too. The notice is real and outside this
// package; a JSON endpoint emitting anything but JSON is the part that is
// ours.
//
// `display_errors = 'stderr'` is the obvious fix and does not work: that
// value is honoured by the `cli` SAPI, not by `cli-server`, which is the
// whole reason this fixture exists. Switching display off and logging
// instead does work, and under `cli-server` the log is stderr — which the
// Process running this server captures.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require dirname(__DIR__, 3) . '/vendor/autoload.php';
require dirname(__DIR__) . '/TestKernel.php';

$kernel = new TestKernel([
    'mode' => $_GET['mode'] ?? 'observe',
    'config_files' => [dirname(__DIR__) . '/config/block.yml'],
]);

$request = Request::createFromGlobals();
$request->server->set('REMOTE_ADDR', $_GET['ip'] ?? '203.0.113.5');

$response = $kernel->handle($request);
$kernel->boot();

/** @var DecisionRecorder $recorder */
$recorder = $kernel->getContainer()->get('test.service_container')->get('test.kanopi_firewall.decision_recorder');
$decision = $recorder->getDecision();

header('Content-Type: application/json');

echo json_encode([
    'sapi' => PHP_SAPI,
    'status' => $response->getStatusCode(),
    'body' => $response->getContent(),
    'decision' => $decision === null ? null : $decision::class,
    'enforced' => $decision?->isEnforced(),
], JSON_THROW_ON_ERROR);
