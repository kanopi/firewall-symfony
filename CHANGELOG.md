# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A challenge page could be cached at the edge and loop every visitor** (#18). In
  `mode: exception` the bundle writes every firewall response itself, and it sent
  `Cache-Control: no-store` alone on the interstitial, the redirects and the solved
  challenge, and `no-store, private` on a block. kanopi/firewall 2.34.1 found that Pantheon's
  Fastly-based Global CDN caches a response carrying only `no-store`. Every visitor to a
  challenged URL then got the same single-use ALTCHA challenge: the first to solve it got
  through, and everyone after was refused and sent back to the same cached page. Every
  response the bundle writes now sends the library's `NoStore::HEADERS`: `Cache-Control:
  private, no-store, no-cache, must-revalidate, max-age=0`, plus `Pragma`, `Expires`,
  `Surrogate-Control` and `CDN-Cache-Control`. Under `blocked_response: http_exception` they
  travel with the `HttpException`, so the application's error page carries them too.

### Changed

- `kanopi/firewall` requires `^2.36`, up from `^2.33` (#19). 2.34.1 for `NoStore`. The floor
  also makes sure every install has fixes that need nothing from the bundle: a solved
  challenge can no longer redirect off-site (2.35.0), the path every rule sees is normalised
  (2.35.0), ASN rules match (2.35.0), and a rate-limit key naming a field with a capital
  letter counts that field (2.33.2).

## [1.2.0] — 2026-09-27

### Added

- `kanopi_firewall.storage_file`: where FileStorage keeps the block list, resolved by the
  container, so `'%env(resolve:FIREWALL_STORAGE_FILE)%'` with
  `FIREWALL_STORAGE_FILE="%kernel.project_dir%/var/firewall/blocked.data"` in `.env` gives
  the web server and `bin/console` one absolute path (#15). It is applied as a config input
  rather than an override, so the native block commands read the file the site writes.
- `kanopi:firewall:init`, for file storage, adds that variable to `.env` inside Flex-style
  `###> kanopi/firewall-symfony ###` markers, creates `var/firewall/`, and sets
  `storage_file` in `config/packages/kanopi_firewall.yaml`, writing that file when there is
  none. Nothing already set is overwritten. `--no-env` writes the YAML alone.
- `kanopi:firewall:doctor` reports where the block list is. It errors on a
  `%kernel.project_dir%` value that reached the library unresolved, on a directory that
  doesn't exist (the firewall can't start) and on a path that isn't writable. It warns on
  the temp directory, on a relative path from Symfony configuration, and on FileStorage
  with no path at all.

### Fixed

- **An empty `FIREWALL_CHALLENGE_SECRET` replaced the secret `firewall.yml` set.**
  `challenge.secret`, `provider` and `audience` are written down only when set, but the
  extension can only check that at compile time, when `'%env(FIREWALL_CHALLENGE_SECRET)%'` is
  a placeholder. An environment that left the variable empty (what a committed `.env` does,
  following Symfony's own `APP_SECRET`) produced an override of `''`, and every challenge
  rule failed to start. An empty value for those three is now read as "not set" when the
  value is finally known.
- `kanopi:firewall:init --help` said the default output was `firewall.yml` in the current
  directory. It is `config/firewall.yml`.

## [1.1.0] — 2026-09-27

### Added

- `QUICKSTART.md`: from `composer require` to enforcing in eight steps — install, write a
  configuration, check it, observe for a week, tell it about the proxy, enforce, wire it into
  the deploy — plus what to do the day somebody says "I'm blocked".
- `kanopi:firewall:challenge` (`kfw:challenge`), wrapping kanopi/firewall 2.30.0's
  `bin/firewall-challenge`: inspect a pass, revoke one by token or by nonce, check a nonce,
  and restore it. Before this, withdrawing one pass on a Symfony site meant running the vendor
  script by hand against a configuration that lacked the secret, or rotating
  `challenge.secret` and re-challenging everyone. Exactly one action is required, and checked
  before the effective configuration — secret included — is written to a temporary file.
- The profiler panel reports tarpit decisions (kanopi/firewall 2.30.0): `tarpitted` when
  the request was held, `tarpit full` when the cap was reached and it was served at once,
  plus the seconds held, the holds in flight, and the rule that asked.

### Fixed

- **Every firewall log line was discarded.** `logging.mode: replace` — the default — wired
  the bridge to `service('monolog.logger.%kanopi_firewall.logging.channel%')`, and a
  parameter placeholder inside a *service id* is not resolved before invalid references are
  pruned. The reference matched nothing, `nullOnInvalid()` did as it was asked, and the
  compiled container read `new LoggerBridge('replace', NULL)`. `apply()` returns early
  without a logger, so the library kept its own handler-less one: no audit trail under
  `enforce`, and nothing at all under `observe`, whose only output is the log. The bundle
  reported `logging.mode: replace` throughout and `kanopi:firewall:doctor` agreed.

  The extension now builds the reference with the channel already interpolated. Three tests
  cover it, all of which fail against the old wiring — including one that follows a real
  blocked request into a real Monolog handler, which is the assertion this suite never had.
  Found by writing QUICKSTART.md and checking that its "read the log" step actually works.
- **The profiler said "allowed" for every marked, recorded and tarpitted request** (#9).
  Those three are non-terminal: the library announces them and carries on, and a request
  nothing else matches ends in a default `RequestAllowed`. The decision recorder kept only
  the last event, so the default allow replaced the decision that mattered. Every panel test
  recorded a single event by hand, so nothing failed. The recorder now keeps every decision
  and looks past a trailing default allow. The mark and the hold survive a block that follows
  them, so a slow block shows both.
- Those same three no longer read as "(observed only)" in enforce mode. `isEnforced()` is
  always false for them because nothing was refused, and the panel took that to mean
  observe mode. A tarpit in observe mode now reads `tarpitted (observed only)` rather than
  `tarpit full`.
- A tarpitted request no longer reads as "not evaluated" in the profiler. The decision
  recorder subscribes by class, and `RequestTarpitted` was not on its list.
- **The native block commands answered with confidence they did not have** (#4). A block
  list that searches from an index of its own — kanopi/firewall 2.33.0's `MemcachedStorage`
  — can lose part of that index and keep the records, and says so through
  `BlockList::backend()['gap']`. `bin/firewall-block` warned; the bundle's commands did not.
  `kanopi:firewall:unblock` with a range or `--all` now warns that what it lifted or counted
  may not be everything and that the rest is still in force, and no longer says "already
  empty" or "nothing matches" when it cannot know. `kanopi:firewall:find-reference` warns
  that a miss may be a block still in force. `kanopi:firewall:status` gains
  `blocks_may_be_incomplete`, NULL when the count is complete. One address is now lifted by
  key when the index has a gap, which cannot miss.
- `kanopi:firewall:doctor` no longer reports "Nothing says whether this is behind a proxy"
  when the proxies are named in the firewall's own YAML. kanopi/firewall 2.33.0 accepts
  `global.trusted_proxies` there and counts it as an answer, so the doctor does too, and says
  what it means in Symfony: the library applies them for the firewall's own reads only, so
  controllers, logs and the profiler still see the proxy, and `framework.trusted_proxies` is
  the setting that answers for the whole application. When both are set it warns that
  `global.trusted_proxies` is ignored, because the library uses the host's proxies and a
  list that looks like it does something invites the next CDN range to be added there.

### Changed

- `kanopi/firewall` requires `^2.33`, up from `^2.26`: 2.30 for the tarpit event, 2.33 for
  the block list's `gap` and for `global.trusted_proxies`, which the doctor's proxy advice
  depends on — on an earlier release that key does nothing.

## [1.0.0] — 2026-09-12

### Added

- First release. `kanopi/firewall` as a Symfony bundle: a `kernel.request` listener at
  priority 250, a DI extension with semantic configuration under `kanopi_firewall`, fifteen
  `kanopi:firewall:*` commands, Monolog wiring, and a WebProfiler panel over the decision
  and the two health lists.
- Seven commands that answer without a subprocess, because there is no script to forward
  to: `status`, `health`, `rules`, `config`, `block`, `unblock` and `find-reference`. They
  close the gap against the Drush and Artisan integrations, which had them and this bundle
  did not. `block` and `unblock` are implemented against the library's public API —
  `bin/firewall-block` can list, find, show and lift, and cannot *add* — and `unblock` will
  lift one exact address even on a storage backend that cannot be enumerated, which neither
  the script nor the other integrations manage.
- `kanopi:firewall:doctor` now runs eleven checks of the Symfony wiring before the
  library's own, and fails on the worse of the two halves. Each one is a way for a
  perfectly healthy firewall to be doing nothing: a listener priority below the router, a
  route squatting the challenge path, an unasserted proxy posture, a configuration input
  that silently failed to load, in-memory storage, logging that is off. `--integration-only`
  needs no readable configuration, so it works on the deployment that is broken.
- `--format=table|json|yaml` on every command that renders its own output, matching what
  Drush gives its commands for free. A machine format prints the document and nothing else,
  so a probe never has to strip prose before decoding.
- A short `kfw:` alias for every command. `kanopi:firewall:` is 17 characters of prefix and
  an incident is not the moment to type it.
- Every wrapper declares the options its script actually takes, instead of accepting a
  free-form list after `--`. So `--help` describes the command, a mistyped option is
  rejected before it reaches the script and is ignored, and shell completion works. The
  passthrough survives as an escape hatch for an option added upstream.
- `kanopi_firewall.mode` with `enforce`, `observe` and `disabled`. The library's `block`
  mode is deliberately unreachable: it calls `exit()`, which inside a kernel skips
  `kernel.terminate` and, under a worker runtime, takes the worker with it.
- `behind_proxy: auto`, which asserts `global.behind_proxy` from the trusted proxies the
  kernel actually applied.
- `on_startup_failure`, making the library's documented fail-open / fail-closed choice
  explicit rather than implicit.
- A refusal to start when any rule sets `metadata.challenge_provider`, raised during
  `cache:clear`. The bundle has no supported way to sign the `provider_token` such a
  configuration needs, and serving the interstitial without it locks the visitor out
  permanently and silently. Tracked upstream as
  [kanopi/firewall#311](https://github.com/kanopi/firewall/issues/311).

- `bin/test-matrix` (`composer test:matrix`), which runs any CI matrix cell locally in the
  `cimg/php` image CI uses — same global Flex install, same line pinning, same checks in
  the same order. A machine has one PHP version and the matrix is five wide, so everything
  this package could get wrong across that axis was invisible until something else ran it.
  It found two failures on its first full pass, both below.

- Support for everything kanopi/firewall 2.26.0 added. `response: redirect` becomes a
  redirect response — the library throws `FirewallRedirectException` from `evaluate()` and
  does not declare it in `@throws`, so a host following the documented contract serves a
  500 where the rule meant to send somebody to a notice page. `response: record` and
  `response: mark` reach the profiler panel with their own verdicts, a marked request
  naming its mark and a redirected one its destination. Lockdown answers carry
  `Retry-After`, which is the header that stops a CDN treating a 503 as permanent and
  serving the refusal after the lockdown is lifted, and `kanopi:firewall:status` reports
  lockdown on its own line — it is a flag rather than a mode, so nothing that reports a
  mode shows it.

### Changed

- **Per-rule challenge providers are supported, and the refusal that stood in for them is
  gone.** `metadata.challenge_provider` used to make this bundle refuse to start at
  `cache:clear`: it rendered the interstitial itself and could not sign the
  `provider_token` that tells the submission handler which provider to verify against, so
  the alternative to refusing was a visitor solving a challenge, being rejected by the rule
  that set it, and being served the same page forever with nothing logged above `notice`.
  Reported as [kanopi/firewall#311](https://github.com/kanopi/firewall/issues/311), fixed
  in 2.26.0 by putting the provider and the signed render context on
  `ChallengeRequiredException`. Consuming it is one call, so `ChallengeRenderer`,
  `ChallengeConfigWarmer` and the refusal itself are all deleted — about 260 lines of
  workaround for one line of library.
- `kanopi/firewall` requires `^2.26`, up from `^2.24`.
- `kanopi:firewall:block` is now the command that blocks one address, and the wrapper
  around `bin/firewall-block` — which lists, finds, shows and lifts — is
  `kanopi:firewall:blocks`. The singular and the plural do opposite things, and overloading
  one name with both would make the destructive reading of a bare typo the easy one to
  reach. It is also the split the Laravel package and the Drush commands make, so the three
  integrations can be documented once.

### Fixed

- CI recorded no test results, and said nothing about it. `store_test_results` was pointed
  at `reports/`, so it parsed PHPUnit's 43 coverage XML files as JUnit and rejected every
  one of them — failing the upload step in all thirteen test jobs. CircleCI does not fail a
  job for that, so the first full run was green with an empty test-results tab. The JUnit
  file now has a directory to itself and the step points at that.
- The `--prefer-lowest` CI job could never have passed. `phpunit.xml` sets
  `displayDetailsOnPhpunitDeprecations`, which PHPUnit added in **10.5.32**, while the
  constraint allowed `^10.5` — so the floor job resolved 10.5.0, failed XML schema
  validation, and turned that into a test-runner warning that `failOnWarning` made fatal.
  The floor is now `^10.5.32`. Found by running the matrix in Docker; it had never run.
- PHPStan at max reported `$argv` as possibly undefined in the test fixture that stands in
  for a shipped `bin/` script — on PHP 8.5 only, so every job below that version passed.
  The fixture is excluded from analysis the way the package's other script-shaped fixture
  already is.
- The wrapped console commands diagnosed a configuration nobody runs. They were handed
  only `config_files`, so inline `settings` and every bundle-level override were invisible
  to them — and `kanopi:firewall:doctor` reported a fatal "challenge.secret is empty" for
  an application whose secret was in `kanopi_firewall.challenge.secret`, where the README
  says to put it. They now receive the effective configuration through short-lived 0600
  files. `kanopi:firewall:rule` still sees only real files, because it edits them.
- The trusted-proxy bridge read `kernel.trusted_proxies` while the container was built.
  FrameworkBundle's default for that parameter is the unresolvable string
  `%env(default::SYMFONY_TRUSTED_PROXIES)%`, so every application that had never
  configured a proxy was told it had one — silencing the exact warning the setting exists
  to raise. The posture is now resolved at runtime from `Request::getTrustedProxies()`,
  after the kernel has applied it.
- `mode: disabled` made the profiler panel build the firewall the listener deliberately
  skips, and report the mode it *would* have run in rather than "disabled".
- The `php -S` fixture server printed PHP diagnostics into its JSON body. At the Symfony
  8.1.0 floor a deprecation from `symfony/event-dispatcher-contracts` landed in front of
  the payload — and before `header()`, so a "headers already sent" warning followed it —
  and the test read a JSON syntax error instead of a verdict. It now suppresses display
  and logs instead; `display_errors = 'stderr'` is the obvious fix and is honoured by the
  `cli` SAPI, not by `cli-server`.

### Changed

- CI gained a Symfony axis. A PHP-only matrix let Composer resolve a mixed set —
  `http-kernel` at 7.4 with `console` at 8.1 — so the 8.x line was never exercised and
  the removal of `Console\Application::add()` in Symfony 8 went unnoticed. Each job now
  pins every `symfony/*` package to one line and asserts it before running. Each line
  also gets a `--prefer-lowest` job, so the 6.4.0 and 8.1.0 floors the constraint promises
  are actually exercised rather than assumed.
- `symfony/monolog-bundle` widened to `^3.10 || ^4.0`. The `^3.10` cap was what held the
  entire Symfony 8 line back, since 3.x requires `symfony/config ^6.4 || ^7.0`.
- `Configuration` builds its tree by holding a reference to each node instead of one long
  fluent chain. Symfony 6.4 types `NodeBuilder::end()` as `NodeParentInterface|null`, so
  the first `->end()` degraded the rest of the chain to `mixed` and PHPStan failed on that
  line — while analysing clean on 7.4 and 8.1, which is why nobody would have noticed
  without a Symfony axis in CI.

[Unreleased]: https://github.com/kanopi/firewall-symfony/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/kanopi/firewall-symfony/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/kanopi/firewall-symfony/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kanopi/firewall-symfony/releases/tag/v1.0.0
