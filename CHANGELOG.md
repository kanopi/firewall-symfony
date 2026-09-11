# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

- `kanopi:firewall:block` is now the command that blocks one address, and the wrapper
  around `bin/firewall-block` — which lists, finds, shows and lifts — is
  `kanopi:firewall:blocks`. The singular and the plural do opposite things, and overloading
  one name with both would make the destructive reading of a bare typo the easy one to
  reach. It is also the split the Laravel package and the Drush commands make, so the three
  integrations can be documented once.

### Fixed

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

[Unreleased]: https://github.com/kanopi/firewall-symfony/compare/main...HEAD
