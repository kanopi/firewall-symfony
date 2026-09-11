# kanopi/firewall-symfony

A Symfony bundle for [`kanopi/firewall`](https://github.com/kanopi/firewall). It evaluates
every request in a `kernel.request` listener and turns the verdict into a `Response`.

> **This is not `security.firewalls`.**
> SecurityBundle has owned the word "firewall" since Symfony 2, and there it means an
> *authentication zone* — a pattern, a user provider, a set of authenticators. This bundle
> refuses hostile traffic: bad IPs, bad user agents, request floods, CRS signature matches.
> Two unrelated things called the same thing in one `config/packages/` directory is a trap
> that springs at the worst possible moment, so everything here is vendor-qualified:
> the config root is `kanopi_firewall`, every service id starts `kanopi_firewall.`, and the
> commands live under `kanopi:firewall:`, each with a short `kfw:` alias.

## Why a bundle rather than three lines in `public/index.php`

The library's own docs suggest calling `Firewall::create([...])->evaluate()` from the front
controller, before the kernel boots. That works, and it has two problems a bundle exists to
fix.

**Trusted proxies are not applied yet.** `Kernel::preBoot()` is what calls
`Request::setTrustedProxies()` from your `framework.trusted_proxies`. Anything running
before the kernel boots reads an unfiltered `getClientIp()` — so behind a CDN every visitor
arrives as the CDN, every IP allowlist matches nobody, and every per-IP rate limit counts
the whole internet into one bucket. A `kernel.request` listener runs strictly after
`preBoot()`, so this cannot happen.

**`evaluate()` calls `exit()`.** In the library's default `block` mode it writes its own
response and exits. Inside a kernel that skips `kernel.terminate`, abandons whatever the
runtime was going to flush, and under a worker runtime takes the worker down with it. The
bundle forces the library into `exception` mode and translates what it throws — and there
is no configuration that turns that off, because `kanopi_firewall.mode` does not offer
`block` as a value.

## Installation

```bash
composer require kanopi/firewall-symfony
```

Without Symfony Flex, register the bundle:

```php
// config/bundles.php
return [
    // …
    Kanopi\FirewallBundle\KanopiFirewallBundle::class => ['all' => true],
];
```

Point it at the `firewall.yml` you already have:

```yaml
# config/packages/kanopi_firewall.yaml
kanopi_firewall:
    config_files:
        - '%kernel.project_dir%/config/firewall.yml'
```

That is the whole minimum. Everything below has a working default.

> **Paths inside `firewall.yml` are not Symfony parameters.** That file is parsed by the
> library, which has never heard of `%kernel.project_dir%` — write it there and you get a
> literal directory with a `%` in its name. Relative paths work and resolve against the
> file's own directory, so `storage_file: ../var/firewall/blocked.data` from
> `config/firewall.yml` is the idiomatic form. Symfony parameters *do* resolve in
> `config_files`, `settings` and `overrides`, because those are Symfony configuration.

Nothing to write yet? `bin/console kanopi:firewall:init --platform=drupal --mode=log`
writes a starter file.

## Modes

`kanopi_firewall.mode` has three values, and none of them can `exit()`.

| Mode | Library mode | What happens |
|---|---|---|
| `enforce` *(default)* | `exception` | A matched request is refused. |
| `observe` | `log` | Everything is evaluated and logged; nothing is refused, nothing is written to storage, nobody is banned. |
| `disabled` | — | The listener returns immediately and the firewall is never built. |

`observe` maps to the library's own `log` mode rather than to "run `enforce` and swallow
the exception", because those are not the same thing: in `exception` mode the library calls
`block()` *before* it throws, which records the offense and applies `blocking_escalation`.
A dry-run built that way would quietly ban the addresses it was only supposed to watch.

**`observe` evaluates nothing on a CLI SAPI.** `Firewall::evaluate()` returns `true`
immediately when `PHP_SAPI === 'cli'` for every mode but `exception`. That is right for
Drush and cron and wrong for RoadRunner and Swoole, which serve HTTP from the `cli` SAPI.
The bundle cannot fix it from outside the library, so it says so once per process at
`warning` level. `enforce` is unaffected. (`php -S`, PHP-FPM, mod_php and FrankenPHP's
non-worker mode all report something other than `cli` and are fine.)

## Configuration reference

```yaml
kanopi_firewall:
    # enforce | observe | disabled
    mode: enforce

    # Existing kanopi/firewall YAML, merged in order.
    config_files:
        - '%kernel.project_dir%/config/firewall.yml'

    # An inline library configuration array, merged after config_files.
    # Passed through verbatim — this bundle does not re-declare the library's
    # plugin schema, so anything the library understands works here.
    settings: {}

    # PropertyAccess bracket paths, applied last.
    # [global][mode] is reserved; use kanopi_firewall.mode.
    overrides:
        '[global][banning_status_code]': 403

    # auto | true | false. See "Trusted proxies" below.
    behind_proxy: auto

    # fail_closed | fail_open. What to do when Firewall::create() throws.
    on_startup_failure: fail_closed

    # plain | http_exception. See "The blocked response" below.
    blocked_response: plain

    listener:
        priority: 250
        only_main_requests: true

    challenge:
        secret: '%env(FIREWALL_CHALLENGE_SECRET)%'
        provider: math
        path: /_firewall/challenge
        cookie_name: fw_challenge_pass
        header_name: X-Firewall-Challenge
        audience: ~
        provider_options: {}
        cookie:
            path: /
            domain: ~
            secure: true
            http_only: true
            same_site: strict

    logging:
        # replace | merge | off
        mode: replace
        channel: kanopi_firewall

    profiler:
        # auto follows %kernel.debug%
        enabled: auto
        collect_health: true

    commands:
        enabled: true
        bin_dir: ~        # defaults to %kernel.project_dir%/vendor/bin
        timeout: 300.0
```

`secret`, `provider` and `audience` default to `~`, which leaves whatever your
`firewall.yml` already sets. `path`, `cookie_name` and `header_name` are always written
down into the library configuration, because the listener and the response factory hold
them as plain strings and that is only safe if the library cannot be reading different
ones.

`config_files` and `settings` are two inputs to one merge, not alternatives. Files come
first, then `settings`, then `overrides` — so an environment-specific
`config/packages/prod/kanopi_firewall.yaml` can adjust a shared `firewall.yml` without
copying it.

## Listener priority

Default **250**, on `kernel.request`. Relative to what Symfony registers on the same event:

| Priority | Listener | Why we sit where we do |
|---|---|---|
| 256 | `ValidateRequestListener` | A malformed `Host` is the framework's to reject. |
| **250** | **this bundle** | |
| 128 | `SessionListener` | A blocked bot starts no session. |
| 32 | `RouterListener` | See below. |
| 8 | Security's `Firewall` | No authentication for traffic that is not getting through. |

Running above `RouterListener` is not a preference, it is the fix for a lockout. The
challenge submission path is deliberately **not a route**. If the router got there first it
would 404 the POST before this listener saw it, and a challenged visitor would be served
the interstitial forever with nothing anywhere saying why. Priority alone guarantees it: no
route to register, nothing to exclude from your routing.

If you lower `listener.priority` below 32, you break that. Nothing will tell you.

## Trusted proxies

Every rule reads `$request->getClientIp()`. Set `framework.trusted_proxies` and the bundle
does the rest:

```yaml
framework:
    trusted_proxies: '%env(TRUSTED_PROXIES)%'
    trusted_headers: ['x-forwarded-for', 'x-forwarded-proto']
```

`behind_proxy: auto` (the default) asserts `global.behind_proxy: true` to the library when
the kernel has actually applied a proxy list, which silences the library's per-request
warning. When no proxy is configured it asserts **nothing** — deliberately. "Nobody
configured proxies" and "there is no proxy" are indistinguishable from inside the process,
and only one of them is safe. If you know there is nothing in front of the deployment, say
so:

```yaml
kanopi_firewall:
    behind_proxy: false
```

To make a missing proxy list fail the deploy rather than warn, use the library's own
setting: `global.require_trusted_proxies: true` in your `firewall.yml`, or
`overrides: { '[global][require_trusted_proxies]': true }`.

This is resolved at runtime rather than while the container is built, and the reason is
worth knowing if you ever reach for the parameter yourself: FrameworkBundle's *default* for
`kernel.trusted_proxies` is the literal, unresolvable string
`%env(default::SYMFONY_TRUSTED_PROXIES)%`. It looks configured and is not.

## When the firewall cannot start

`Firewall::create()` throws for a bad `challenge.secret`, an unresolvable provider, an
unreachable database, an unwritable storage path. The library's docs are explicit that
fail-open versus fail-closed is the integrator's decision; `on_startup_failure` is where
you make it.

- `fail_closed` *(default)* — the exception propagates, and the request becomes a 500.
  Right wherever serving unfiltered traffic is worse than serving an error.
- `fail_open` — logged at `critical`, and the request is served unfiltered. Reasonable only
  for public, low-risk content, and only if that alert actually pages someone.

Either way the outcome is remembered: a firewall that cannot start will not start on the
next request either, and retrying a refused database connection on every request turns a
filtering outage into a latency outage.

Config *loading* is a separate question, and lenient by default — a missing or malformed
`firewall.yml` produces a firewall with no rules that allows everything, and logs at
`error`. Turn that into a startup failure with `global.require_config: true` in your YAML.

## The blocked response

`blocked_response: plain` *(default)* writes the refusal directly, as
`text/plain; charset=utf-8` with `X-Content-Type-Options: nosniff` — the same two headers
the library sends in `block` mode, and for the same reason. The banning message is a
template over request data (`{{request.header.X-Foo}}` and friends), so it can carry bytes
the client chose. Escaping is one belt; a content type no browser will parse as markup is
the other.

`blocked_response: http_exception` throws an `HttpException` instead, so your error
controller renders the status with your own templates. The banning message is dropped —
an error template is HTML by definition — though the original exception is chained as
`previous`, so it still reaches your logger.

## The challenge flow

In `exception` mode the library throws instead of rendering, so the bundle owns the HTTP
side of the round trip. It does not reimplement anything: it stands up a
`ChallengeProviderRegistry` from the same configuration and asks the same provider for the
same document, so the markup, the submit JavaScript and the field names are what `block`
mode would have served.

| The library throws | The bundle returns |
|---|---|
| `ChallengeRequiredException` | 200, the interstitial, `Cache-Control: no-store` |
| `ChallengeSolvedException` | 303 to `getRedirect()`, with the pass cookie |
| `FirewallBlockedException` | `getStatusCode()`, the banning message |

303 rather than 302, because the visitor got here by POSTing a solution and a client that
repeats the POST re-submits one a single-use provider has already burned. The pass cookie
expires with the token it carries — the TTL is read off the `ChallengeSolved` event, which
the library announces immediately before it throws.

### Per-rule challenge providers are not supported

`metadata.challenge_provider` lets a single rule name its own provider. **The bundle
refuses to start when any rule does**, and the refusal fires during `cache:clear`, so it
lands at deploy rather than on a visitor.

The reason is a lockout, not an inconvenience. When rules use different providers, the
interstitial has to carry a *signed* `provider_token` back so the submission is verified by
the right one, and that signature is `Firewall::signProviderName()` — `protected`, over a
`private const`, with no public equivalent. Rendering without it means the solution is
verified by `challenge.provider`, the minted token carries that provider's name, the rule
that named a different one rejects it, and the visitor is served the same interstitial
forever with nothing in the logs calling it an error.

Reproducing the signature was the alternative. It lost because if the library ever changes
that private constant, the field fails its signature check and we are back at the same
silent lockout — with a green test suite. Use one `challenge.provider` for every rule until
[kanopi/firewall#311](https://github.com/kanopi/firewall/issues/311) exposes a public way
to sign it.

## Console commands

Fifteen commands under `kanopi:firewall:`, each with a short `kfw:` alias. Eight wrap the
library's shipped scripts; seven answer for themselves, because there is no script behind
them.

Every one of them declares its own options, so `--help` describes the command, a mistyped
option is rejected before it reaches anything, and shell completion works.

### Is it on, and is it working?

| Command | What it answers | Exits non-zero when |
|---|---|---|
| `kanopi:firewall:status` | Is this thing on, what is it enforcing, is any of it failing | The firewall could not be built at all |
| `kanopi:firewall:health` | Is it working **right now** | A configured rule is not running, or a panic file did not take |
| `kanopi:firewall:doctor` | Is it configured **correctly** — the Symfony wiring *and* the library's own checks | Either half reports an error |
| `kanopi:firewall:rules` | What will be evaluated, in evaluation order | — |
| `kanopi:firewall:config` | What the merged configuration actually became | An input failed to load |

`status` is the one to run first. `health` is the one to point a monitor at: its output is
a fixed, flat shape a check can key off without parsing sentences. `doctor` is the one to
gate a deploy on — it reads prose written for a person, and it is the only one that knows
about the parts of this bundle the library cannot see:

```
Symfony integration checks
--------------------------

 OK  Mode is "enforce"
 OK  Listener priority is 250
        Ahead of the router and the session, so the challenge path is reachable and a
        refused request starts no session.
 WARN  Nothing says whether this is behind a proxy
        framework.trusted_proxies is empty and kanopi_firewall.behind_proxy is "auto", so
        every rule reads getClientIp() unfiltered. Behind a CDN that means every visitor
        arrives as the CDN's address: allowlists match nobody and a per-IP rate limit
        counts the whole internet into one bucket.

 10 ok, 1 warning, 0 error

Library checks (bin/firewall-doctor)
------------------------------------
  ...
```

It checks eleven things, and each one is a way for a perfectly healthy firewall to be doing
nothing: a mode that acts on no verdict, a configuration that declared no rules, an input
that failed to load, a listener priority below the router, a route squatting the challenge
path, an unasserted proxy posture, in-memory storage, `fail_open`, logging that is off,
sub-requests evaluated twice, and scripts that are not where the bundle looks. The
integration half runs first on purpose: a firewall whose listener never runs is in perfect
health and completely ineffective, so you should read about the wiring before reading a
clean bill of health about the rules. `--integration-only` needs no readable configuration
at all, which is what makes it usable on the deployment that is broken.

### Who is blocked, and letting them back in

| Command | What it does |
|---|---|
| `kanopi:firewall:block <ip>` | Block one address now, without writing a rule |
| `kanopi:firewall:unblock <ip\|cidr>` | Lift a block, or `--all` to empty the list |
| `kanopi:firewall:blocks` | List, find and inspect what is in force |
| `kanopi:firewall:find-reference <ref>` | Turn the reference off a block page back into a client |

```bash
bin/console kanopi:firewall:block 203.0.113.9 --duration=0 --reason="Scraping /api"
bin/console kanopi:firewall:blocks --list
bin/console kanopi:firewall:find-reference 2CB3B1780E3653DE9C7AFA913F3C1A33
bin/console kanopi:firewall:unblock 203.0.113.0/24 --dry-run
```

`block` and `unblock` have no script behind them: `bin/firewall-block` can list, find, show
and lift, and it cannot *add*. That is deliberate upstream, where a block is something a
rule earns — and it is a gap the first time somebody is on the phone reading a reference
number off an error page. Both are implemented against the library's public API, and both
know two things about the storage contract that are not guessable: `set()`'s expiry is a
duration and not a timestamp, and `set()` on an existing key keeps the *original* expiry.
That second one is why re-blocking is refused rather than silently doing nothing useful —
pass `--force` and it lifts first, so a longer `--duration` applies.

`find-reference` is the answer to the only thing a blocked visitor can read out. The
firewall's page deliberately tells them nothing about which rule matched, so support was
left with a hex string and no way to use it.

Two asymmetries worth knowing, both deliberate: `block` refuses a CIDR range, because a
block is stored under one exact address and a range would sit in the list looking
authoritative while matching no visitor ever (use `kanopi:firewall:rule add --ip=…` for
that). `unblock` accepts one, because lifting matches against what is already stored.

### The rest

| Command | Script | What it answers |
|---|---|---|
| `kanopi:firewall:check` | `firewall-check` | Would *this* request be blocked, and by what? |
| `kanopi:firewall:rule` | `firewall-rule` | Add, remove, enable, disable managed rules |
| `kanopi:firewall:sources` | `firewall-sources` | Fetch and cache remote rule sources |
| `kanopi:firewall:migrate` | `firewall-migrate` | Bring database tables up to the declared schema |
| `kanopi:firewall:log-prune` | `firewall-log-prune` | Delete log rows past their retention |
| `kanopi:firewall:init` | `firewall-init` | Write a starter `firewall.yml` |

```bash
bin/console kanopi:firewall:check --ip=203.0.113.5 --url=/wp-admin/ --explain
bin/console kanopi:firewall:rule init                 # once, before the first add
bin/console kanopi:firewall:rule add --ip=203.0.113.9 --name=office
bin/console kanopi:firewall:rule disable office
bin/console kanopi:firewall:migrate --dry-run         # exits 3 when changes are pending
bin/console kanopi:firewall:doctor -- --help          # the script's own options
```

`check` is safe to point at a production configuration: the script swaps storage for a
throwaway store by default, so asking cannot ban anybody. Pass `--live-storage` when you
mean the durable list.

### Output formats and exit codes

The native commands take `--format=table|json|yaml` — `table` for a person, the other two
for anything else. In a machine format they print the document and nothing else: the
"lift it with…" hints and the warnings about in-memory storage are worth more than they
cost to a person, and are a parse error to everything else.

The wrappers take the scripts' own `--json`, because their output *is* the script's.
`--quiet` is the one rename: Symfony Console owns it, so the scripts' flag is spelled
`--quiet-output`.

Exit codes are the library's, and they are the same across every command here: **0** fine
or warnings only, **1** something configured is not happening or the action was refused,
**2** the configuration could not be read or the arguments made no sense, **3** changes are
pending (`migrate --dry-run` only, so a deploy can gate on it).

`kanopi:firewall:doctor --json` emits *two* documents — the integration findings, then
whatever the script writes. They cannot be merged: the second half comes from another
process, and buffering it to splice the two would mean a doctor that appears to hang while
it waits on a slow database. For one machine-readable answer use `--integration-only
--json`, or `kanopi:firewall:health --format=json`.

### Why subprocesses, and what they are given

The wrapped scripts are subprocesses rather than native rewrites on purpose. They are 150
to 640 lines each of argument parsing, output formatting and exit-code policy — and most of
it is not reachable through a public class. Rewriting them would buy nicer output and cost a
2,500-line fork that drifts from the parent on every release, in the one part of the system
you reach for during an incident. A passthrough after `--` survives as an escape hatch, so
an option added upstream is usable before this bundle is updated for it.

They see the configuration the listener actually runs, not just `config_files`. Inline
`settings` and everything the bundle decides — the forced mode, the proxy posture, the
challenge path and cookie, a `challenge.secret` set in bundle config — are written to
short-lived 0600 files alongside the real ones and deleted afterwards.

That is a fix, not a flourish. Passing only `config_files` meant putting the secret where
this README tells you to put it and then reading:

```
✗ The firewall refuses to start with this configuration
    response: challenge plugins are configured but `challenge.secret` is empty.
```

— about an application that starts and serves challenges perfectly well. A health command
that invents a fatal error is worse than none, because the next real one gets ignored too.

Two exceptions. `kanopi:firewall:rule` sees only the real files: it *edits* configuration,
placing a managed file beside the first config it is given, so a generated one would put
that file in the temp directory and offer rules for editing that nothing can edit. And an
explicit `--config=` is taken at face value — you are asking about that file, not about
this application.

The remaining consequence is that there is no interactive TTY: `kanopi:firewall:init` takes
its four answers as options and falls back to their defaults rather than prompting.

### In a deploy

```bash
bin/console kanopi:firewall:migrate      # additive only; never drops or renames
bin/console kanopi:firewall:sources      # warm the caches before traffic arrives
bin/console kanopi:firewall:doctor       # fails the deploy if something is not running
```

And for a monitor, every thirty minutes:

```bash
bin/console kanopi:firewall:health --format=json
```

## Logging

The library logs through PSR-3, and those lines are the audit trail — "who was blocked, by
which rule, when" exists nowhere else. `logging.mode` decides whose handlers win:

- `replace` *(default)* — the library logs to your Monolog channel, so it lands wherever
  `monolog.yaml` says and shows up in the profiler's log panel. Its own `logger:` block
  stops taking effect.
- `merge` — keep the library's logger *and* add your handlers to it. Use this when the
  `logger:` block configures something you want to keep, such as a `DatabaseHandler` held
  as a retained audit trail.
- `off` — leave the library alone. Forced automatically when MonologBundle is not
  installed.

The channel (`kanopi_firewall` by default) is declared for you via `monolog.channels`, so
routing it somewhere of its own just works:

```yaml
monolog:
    handlers:
        firewall:
            type: rotating_file
            path: '%kernel.logs_dir%/firewall.log'
            level: info
            channels: ['kanopi_firewall']
```

## Profiler panel

On by default in debug. It shows the verdict, the rule that produced it, the mode actually
in force versus the one configured, and whether a panic file is overriding it.

It also shows the two health lists, which are the reason it is worth having:

- **Rules that failed to build** — `getFailedRules()`. These are **not running**. A rate
  limit whose Redis constructor threw is skipped, logged once at `error`, and otherwise
  indistinguishable from a rule that matched nothing.
- **Backends running blind** — `getDegradedBackends()`. These *are* running and have
  nothing to consult. `RedisStorage` catches a connection failure and answers every read as
  though the store were empty, so the rule constructs fine and allows everyone.

Both build every rule that is not built yet, which is what opens a storage connection, so
the panel skips them on any request the firewall did not evaluate. Set
`profiler.collect_health: false` to skip them entirely.

For a production health endpoint, autowire `Kanopi\FirewallBundle\Firewall\FirewallFactory`
and call the same two methods — off a request path, as the library's docs say.

## Decision events

The container's `event_dispatcher` is handed to `Firewall::create()` directly; Symfony's
dispatcher is a PSR-14 dispatcher, so there is no adapter. Listen the ordinary way:

```php
use Kanopi\Firewall\Event\RequestBlocked;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

#[AsEventListener]
final class NotifyOnBlock
{
    public function __invoke(RequestBlocked $event): void
    {
        if (!$event->isEnforced()) {
            return; // observe mode — recorded, not applied
        }

        // $event->getPlugin(), ->getStatusCode(), ->wasAlreadyBlocked()
    }
}
```

They are read-only by design. A listener cannot change a verdict, and one that throws is
swallowed and logged by the library — so do not build anything that depends on one running.
The bundle obeys its own advice: it registers a listener to remember which rule matched
(for the profiler) and how long a challenge should last (for the pass cookie), and both
degrade to a sensible default when nothing was recorded.

## Requirements

PHP 8.1–8.5 and `kanopi/firewall ^2.24`, which is what fixes the Symfony range:

| Symfony | Supported | Tested in CI | Notes |
|---|---|---|---|
| 6.4 LTS | yes | PHP 8.1–8.5, plus a 6.4.0 floor | |
| 7.3 | yes | not directly | Same constraint branch as 7.4; add `7.3.*` to the matrix if you need it asserted |
| 7.4 LTS | yes | PHP 8.2–8.5 | |
| **8.0** | **no** | — | `kanopi/firewall` requires `~8.1`, which skips the 8.0 line. No resolution exists; supporting it needs an upstream change first. |
| 8.1 | yes | PHP 8.4–8.5, plus an 8.1.0 floor | Symfony 8.1 requires PHP 8.4.1 |

Every combination above is a separate CI job, and each one asserts that **every**
`symfony/*` package resolved to the line it claims before it runs anything.

Each supported line also gets a `--prefer-lowest` job, because `~6.4` and `~8.1` promise
that **6.4.0 and 8.1.0** work and every other job resolves the newest patch. The 8.1 floor
earned its place the moment it was added: at Symfony 8.1.0 a deprecation from a floor
dependency printed into a fixture server's response body and broke a test that passes on
8.1.6.

That assertion is not ceremony. With a PHP-only matrix, Composer settled on a *mixed* set
on every PHP version — `http-kernel` and `framework-bundle` at 7.4 while `console`,
`http-foundation` and `process` sat at 8.1. No application runs that combination, the
8.x line was never actually exercised, and it hid a real break:
`Console\Application::add()` was removed in Symfony 8.

To reproduce a single job locally:

```bash
composer global require symfony/flex
SYMFONY_REQUIRE=6.4.* composer update -W
composer test
```

Install Flex **globally**, not into this package. As a dev dependency it writes a Symfony
application skeleton (`config/`, `public/`, `bin/console`, `.env`) into the checkout —
`--no-scripts` does not stop it, and one of its recipes appends `/phpunit.xml` to
`.gitignore`, which would quietly stop this package's own PHPUnit config from being
committed. It would also fall under `--prefer-lowest` and resolve to a version that
fatals on a current Composer. Globally it is tooling: outside the dependency graph, and
it applies no recipes.

## Development

```bash
composer install
composer test           # both suites, no coverage
composer test:gate      # coverage, then the 100% line/method gate
composer check          # PHPCS + PHPStan at max
```

The suite runs a real kernel, because the interesting failures are wiring failures: a
listener priority that lets the router claim the challenge path, an extension that stops
declaring its Monolog channel, a service argument that no longer resolves. One test starts
`php -S` in a subprocess — `observe` mode cannot be proven from PHPUnit, which runs on the
`cli` SAPI where the library short-circuits before evaluating anything.

It is still a test suite, so it is worth installing the bundle into a scratch Symfony
application before a release and driving it by hand. Two defects in this package were
found that way and by nothing else: the `doctor` false positive above, and a proxy bridge
that read `kernel.trusted_proxies` at container-build time — where FrameworkBundle's own
default for it is the unresolvable string `%env(default::SYMFONY_TRUSTED_PROXIES)%`, so
every application that had never configured a proxy would have been told it had one.

## License

MIT. See [LICENSE](LICENSE).
