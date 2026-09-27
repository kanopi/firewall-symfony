# Quickstart

From nothing to a Symfony application that is filtering hostile traffic, in about fifteen
minutes. Every command here was run against a fresh `symfony/skeleton` before it was
written down.

The path is deliberately: **install → observe → read the log → enforce.** Turning an
unfamiliar rule set straight on is how a site discovers its false positives in production,
and the usual recovery is to remove the firewall rather than to tune it.

**Requirements:** PHP 8.1–8.5, Symfony 6.4 / 7.4 / 8.1, Composer, and
`kanopi/firewall-symfony` **1.0.1 or newer** — 1.0.0 wired its logger to nothing and
discarded every firewall log line, which makes step 5 below impossible.

---

## 1. Install

```bash
composer require kanopi/firewall-symfony
```

Symfony Flex registers the bundle for you. Check:

```bash
grep Kanopi config/bundles.php
# Kanopi\FirewallBundle\KanopiFirewallBundle::class => ['all' => true],
```

No line? You are not using Flex. Add it by hand:

```php
// config/bundles.php
return [
    // ...
    Kanopi\FirewallBundle\KanopiFirewallBundle::class => ['all' => true],
];
```

Logging is worth having from the first request — the log is the whole point of the observe
step below:

```bash
composer require symfony/monolog-bundle
```

## 2. Write a firewall configuration

The rules live in a YAML file that belongs to your application, not to the bundle. Generate
a starting one:

```bash
bin/console kanopi:firewall:init --platform=other --storage=file --output=config/firewall.yml
```

`--platform` accepts `wordpress`, `drupal` or `other`; a Symfony application is `other`,
which pulls in the two platform-neutral presets — `malicious-requests.yml` and
`malicious-urls.yml`. Behind a CDN, add `--cdn=cloudflare` (or `pantheon`, `wpengine`,
`fastly`) and it will write the ranges to trust.

**Read the file it writes.** It is commented throughout and every value in it is meant to
be edited.

One edit to make now, in `config/firewall.yml`:

```yaml
storage:
  type: Kanopi\Firewall\Storage\FileStorage
  config:
    storage_file: ../var/firewall-blocks.json
```

The generated default writes to `/tmp`, which works immediately and does not survive a
reboot. A **relative path resolves against the directory of the file that declares it**, so
`../var/…` from `config/firewall.yml` lands in your application's `var/`. The file is
created `0600`.

## 3. Point the bundle at it

```yaml
# config/packages/kanopi_firewall.yaml
kanopi_firewall:
    mode: observe
    config_files:
        - '%kernel.project_dir%/config/firewall.yml'
```

```bash
bin/console cache:clear
```

That `cache:clear` is not optional the first time. A configuration file that did not exist
when the container was built does not always invalidate it, and the symptom is a status
report showing no rules at all. Edits to the file afterwards are picked up normally.

## 4. Check what you have

```bash
bin/console kanopi:firewall:status
```

```
  Library version      v2.26.0
  Bundle mode          observe
  Enforcing            no
  Firewall started     yes
  Healthy              yes
  Rules enabled        2
  Rules declared       2
  Lockdown             off
  Storage backend      Kanopi\Firewall\Storage\FileStorage
  Blocks in force      0
```

Two rules from two presets, both enabled, nothing refused yet. `Enforcing: no` is the
whole point of this step.

Then the one that checks the wiring rather than the rules:

```bash
bin/console kanopi:firewall:doctor
```

It runs eleven checks of the Symfony side — listener priority, challenge path, proxy
posture, whether every config input actually loaded — and then the library's own. **Fix
anything it calls an ERROR before going further.** Each one is a way for a firewall to
report perfect health while doing nothing.

Expect two warnings at this stage, and both are correct:

- *"Mode is observe"* — rules are evaluated and nothing is refused. That is deliberate
  until step 7.
- *"Nothing says whether this is behind a proxy"* — step 6 deals with it.

A warning does not fail the command; an error does.

To see what will be evaluated, in evaluation order:

```bash
bin/console kanopi:firewall:rules
```

## 5. Observe for a week

`mode: observe` evaluates every rule, logs every match, and refuses nothing. Route the log
somewhere you will actually read:

```yaml
# config/packages/monolog.yaml
monolog:
    handlers:
        firewall:
            type: rotating_file
            path: '%kernel.logs_dir%/firewall.log'
            level: info
            channels: ['kanopi_firewall']
```

The `kanopi_firewall` channel is declared for you. Now drive real traffic at it and read
`var/log/firewall.log`. Every line is a request that **would** have been refused.

Impatient? Ask about one request without waiting for traffic:

```bash
bin/console kanopi:firewall:check --ip=203.0.113.5 --url=/xmlrpc.php --explain
```

That is safe to run against production configuration: it swaps in a throwaway store, so
asking cannot ban anybody. It **exits 1 when the verdict is "blocked"** — that is the
answer, not a failure, so guard it if it runs under `set -e`.

When the log is boring, the rules fit your traffic.

## 6. Tell it about your proxy

Skip this only if nothing sits in front of the application. Behind a CDN or load balancer
with this unset, **every visitor arrives as the proxy's address**: allowlists match nobody
and a per-IP rate limit counts the whole internet into one bucket.

```yaml
# config/packages/framework.yaml
framework:
    trusted_proxies: '%env(TRUSTED_PROXIES)%'
    trusted_headers: ['x-forwarded-for', 'x-forwarded-proto']
```

The bundle reads what Symfony resolved, so there is no second setting to keep in step. If
there is genuinely nothing in front, say so explicitly:

```yaml
kanopi_firewall:
    behind_proxy: false
```

Re-run `kanopi:firewall:doctor` — the proxy warning should be gone.

## 7. Enforce

```yaml
kanopi_firewall:
    mode: enforce
```

```bash
bin/console cache:clear && bin/console kanopi:firewall:doctor
```

A refused request gets the library's banning message and, by default, **status 400**.

Changing that is less obvious than it looks, and the two settings do not overlap:

```yaml
# config/firewall.yml — the rule that matched decides
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    metadata:
      status_code: 403          # this rule answers 403
    config: [path:/xmlrpc.php]

global:
  banning_status_code: 403      # only for block-list hits, which have no rule
```

A rule always supplies a status — `metadata.status_code`, defaulting to 400 — so
`global.banning_status_code` never applies to a rule match, including every rule in the
shipped presets. What it *does* govern is a request refused by the durable block list,
where no rule was involved. Both were verified by watching the status change.

Prefer your own error page? `kanopi_firewall.blocked_response: http_exception` hands the
refusal to Symfony's error controller, which renders your `error.html.twig` instead of the
plain banning message.

## 8. Wire it into your deploy

```bash
bin/console kanopi:firewall:sources    # warm remote rule lists before traffic arrives
bin/console kanopi:firewall:doctor     # fails the deploy if something configured is not running
```

On **database** storage or logging, add the schema step first:

```bash
bin/console kanopi:firewall:migrate    # additive only; never drops or renames
```

Only then. On the file storage this quickstart configured, `migrate` **exits 2** — it has
nothing database-backed to migrate and says so — which under `set -e` fails the deploy for
a firewall that is working perfectly.

`doctor` is the one to gate on: a warning does not fail it, an error does. And for a
monitor, every thirty minutes:

```bash
bin/console kanopi:firewall:health --format=json
```

`health` answers "is it working **right now**" in a fixed, flat shape a check can key off
— a rule that failed to build, a backend that cannot reach its store, a panic file left
down. `doctor` answers "is it configured correctly". Both exist because both fail silently.

---

## The day somebody says "I'm blocked"

They can read you one thing: the hex reference on the block page.

```bash
bin/console kanopi:firewall:find-reference 2CB3B1780E3653DE9C7AFA913F3C1A33
```

```
  Reference    2CB3B1780E3653DE9C7AFA913F3C1A33
  Address      198.51.100.9
  Blocked at   2026-09-12T21:43:56+00:00
  Expires      2026-09-12T21:53:56+00:00
  Reason       Scraping /api

 Lift it with: bin/console kanopi:firewall:unblock 198.51.100.9
```

```bash
bin/console kanopi:firewall:unblock 198.51.100.9
```

Nothing found is usually not a typo — blocks lapse, and the page they are looking at may be
from an hour ago. The other direction, when a scraper is costing you money right now:

```bash
bin/console kanopi:firewall:block 203.0.113.9 --duration=0 --reason="Scraping /api"
bin/console kanopi:firewall:blocks --list
```

A block takes effect on the next request with no deploy, and `--duration` lets it lapse on
its own. For anything that should outlive the incident, write a rule instead:

```bash
bin/console kanopi:firewall:rule init                                    # once
# then add the include it prints to config/firewall.yml:
#   configs:
#     - "firewall-managed.yml"
bin/console kanopi:firewall:rule add --ip=203.0.113.0/24 --name=bad-range
```

`rule init` writes `config/firewall-managed.yml` and **does not wire it in** — deliberately,
because naming an include before the file exists is a load failure that empties the whole
document rather than skipping a line. Add the include yourself, once, after `init`. Skip it
and `rule add` still writes the rule, warns that nothing reads it, and exits 0.

Every command has a short alias: `kfw:status`, `kfw:block`, `kfw:doctor`. During an
incident that matters more than it looks.

## Troubleshooting

| What you see | What it usually is |
|---|---|
| `status` shows 0 rules, and you just added the config | The container predates the file. `bin/console cache:clear`. |
| `doctor`: "No firewall configuration is declared" | `config_files` is empty or the path is wrong. It takes an absolute path — use `%kernel.project_dir%`. |
| `doctor`: "N configuration input(s) failed to load" | An unreadable file, or one `%env()%` token naming an unset variable — which discards the **whole file**, not that one value. |
| Everything is allowed, and the rules look right | Check `Enforcing` in `status`. `observe` is the default in step 3 on purpose. |
| `blocks --list` is always empty | In-memory storage. It is discarded when the process exits — step 2's `storage` block is what fixes it. |
| A blocked visitor stays blocked after you lift them | A *rule* matches their traffic, not a durable block. `kanopi:firewall:check --ip=… --explain` says which. |
| You tested one blocked URL locally and now **every** page is refused | You blocked yourself. The rule wrote `127.0.0.1` to the durable list, and the list is checked before any rule — so the refusal outlives the request that earned it. `kanopi:firewall:blocks --list` shows it; `kanopi:firewall:unblock 127.0.0.1` gives you your site back. |
| A challenge page that never accepts an answer | Your listener priority is below the router, so the submission path 404s. `doctor` reports it as an ERROR. |

## Where to go next

- **[README.md](README.md)** — configuration reference, the listener priority table, the
  challenge flow, decision events, and the profiler panel.
- **`bin/console list kanopi`** — all sixteen commands. Each `--help` is written for an
  operator, not as a syntax dump.
- **Response actions beyond block/allow** — `record` serves the request and refuses the
  next one (what a honeypot needs), `redirect` sends a visitor to a notice page, `mark`
  annotates the request and lets your code decide. See "What a matched rule can do" in the
  README.
- **`kanopi/firewall`'s own docs** — the rules, the presets and the plugins are the
  library's: <https://github.com/kanopi/firewall>.
