<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Diagnostics;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\FirewallBundle\DependencyInjection\Configuration;
use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Exception\ExceptionInterface as RoutingExceptionInterface;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\RouterInterface;

/**
 * Checks the wiring between Symfony and the firewall.
 *
 * ## Why this is separate from the library's own doctor
 *
 * `bin/firewall-doctor` checks the firewall: every rule builds, every
 * backend answers, every file is readable. It cannot check whether the
 * firewall is ever *consulted*, because from inside the library there is
 * nothing to look at — and a firewall whose listener runs after the router,
 * or whose mode is `disabled`, is in perfect health and completely
 * ineffective.
 *
 * Those are the failures this class looks for. They are all bundle-shaped:
 * a listener priority, a proxy posture, a mode, a path that something else
 * claimed. Every one of them leaves the library reporting a clean bill of
 * health, which is why the integration findings are printed **first** by
 * `kanopi:firewall:doctor` — an operator should read about the wiring before
 * reading that the rules are fine.
 *
 * ## Why the findings are the library's `Diagnosis` objects
 *
 * So that one command can print both halves the same way, and so a `--json`
 * consumer sees one shape. The alternative was a bundle-local finding class
 * that the command then translated, which is a second vocabulary for the
 * same three states.
 */
final class IntegrationDoctor
{
    /**
     * `RouterListener`'s `kernel.request` priority.
     *
     * The number that matters: at or below it, the router resolves the
     * request before the firewall sees it, and the challenge submission path
     * — which is deliberately not a route — 404s before a challenged
     * visitor can answer. See Configuration::DEFAULT_PRIORITY.
     */
    private const ROUTER_PRIORITY = 32;

    /**
     * `SessionListener`'s `kernel.request` priority.
     *
     * Not a correctness boundary, unlike the router: below it, a request the
     * firewall is about to refuse has already had a session started for it.
     */
    private const SESSION_PRIORITY = 128;

    /**
     * @param string $mode
     *   `kanopi_firewall.mode`.
     * @param int $listenerPriority
     *   `kanopi_firewall.listener.priority`.
     * @param bool $onlyMainRequests
     *   `kanopi_firewall.listener.only_main_requests`.
     * @param string $challengePath
     *   `kanopi_firewall.challenge.path`.
     * @param string $binDir
     *   Where the library's `bin/` scripts should be.
     * @param string $loggingMode
     *   The resolved `kanopi_firewall.logging.mode` — already downgraded to
     *   `off` by the extension when MonologBundle is absent.
     * @param string $onStartupFailure
     *   `fail_closed` or `fail_open`.
     * @param array<int, string|array<string, mixed>> $configInputs
     *   The config inputs the firewall is built from.
     * @param ProxyPosture $proxyPosture
     *   Answers whether a proxy has been asserted.
     * @param ConfigSnapshot $configSnapshot
     *   The merged library configuration, and what failed to load.
     * @param RouterInterface|null $router
     *   For the challenge-path collision check. NULL in an application with
     *   no router, where there is nothing to collide with.
     */
    public function __construct(
        private readonly string $mode,
        private readonly int $listenerPriority,
        private readonly bool $onlyMainRequests,
        private readonly string $challengePath,
        private readonly string $binDir,
        private readonly string $loggingMode,
        private readonly string $onStartupFailure,
        private readonly array $configInputs,
        private readonly ProxyPosture $proxyPosture,
        private readonly ConfigSnapshot $configSnapshot,
        private readonly ?RouterInterface $router = null
    ) {
    }

    /**
     * Every check, in the order they should be read.
     *
     * Ordered by what invalidates what: a firewall that is disabled or whose
     * configuration did not load makes every later finding moot, so those
     * come first.
     *
     * @return array<int, Diagnosis>
     *   The findings.
     */
    public function run(): array
    {
        return [
            $this->checkMode(),
            $this->checkConfigInputs(),
            $this->checkConfigLoaded(),
            $this->checkListenerPriority(),
            $this->checkChallengePath(),
            $this->checkProxyPosture(),
            $this->checkPathSource(),
            $this->checkStorage(),
            $this->checkStartupPolicy(),
            $this->checkLogging(),
            $this->checkSubRequests(),
            $this->checkScripts(),
        ];
    }

    /**
     * Is the bundle configured to act on a verdict at all?
     */
    private function checkMode(): Diagnosis
    {
        if ($this->mode === 'disabled') {
            return Diagnosis::warning(
                'Mode is "disabled"',
                'The listener returns before evaluating anything, so no rule is applied and no '
                . 'decision is logged. Nothing below this line describes what is happening to '
                . 'live traffic. Set kanopi_firewall.mode to observe or enforce.'
            );
        }

        if ($this->mode === 'observe') {
            return Diagnosis::warning(
                'Mode is "observe"',
                'Rules are evaluated and decisions logged, and nothing is blocked. That is the '
                . 'right way to start. Two things to know: the log is the only evidence, and '
                . 'under a CLI-SAPI runtime — RoadRunner, Swoole, FrankenPHP in worker mode — '
                . 'the library returns early in every mode but "exception", so observe evaluates '
                . 'nothing there. kanopi_firewall.mode: enforce is exempt from that.',
                'docs/configuration/global.md'
            );
        }

        return Diagnosis::ok('Mode is "enforce"', 'A block verdict becomes a response.');
    }

    /**
     * Is there any configuration to enforce?
     */
    private function checkConfigInputs(): Diagnosis
    {
        if ($this->configInputs === []) {
            return Diagnosis::error(
                'No firewall configuration is declared',
                'Neither kanopi_firewall.config_files nor kanopi_firewall.settings is set, so the '
                . 'firewall runs on the library\'s defaults, which contain no rules: every request '
                . 'is allowed. Write a starting file with kanopi:firewall:init and list it in '
                . 'config_files.'
            );
        }

        $rules = $this->configSnapshot->rules();
        $enabled = array_filter($rules, static fn (array $rule): bool => $rule['enabled']);

        if ($rules === []) {
            // Configuration exists and declares nothing to do with it. The
            // usual cause is a `plugins:` list that lost its indentation, or
            // an input that was meant to carry the rules and did not load —
            // which the check below names.
            return Diagnosis::error(
                'The configuration declares no rules',
                'Something is configured, and it contains no rules at all, so every request is '
                . 'allowed. Add rules with kanopi:firewall:rule add, or pull in a shipped preset '
                . 'through a `configs:` include.'
            );
        }

        if ($enabled === []) {
            return Diagnosis::error(
                'No rule is enabled',
                sprintf(
                    'The merged configuration declares %d rule(s) and every one of them is '
                    . '`enable: false`, so every request is allowed.',
                    count($rules)
                )
            );
        }

        return Diagnosis::ok(
            'Rules are configured',
            sprintf('%d of %d enabled. List them with kanopi:firewall:rules.', count($enabled), count($rules))
        );
    }

    /**
     * Did every configuration input actually load?
     *
     * The failure this catches is the quietest one in the system. Loading is
     * lenient, so an unreadable file — or one `%env()%` token naming a
     * variable that is not set, which discards the whole file rather than
     * that one value — leaves the firewall running on whatever else merged.
     * A firewall with no rules allows everything, and says so nowhere an
     * operator is looking.
     */
    private function checkConfigLoaded(): Diagnosis
    {
        $errors = $this->configSnapshot->loadErrors();

        if ($errors === []) {
            return Diagnosis::ok('Every configuration input loaded');
        }

        return Diagnosis::error(
            sprintf('%d configuration input(s) failed to load', count($errors)),
            'The firewall started on whatever else merged, so the rules in these are not being '
            . 'enforced and nothing will say so again: ' . implode(' ', $errors),
            'docs/configuration/loading-and-includes.md'
        );
    }

    /**
     * Does the listener run before the router?
     *
     * Not a preference. The challenge submission path is deliberately not a
     * route, so if the router gets there first it raises a 404 before the
     * listener sees the POST — and a challenged visitor is served the
     * interstitial forever, with nothing anywhere saying why.
     */
    private function checkListenerPriority(): Diagnosis
    {
        if ($this->listenerPriority <= self::ROUTER_PRIORITY) {
            return Diagnosis::error(
                sprintf('Listener priority %d is not above the router', $this->listenerPriority),
                sprintf(
                    'RouterListener runs at %d. Below it, the challenge submission path (%s) is '
                    . 'resolved as a route, 404s, and a challenged visitor can never answer — they '
                    . 'are served the interstitial forever. Raise kanopi_firewall.listener.priority '
                    . 'back to %d.',
                    self::ROUTER_PRIORITY,
                    $this->challengePath,
                    Configuration::DEFAULT_PRIORITY
                )
            );
        }

        if ($this->listenerPriority <= self::SESSION_PRIORITY) {
            return Diagnosis::warning(
                sprintf('Listener priority %d is below SessionListener', $this->listenerPriority),
                sprintf(
                    'Above the router (%d), so the challenge path is safe. But SessionListener runs '
                    . 'at %d, so a request the firewall is about to refuse has already had a session '
                    . 'started for it. The default is %d.',
                    self::ROUTER_PRIORITY,
                    self::SESSION_PRIORITY,
                    Configuration::DEFAULT_PRIORITY
                )
            );
        }

        return Diagnosis::ok(
            sprintf('Listener priority is %d', $this->listenerPriority),
            'Ahead of the router and the session, so the challenge path is reachable and a refused '
            . 'request starts no session.'
        );
    }

    /**
     * Has something else claimed the challenge submission path?
     *
     * A route there is not a lockout — priority already guarantees the
     * firewall is asked first — it is the opposite: the firewall answers
     * that path, so the route behind it may never be reached. Worth saying
     * because the symptom is a controller that silently stops being called.
     */
    private function checkChallengePath(): Diagnosis
    {
        if (!$this->router instanceof RouterInterface) {
            return Diagnosis::ok(
                'No router to collide with the challenge path',
                sprintf('%s is answered by the firewall.', $this->challengePath)
            );
        }

        $matcher = new UrlMatcher($this->router->getRouteCollection(), new RequestContext('', 'POST'));

        try {
            $matched = $matcher->match($this->challengePath);
        } catch (RoutingExceptionInterface) {
            // The ordinary, correct case: nothing routes there.
            return Diagnosis::ok(
                'The challenge path is not a route',
                sprintf('%s reaches the firewall and nothing else.', $this->challengePath)
            );
        }

        $route = $matched['_route'] ?? null;

        return Diagnosis::warning(
            'The challenge path is also a route',
            sprintf(
                'Route "%s" matches %s, which the firewall answers first because its listener runs '
                . 'above the router. The controller behind that route may never be called. Move it, '
                . 'or point kanopi_firewall.challenge.path somewhere unrouted.',
                is_string($route) ? $route : '(unnamed)',
                $this->challengePath
            )
        );
    }

    /**
     * Does the deployment know whether it is behind a proxy?
     *
     * ## Two places to name a proxy, and why they are not equivalent
     *
     * kanopi/firewall 2.33.0 accepts `global.trusted_proxies` in its own
     * YAML, and counts it as an answer to this question. The library does
     * not call `Request::setTrustedProxies()` with them — that is
     * process-wide state, and the host's — but applies them for the length
     * of one evaluation and puts the previous values back. So in a Symfony
     * application they are **the firewall's alone**: every IP rule sees the
     * visitor, and every controller, log line and profiler entry still sees
     * the proxy. That works, and it is why this is advice rather than a
     * warning; but `framework.trusted_proxies` answers the same question for
     * the whole application at once, and is the one to reach for.
     *
     * When both are set the library uses the host's and ignores its own —
     * the host knows its infrastructure. The YAML list is then configuration
     * that does nothing, which is worth a warning precisely because it looks
     * like it does something: the next person to add a CDN range will add it
     * there.
     */
    private function checkProxyPosture(): Diagnosis
    {
        $declared = $this->configSnapshot->trustedProxies();

        if ($declared !== [] && Request::getTrustedProxies() !== []) {
            return Diagnosis::warning(
                'global.trusted_proxies is ignored',
                sprintf(
                    'The firewall configuration names %s, and framework.trusted_proxies is set too. '
                    . 'When the application has trusted proxies of its own the library uses those and '
                    . 'ignores its list, so editing it changes nothing. Keep the proxies in '
                    . 'framework.trusted_proxies and remove global.trusted_proxies, so there is one source.',
                    implode(', ', $declared)
                )
            );
        }

        if ($declared !== []) {
            return Diagnosis::ok(
                'The proxy posture is asserted, for the firewall only',
                sprintf(
                    'global.trusted_proxies names %s. The library applies them while it evaluates a '
                    . 'request and not afterwards, so IP rules see the visitor while controllers, logs '
                    . 'and the profiler still see the proxy. Move them to framework.trusted_proxies to '
                    . 'give the whole application the same answer.',
                    implode(', ', $declared)
                )
            );
        }

        if ($this->proxyPosture->overrides() !== []) {
            return Diagnosis::ok(
                'The proxy posture is asserted',
                'Taken from framework.trusted_proxies, or from kanopi_firewall.behind_proxy.'
            );
        }

        return Diagnosis::warning(
            'Nothing says whether this is behind a proxy',
            'framework.trusted_proxies is empty and kanopi_firewall.behind_proxy is "auto", so the '
            . 'library warns on every request and every rule reads getClientIp() unfiltered. Behind '
            . 'a CDN that means every visitor arrives as the CDN\'s address: allowlists match nobody '
            . 'and a per-IP rate limit counts the whole internet into one bucket. Set '
            . 'framework.trusted_proxies (global.trusted_proxies in the firewall configuration also '
            . 'works, for the firewall alone), or kanopi_firewall.behind_proxy: false if there is genuinely '
            . 'nothing in front.'
        );
    }

    /**
     * Do the rules see the path the application routes on?
     *
     * `global.path_source: script_name` (kanopi/firewall 2.34) matches the
     * file the web server ran rather than the path through the front
     * controller, for WordPress's directly served `wp-login.php` and
     * `/wp-admin/*.php`. A Symfony application always runs
     * `public/index.php`, so the default is already the path it routes on,
     * and the library says front-controller applications should keep it.
     * Here `script_name` is a no-op at best. In a subdirectory install it
     * puts the base path in front of every path, and a rule written as
     * `/admin` quietly stops matching.
     *
     * An unknown value is left to the library's half of the doctor, which
     * reports it as an error.
     */
    private function checkPathSource(): Diagnosis
    {
        $source = $this->configSnapshot->pathSource();

        if ($source !== 'script_name') {
            return Diagnosis::ok(
                'Rules see the path through the front controller',
                sprintf('global.path_source is %s.', $source)
            );
        }

        $basePath = $this->configSnapshot->basePath();

        return Diagnosis::warning(
            'global.path_source is script_name',
            'That matches the file the web server ran, which is for WordPress\'s directly served '
            . 'files. A Symfony application always runs public/index.php, so the default (pathinfo) '
            . 'is already the path it routes on'
            . ($basePath === ''
                ? '. In a subdirectory install, script_name would put the subdirectory in front of every path.'
                : sprintf(', and global.base_path (%s) only has to undo what script_name added.', $basePath))
            . ' Remove global.path_source unless the firewall sits in front of something other than this application.'
        );
    }

    /**
     * Will a block written from the command line survive the command?
     */
    private function checkStorage(): Diagnosis
    {
        $type = $this->configSnapshot->storageType();

        if ($type === '') {
            return Diagnosis::warning(
                'No storage backend is configured',
                'The library falls back to its default. Declare storage.type explicitly — a rate '
                . 'limit or an escalating ban is only as durable as the store it counts in.',
                'docs/configuration/storage.md'
            );
        }

        if (str_contains($type, 'InMemoryStorage')) {
            return Diagnosis::warning(
                'Storage is in-memory',
                'Every block is discarded when the process exits, so kanopi:firewall:block cannot '
                . 'stop anything, kanopi:firewall:blocks always reports an empty list, and a rate '
                . 'limit counts per worker rather than per client. Use FileStorage, DatabaseStorage '
                . 'or RedisStorage anywhere real.',
                'docs/configuration/storage.md'
            );
        }

        if (str_contains($type, 'FileStorage')) {
            return $this->checkStorageFile($this->configSnapshot->storageFile());
        }

        return Diagnosis::ok('Storage backend', $type);
    }

    /**
     * Where is the block list, and will every worker find the same one?
     *
     * The path is reported even when nothing is wrong with it, because
     * "where is this stored?" is a question the configuration answers badly:
     * the starter file says `%env(default:/tmp/…:FIREWALL_STORAGE_FILE)%`,
     * and what that comes to depends on an environment the file cannot see.
     *
     * @param string|null $file
     *   `storage.config.storage_file` from the merged configuration.
     */
    private function checkStorageFile(?string $file): Diagnosis
    {
        if ($file === null) {
            return Diagnosis::warning(
                'FileStorage names no storage_file',
                'The library falls back to a per-user directory under the system temp dir. Set '
                . 'kanopi_firewall.storage_file: \'%env(resolve:FIREWALL_STORAGE_FILE)%\' and '
                . 'FIREWALL_STORAGE_FILE="%kernel.project_dir%/var/firewall/blocked.data" in .env — '
                . 'kanopi:firewall:init writes both.'
            );
        }

        // The half-wired case: .env carries a container placeholder, and the
        // library — which resolves %env()% itself, from the YAML — was handed
        // it verbatim because kanopi_firewall.storage_file is not set.
        if (preg_match('/%[a-z_.]+%/i', $file) === 1) {
            return Diagnosis::error(
                'The storage path contains an unresolved placeholder',
                sprintf(
                    '%s reached the library as written. A %%kernel.project_dir%%-style value is only '
                    . 'resolved by the container: set kanopi_firewall.storage_file: '
                    . '\'%%env(resolve:FIREWALL_STORAGE_FILE)%%\'.',
                    $file
                )
            );
        }

        if (!$this->isAbsolute($file)) {
            return Diagnosis::warning(
                'The storage path is relative',
                sprintf(
                    '%s came from Symfony configuration, where there is no file for it to be '
                    . 'relative to, so it resolves against the working directory: public/ for the web '
                    . 'server and the project root for bin/console — two block lists, and an unblock '
                    . 'from the command line that the site never sees. Use %%kernel.project_dir%% '
                    . 'through kanopi_firewall.storage_file, or set it in firewall.yml, where a '
                    . 'relative path resolves against the file.',
                    $file
                )
            );
        }

        $directory = dirname($file);

        if (!is_dir($directory)) {
            return Diagnosis::error(
                'The storage directory does not exist',
                sprintf(
                    '%s. The library creates the file but not its directory, so the firewall cannot '
                    . 'start — a 500 on every request under on_startup_failure: fail_closed.',
                    $directory
                )
            );
        }

        if (!is_writable(file_exists($file) ? $file : $directory)) {
            return Diagnosis::error(
                'The storage path is not writable',
                sprintf('%s must be writable by the web user and by whoever runs bin/console.', $file)
            );
        }

        $temp = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        if (str_starts_with($file, $temp) || str_starts_with($file, '/tmp/')) {
            return Diagnosis::warning(
                'The block list is in the temp directory',
                sprintf(
                    '%s. It is cleared on reboot, and on some hosts is private to each process, '
                    . 'which quietly gives every worker a block list of its own.',
                    $file
                )
            );
        }

        return Diagnosis::ok('Block list', $file);
    }

    /**
     * Whether a path is absolute, on either family of filesystem.
     */
    private function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/') || preg_match('~^[A-Za-z]:[\\\\/]~', $path) === 1;
    }

    /**
     * What happens if the firewall cannot start?
     */
    private function checkStartupPolicy(): Diagnosis
    {
        if ($this->onStartupFailure === 'fail_open') {
            return Diagnosis::warning(
                'on_startup_failure is "fail_open"',
                'A configuration error or an unreachable storage backend is logged at critical and '
                . 'the request is served unfiltered. That is a deliberate choice and the right one '
                . 'for some deployments — it is worth knowing that it means a broken firewall looks '
                . 'exactly like no firewall until somebody reads the log.',
                'docs/guides/error-handling.md'
            );
        }

        return Diagnosis::ok(
            'on_startup_failure is "fail_closed"',
            'A firewall that cannot start raises, so the failure is a 500 rather than unfiltered '
            . 'traffic.'
        );
    }

    /**
     * Is there an audit trail?
     */
    private function checkLogging(): Diagnosis
    {
        if ($this->loggingMode === 'off') {
            return Diagnosis::warning(
                'Firewall logging is off',
                'No decision is recorded through Monolog, which in "observe" mode means the '
                . 'firewall is producing no evidence at all, and in "enforce" mode means a blocked '
                . 'customer cannot be explained after the fact. Install symfony/monolog-bundle and '
                . 'set kanopi_firewall.logging.mode to replace or merge.'
            );
        }

        return Diagnosis::ok(
            sprintf('Firewall logging is "%s"', $this->loggingMode),
            'Decisions reach the application\'s Monolog channels.'
        );
    }

    /**
     * Are sub-requests being evaluated twice?
     */
    private function checkSubRequests(): Diagnosis
    {
        if ($this->onlyMainRequests) {
            return Diagnosis::ok('Sub-requests are skipped', 'Only the main request is evaluated.');
        }

        return Diagnosis::warning(
            'Sub-requests are evaluated too',
            'kanopi_firewall.listener.only_main_requests is false, so an ESI fragment or a '
            . 'forwarded request is evaluated again. It carries the same client and cannot reach a '
            . 'different verdict, but it does spend another request from every per-IP rate limit — a '
            . 'page with three fragments consumes four requests\' worth of budget.'
        );
    }

    /**
     * Are the wrapped scripts where the bundle expects them?
     */
    private function checkScripts(): Diagnosis
    {
        if (is_file($this->binDir . '/firewall-doctor')) {
            return Diagnosis::ok('The library\'s bin/ scripts are installed', $this->binDir);
        }

        return Diagnosis::error(
            'The library\'s bin/ scripts are not where the bundle expects',
            sprintf(
                'Nothing at %s/firewall-doctor, so every wrapped command — doctor, check, blocks, '
                . 'challenge, rule, sources, migrate, log-prune, init — will refuse to run. Set '
                . 'kanopi_firewall.commands.bin_dir if Composer\'s bin-dir is somewhere else.',
                $this->binDir
            )
        );
    }
}
