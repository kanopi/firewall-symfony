<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Semantic configuration for the `kanopi_firewall` bundle.
 *
 * @phpstan-type CookieOptions array{
 *     path: string,
 *     domain: string|null,
 *     secure: bool,
 *     http_only: bool,
 *     same_site: 'lax'|'strict'|'none'
 * }
 * @phpstan-type BundleConfig array{
 *     mode: 'enforce'|'observe'|'disabled',
 *     config_files: array<int, string>,
 *     settings: array<string, mixed>,
 *     overrides: array<string, mixed>,
 *     behind_proxy: bool|'auto',
 *     on_startup_failure: 'fail_closed'|'fail_open',
 *     blocked_response: 'plain'|'http_exception',
 *     listener: array{priority: int, only_main_requests: bool},
 *     challenge: array{
 *         secret: string|null,
 *         provider: string|null,
 *         path: string,
 *         cookie_name: string,
 *         header_name: string,
 *         audience: string|null,
 *         provider_options: array<string, mixed>,
 *         cookie: CookieOptions
 *     },
 *     logging: array{mode: 'replace'|'merge'|'off', channel: string},
 *     profiler: array{enabled: bool|'auto', collect_health: bool},
 *     commands: array{enabled: bool, bin_dir: string|null, timeout: float}
 * }
 *
 * ## Why `kanopi_firewall` and not `firewall`
 *
 * SecurityBundle has owned the word "firewall" since Symfony 2, and there it
 * means an authentication zone — a `security.firewalls.main` entry with a
 * pattern, a provider and a set of authenticators. It has nothing to do with
 * refusing hostile traffic. Two unrelated things called the same thing in the
 * same `config/packages/` directory is a trap that springs at the worst
 * possible moment: an operator debugging "why is this request being refused"
 * reading the wrong file.
 *
 * So everything this bundle owns is vendor-qualified: the config root is
 * `kanopi_firewall`, every service id starts `kanopi_firewall.`, and the
 * commands live under `kanopi:firewall:`. The alternative considered was
 * renaming the concept outright — `request_shield`, `gatekeeper` — which
 * would have been unambiguous without the prefix. It lost because it severs
 * the link to the library's own documentation: an operator reading
 * kanopi/firewall's docs about `global.mode` needs to find that key here, and
 * they will look for something with "firewall" in the name.
 *
 * ## What this class deliberately does not describe
 *
 * The library's `plugins:` list, `storage:`, `logger:` and `sources:` blocks
 * are passed through as opaque values under `settings`, not re-declared as
 * semantic nodes. Two reasons, and the second is the important one:
 *
 *  1. It is a large schema that changes every library release, and a stale
 *     copy here would reject configuration the library understands perfectly.
 *  2. Most users already have a `firewall.yml`. Re-expressing it in Symfony
 *     config gains them nothing and costs them a translation step.
 *
 * What *is* described semantically is the subset the bundle itself has to
 * know about, because the bundle — not the library — is what acts on it:
 * the mode (it decides whether the process can `exit()`), the challenge path
 * and cookie (it builds the Response), the proxy posture (it bridges
 * Symfony's own setting), and the listener priority.
 */
final class Configuration implements ConfigurationInterface
{
    /**
     * The bundle's configuration root, and the prefix of every service id.
     */
    public const ROOT = 'kanopi_firewall';

    /**
     * Default `kernel.request` priority.
     *
     * Chosen relative to the listeners Symfony registers on the same event:
     *
     * | Priority | Listener                | Why we sit where we do          |
     * |----------|-------------------------|---------------------------------|
     * | 256      | ValidateRequestListener | Runs first: a malformed Host is |
     * |          |                         | the framework's to reject.      |
     * | **250**  | **this bundle**         |                                 |
     * | 128      | SessionListener         | A blocked bot starts no session.|
     * | 32       | RouterListener          | See below — this one matters.   |
     * | 8        | Security's Firewall     | No authentication for traffic   |
     * |          |                         | that is not getting through.    |
     *
     * Running above RouterListener is not a preference, it is the fix for a
     * lockout. The challenge submission path (`challenge.path`, default
     * `/_firewall/challenge`) is deliberately not a route. If the router got
     * there first it would raise a 404 before this listener ever saw the POST,
     * and a challenged visitor would have no way to submit an answer — they
     * would be served the interstitial forever, with no error anywhere saying
     * why. Priority alone guarantees it, so the bundle needs no route, no
     * `ExceptionListener` hook, and no instruction to the user to exclude a
     * path from their routing.
     *
     * Trusted proxies are a separate question and are *not* what this number
     * protects: `Kernel::preBoot()` applies `framework.trusted_proxies` while
     * building the container, which is strictly before any `kernel.request`
     * listener runs. That is precisely the reason to be a listener at all —
     * the integration the library's own docs suggest for Symfony, calling
     * `Firewall::create()->evaluate()` from `public/index.php`, runs *before*
     * the kernel boots, so every rule reads an unfiltered `getClientIp()` and
     * every IP allowlist is one forged `X-Forwarded-For` away from useless.
     */
    public const DEFAULT_PRIORITY = 250;

    /**
     * {@inheritdoc}
     *
     * ## Why this is not one fluent chain
     *
     * The usual `$root->children()->scalarNode(…)->end()->scalarNode(…)` style
     * does not survive static analysis across the supported Symfony range.
     * On 6.4, `NodeBuilder::end()` is typed `NodeParentInterface|null`, so the
     * first `->end()` in a chain degrades everything after it to `mixed` and
     * PHPStan reports every subsequent call as "cannot call method on mixed".
     * It analyses clean on 7.4 and 8.1, which is exactly how the problem
     * stays hidden: a developer on a current Symfony never sees it, and the
     * 6.4 job is the only thing that does.
     *
     * Holding a reference to each node and never calling `end()` is immune to
     * that, and reads at a fixed indent rather than a drifting one.
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder(self::ROOT);
        /** @var ArrayNodeDefinition $root */
        $root = $treeBuilder->getRootNode();
        $children = $root->children();

        $children->enumNode('mode')
            ->values(['enforce', 'observe', 'disabled'])
            ->defaultValue('enforce')
            ->info(
                'enforce: refuse matched requests (library mode `exception`). '
                . 'observe: evaluate and log only, change nothing (library mode `log`). '
                . 'disabled: never evaluate. '
                . 'The library\'s `block` mode is deliberately unreachable — it calls exit().'
            );

        $configFiles = $children->arrayNode('config_files');
        $configFiles->info('Paths to existing kanopi/firewall YAML files, merged in the order given.');
        $configFiles->example(['%kernel.project_dir%/config/firewall.yml']);
        $configFiles->scalarPrototype()->cannotBeEmpty();

        $settings = $children->variableNode('settings');
        $settings->info(
            'An inline kanopi/firewall configuration array, merged after config_files. '
            . 'Passed through verbatim — this bundle does not re-declare the library schema.'
        );
        $settings->defaultValue([]);
        $settings->validate()
            ->ifTrue(static fn(mixed $value): bool => !is_array($value))
            ->thenInvalid('kanopi_firewall.settings must be an array, got %s.');

        $overrides = $children->arrayNode('overrides');
        $overrides->info(
            'PropertyAccess bracket paths applied last, e.g. "[global][banning_status_code]: 403". '
            . '[global][mode] is reserved: it is set from kanopi_firewall.mode.'
        );
        $overrides->normalizeKeys(false);
        $overrides->variablePrototype();

        $children->enumNode('behind_proxy')
            ->values(['auto', true, false])
            ->defaultValue('auto')
            ->info(
                'Bridges Symfony\'s framework.trusted_proxies onto the library\'s global.behind_proxy. '
                . '"auto" asserts true when the kernel has actually applied trusted proxies and asserts '
                . 'nothing otherwise, so the library keeps warning while the posture is genuinely '
                . 'unknown. Set false to say there is no proxy; that is what silences the warning.'
            );

        $children->enumNode('on_startup_failure')
            ->values(['fail_closed', 'fail_open'])
            ->defaultValue('fail_closed')
            ->info(
                'What to do when Firewall::create() throws — bad config, unreachable storage. '
                . 'fail_closed rethrows, so the request errors. fail_open logs at critical and lets '
                . 'the request through unfiltered.'
            );

        $children->enumNode('blocked_response')
            ->values(['plain', 'http_exception'])
            ->defaultValue('plain')
            ->info(
                'plain writes the refusal directly as text/plain — cheap, and it cannot render the '
                . 'banning message as markup. http_exception throws an HttpException instead so your '
                . 'error controller renders the status; the message is dropped, because an error '
                . 'template is HTML and the message can carry client-chosen bytes.'
            );

        $root->append($this->listenerNode());
        $root->append($this->challengeNode());
        $root->append($this->loggingNode());
        $root->append($this->profilerNode());
        $root->append($this->commandsNode());

        return $treeBuilder;
    }

    /**
     * The `listener:` block.
     */
    private function listenerNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('listener');
        $node->addDefaultsIfNotSet();
        $children = $node->children();

        $children->integerNode('priority')
            ->defaultValue(self::DEFAULT_PRIORITY)
            ->info('kernel.request priority. See Configuration::DEFAULT_PRIORITY before lowering it below 32.');

        $children->booleanNode('only_main_requests')
            ->defaultTrue()
            ->info(
                'Skip sub-requests. A forwarded or ESI sub-request carries the same client as the main '
                . 'one, which was already evaluated; evaluating it again double-counts every rate limit.'
            );

        return $node;
    }

    /**
     * The `challenge:` block.
     *
     * These keys exist here as well as in the library's YAML because the
     * bundle is what renders the interstitial and sets the pass cookie in
     * `exception` mode — the library throws instead of writing either. The
     * values are pushed down into the library config too, so there is exactly
     * one place to set them.
     */
    private function challengeNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('challenge');
        $node->addDefaultsIfNotSet();
        $children = $node->children();

        $children->scalarNode('secret')
            ->defaultNull()
            ->info('HMAC key for pass tokens. Null leaves whatever challenge.secret the YAML set.')
            ->example('%env(FIREWALL_CHALLENGE_SECRET)%');

        $children->scalarNode('provider')
            ->defaultNull()
            ->info('math | altcha | turnstile | recaptcha, or an FQCN. Null leaves the YAML value.');

        $children->scalarNode('path')
            ->defaultValue('/_firewall/challenge')
            ->cannotBeEmpty()
            ->info('Where the interstitial POSTs. Must not be a route — see Configuration::DEFAULT_PRIORITY.');

        $children->scalarNode('cookie_name')
            ->defaultValue('fw_challenge_pass')
            ->info('Cookie carrying the pass token. Empty string disables cookie delivery.');

        $children->scalarNode('header_name')
            ->defaultValue('X-Firewall-Challenge')
            ->info('Header an SPA sends instead of the cookie. Empty string disables that path.');

        $children->scalarNode('audience')
            ->defaultNull()
            ->info('Scopes pass tokens to this instance. Null leaves the YAML value.');

        $providerOptions = $children->variableNode('provider_options');
        $providerOptions->defaultValue([]);
        $providerOptions->info(
            'Forwarded to the provider constructor. turnstile/recaptcha require site_key and secret_key.'
        );
        $providerOptions->validate()
            ->ifTrue(static fn(mixed $value): bool => !is_array($value))
            ->thenInvalid('kanopi_firewall.challenge.provider_options must be an array, got %s.');

        $cookie = $children->arrayNode('cookie');
        $cookie->addDefaultsIfNotSet();
        $cookie->info('Attributes for the pass-token cookie. Defaults mirror what the library sets itself.');
        $cookieChildren = $cookie->children();
        $cookieChildren->scalarNode('path')->defaultValue('/');
        $cookieChildren->scalarNode('domain')->defaultNull();
        $cookieChildren->booleanNode('secure')
            ->defaultTrue()
            ->info('Leave true. False is only defensible on a plain-HTTP development host.');
        $cookieChildren->booleanNode('http_only')->defaultTrue();
        $cookieChildren->enumNode('same_site')->values(['lax', 'strict', 'none'])->defaultValue('strict');

        return $node;
    }

    /**
     * The `logging:` block.
     *
     * The library logs through a Monolog `Logger` it builds itself from its
     * own `logger:` config, and `Firewall::create()` installs it
     * unconditionally — so anything the bundle wants to do about logging has
     * to happen after `create()` returns. The three modes are the three
     * defensible answers to "whose handlers win".
     */
    private function loggingNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('logging');
        $node->addDefaultsIfNotSet();
        $children = $node->children();

        $children->enumNode('mode')
            ->values(['replace', 'merge', 'off'])
            ->defaultValue('replace')
            ->info(
                'replace: the library logs to your Monolog channel; its own logger: config is ignored. '
                . 'merge: keep the library\'s handlers and add yours, so a DatabaseHandler audit trail '
                . 'survives. off: leave the library\'s logger alone.'
            );

        $children->scalarNode('channel')
            ->defaultValue('kanopi_firewall')
            ->cannotBeEmpty()
            ->info('Monolog channel. Registered for you via monolog.channels.');

        return $node;
    }

    /**
     * The `profiler:` block.
     */
    private function profilerNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('profiler');
        $node->addDefaultsIfNotSet();
        $children = $node->children();

        $children->enumNode('enabled')
            ->values([true, false, 'auto'])
            ->defaultValue('auto')
            ->info('Collect the decision for the WebProfiler panel. "auto" follows %kernel.debug%.');

        $children->booleanNode('collect_health')
            ->defaultTrue()
            ->info(
                'Also report failed rules and degraded backends in the panel. Both build every rule '
                . 'that is not built yet, so this is skipped on requests the firewall did not evaluate.'
            );

        return $node;
    }

    /**
     * The `commands:` block.
     */
    private function commandsNode(): ArrayNodeDefinition
    {
        $node = new ArrayNodeDefinition('commands');
        $node->addDefaultsIfNotSet();
        $children = $node->children();

        $children->booleanNode('enabled')->defaultTrue();

        $children->scalarNode('bin_dir')
            ->defaultNull()
            ->info('Where the library\'s bin/ scripts live. Null resolves %kernel.project_dir%/vendor/bin.');

        $children->floatNode('timeout')
            ->defaultValue(300.0)
            ->info('Seconds before a wrapped script is killed. 0 disables the timeout.');

        return $node;
    }
}
