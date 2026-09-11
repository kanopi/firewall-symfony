<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Composer\InstalledVersions;
use Kanopi\Firewall\Utility\BlockList;
use Kanopi\FirewallBundle\CacheWarmer\ChallengeConfigWarmer;
use Kanopi\FirewallBundle\Command\BlockCommand;
use Kanopi\FirewallBundle\Command\BlocksCommand;
use Kanopi\FirewallBundle\Command\CheckCommand;
use Kanopi\FirewallBundle\Command\ConfigCommand;
use Kanopi\FirewallBundle\Command\DoctorCommand;
use Kanopi\FirewallBundle\Command\EffectiveConfig;
use Kanopi\FirewallBundle\Command\FindReferenceCommand;
use Kanopi\FirewallBundle\Command\HealthCommand;
use Kanopi\FirewallBundle\Command\InitCommand;
use Kanopi\FirewallBundle\Command\LogPruneCommand;
use Kanopi\FirewallBundle\Command\MigrateCommand;
use Kanopi\FirewallBundle\Command\RuleCommand;
use Kanopi\FirewallBundle\Command\RulesCommand;
use Kanopi\FirewallBundle\Command\ScriptRunner;
use Kanopi\FirewallBundle\Command\SourcesCommand;
use Kanopi\FirewallBundle\Command\StatusCommand;
use Kanopi\FirewallBundle\Command\UnblockCommand;
use Kanopi\FirewallBundle\DataCollector\FirewallDataCollector;
use Kanopi\FirewallBundle\Diagnostics\IntegrationDoctor;
use Kanopi\FirewallBundle\EventListener\DecisionRecorder;
use Kanopi\FirewallBundle\EventListener\FirewallRequestListener;
use Kanopi\FirewallBundle\Firewall\BlockManager;
use Kanopi\FirewallBundle\Firewall\ConfigSnapshot;
use Kanopi\FirewallBundle\Firewall\FirewallFactory;
use Kanopi\FirewallBundle\Firewall\LoggerBridge;
use Kanopi\FirewallBundle\Firewall\ProxyPosture;
use Kanopi\FirewallBundle\Firewall\StatusReport;
use Kanopi\FirewallBundle\Http\ChallengeConfigResolver;
use Kanopi\FirewallBundle\Http\ChallengeRenderer;
use Kanopi\FirewallBundle\Http\FirewallResponseFactory;

// Every service the bundle registers.
//
// All of them are private. The bundle's surface is its configuration and its
// commands, not its object graph, and a public service is a promise about
// class names that a bundle at 1.0 should not be making. The two an
// application might genuinely want to reach -- FirewallFactory for a health
// endpoint, DecisionRecorder for a custom error page -- are aliased to their
// class names, so autowiring finds them without anything being fetched from
// the container by string.
//
// The commands are registered in two groups. The wrappers around the
// library's bin/ scripts share ScriptRunner and EffectiveConfig and declare
// their own options -- see AbstractScriptCommand. The native ones answer
// without a subprocess, because there is no script to forward to: adding a
// block, lifting one, finding a reference, reporting health, and printing
// the merged configuration are all things the library's scripts cannot do.
//
// Every command carries a short `kfw:` alias, because `kanopi:firewall:` is
// 17 characters of prefix and an incident is not the moment to type it. The
// canonical name stays vendor-qualified for the reason Configuration
// explains: "firewall" in a Symfony application already means an
// authentication zone.
return static function (ContainerConfigurator $containerConfigurator): void {
    $services = $containerConfigurator->services()
        ->defaults()
        ->private()
        ->autoconfigure(false);

    $services->set('kanopi_firewall.logger_bridge', LoggerBridge::class)
        ->args([
            param('kanopi_firewall.logging.mode'),
            // A null second argument when MonologBundle is absent: the
            // extension has already forced the mode to `off` in that case,
            // so the service is inert rather than broken.
            service('monolog.logger.%kanopi_firewall.logging.channel%')->nullOnInvalid(),
        ]);

    $services->set('kanopi_firewall.proxy_posture', ProxyPosture::class)
        ->args([param('kanopi_firewall.behind_proxy')]);

    $services->set('kanopi_firewall.firewall_factory', FirewallFactory::class)
        ->args([
            param('kanopi_firewall.library_configs'),
            param('kanopi_firewall.library_overrides'),
            service('kanopi_firewall.proxy_posture'),
            service('kanopi_firewall.logger_bridge'),
            param('kanopi_firewall.on_startup_failure'),
            service('logger')->nullOnInvalid(),
            // Symfony's dispatcher is a PSR-14 dispatcher, so the library's
            // third `create()` argument takes it directly — no adapter, and
            // the application's own listeners on the decision events are
            // registered the ordinary way.
            service('event_dispatcher'),
        ]);
    $services->alias(FirewallFactory::class, 'kanopi_firewall.firewall_factory');

    $services->set('kanopi_firewall.decision_recorder', DecisionRecorder::class)
        ->tag('kernel.event_subscriber');
    $services->alias(DecisionRecorder::class, 'kanopi_firewall.decision_recorder');

    $services->set('kanopi_firewall.challenge_config_resolver', ChallengeConfigResolver::class)
        ->args([
            param('kanopi_firewall.library_configs'),
            param('kanopi_firewall.library_overrides'),
        ]);

    $services->set('kanopi_firewall.challenge_renderer', ChallengeRenderer::class)
        ->args([
            service('kanopi_firewall.challenge_config_resolver'),
            service('kanopi_firewall.decision_recorder'),
        ]);

    $services->set('kanopi_firewall.response_factory', FirewallResponseFactory::class)
        ->args([
            service('kanopi_firewall.challenge_renderer'),
            service('kanopi_firewall.challenge_config_resolver'),
            service('kanopi_firewall.decision_recorder'),
            param('kanopi_firewall.challenge.cookie'),
            param('kanopi_firewall.blocked_response'),
        ]);

    $services->set('kanopi_firewall.request_listener', FirewallRequestListener::class)
        ->args([
            service('kanopi_firewall.firewall_factory'),
            service('kanopi_firewall.response_factory'),
            service('kanopi_firewall.decision_recorder'),
            param('kanopi_firewall.mode'),
            param('kanopi_firewall.challenge.path'),
            param('kanopi_firewall.listener.only_main_requests'),
            service('logger')->nullOnInvalid(),
        ])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.request',
            'method' => '__invoke',
            'priority' => '%kanopi_firewall.listener.priority%',
        ]);

    $services->set('kanopi_firewall.challenge_config_warmer', ChallengeConfigWarmer::class)
        ->args([service('kanopi_firewall.challenge_config_resolver')])
        ->tag('kernel.cache_warmer');

    $services->set('kanopi_firewall.data_collector', FirewallDataCollector::class)
        ->args([
            service('kanopi_firewall.decision_recorder'),
            service('kanopi_firewall.firewall_factory'),
            param('kanopi_firewall.mode'),
            param('kanopi_firewall.profiler.collect_health'),
        ])
        ->tag('data_collector', [
            'id' => FirewallDataCollector::NAME,
            'template' => '@KanopiFirewall/Collector/firewall.html.twig',
            // Late, so the panel sits with the other security-adjacent ones
            // rather than in front of the request itself.
            'priority' => -260,
        ]);

    $services->set('kanopi_firewall.effective_config', EffectiveConfig::class)
        ->args([
            param('kanopi_firewall.library_configs'),
            param('kanopi_firewall.library_overrides'),
            service('kanopi_firewall.proxy_posture'),
        ]);

    $services->set('kanopi_firewall.script_runner', ScriptRunner::class)
        ->args([
            param('kanopi_firewall.commands.bin_dir'),
            param('kanopi_firewall.commands.timeout'),
        ]);

    $services->set('kanopi_firewall.config_snapshot', ConfigSnapshot::class)
        ->args([
            param('kanopi_firewall.library_configs'),
            param('kanopi_firewall.library_overrides'),
        ]);

    // The library's own class, registered as a service so the native block
    // commands can be handed it. Its constructor only stores the config
    // inputs -- storage is opened on first use -- so registering it eagerly
    // costs nothing per request.
    //
    // Given `library_configs` and not the effective configuration: the
    // overrides the bundle applies are the mode, the challenge path and the
    // challenge secret, none of which a storage backend reads. Materializing
    // them here would mean writing a temp file to answer "who is blocked".
    $services->set('kanopi_firewall.block_list', BlockList::class)
        ->args([param('kanopi_firewall.library_configs')]);

    $services->set('kanopi_firewall.block_manager', BlockManager::class)
        ->args([service('kanopi_firewall.block_list')]);
    $services->alias(BlockManager::class, 'kanopi_firewall.block_manager');

    $services->set('kanopi_firewall.integration_doctor', IntegrationDoctor::class)
        ->args([
            param('kanopi_firewall.mode'),
            param('kanopi_firewall.listener.priority'),
            param('kanopi_firewall.listener.only_main_requests'),
            param('kanopi_firewall.challenge.path'),
            param('kanopi_firewall.commands.bin_dir'),
            param('kanopi_firewall.logging.mode'),
            param('kanopi_firewall.on_startup_failure'),
            param('kanopi_firewall.library_configs'),
            service('kanopi_firewall.proxy_posture'),
            service('kanopi_firewall.config_snapshot'),
            // Absent in an application with no routing, where there is
            // nothing for the challenge path to collide with.
            service('router')->nullOnInvalid(),
        ]);

    $services->set('kanopi_firewall.status_report', StatusReport::class)
        ->args([
            param('kanopi_firewall.mode'),
            param('kanopi_firewall.listener.priority'),
            param('kanopi_firewall.logging.mode'),
            param('kanopi_firewall.commands.bin_dir'),
            // Resolved here rather than in the class that reports it,
            // because Composer's runtime API is an environment fact and a
            // class that probed for it would carry a branch for "Composer is
            // not installed" that no test in a Composer-installed package
            // can reach.
            InstalledVersions::isInstalled('kanopi/firewall')
                ? (InstalledVersions::getPrettyVersion('kanopi/firewall') ?? 'unknown')
                : 'unknown',
            param('kanopi_firewall.library_configs'),
            service('kanopi_firewall.config_snapshot'),
            service('kanopi_firewall.firewall_factory'),
            service('kanopi_firewall.block_manager'),
        ]);

    // Wrappers around the shipped scripts. Every one of them takes the same
    // two collaborators; the differences are declared in the classes.
    $scriptCommands = [
        'check' => CheckCommand::class,
        'blocks' => BlocksCommand::class,
        'rule' => RuleCommand::class,
        'sources' => SourcesCommand::class,
        'migrate' => MigrateCommand::class,
        'log-prune' => LogPruneCommand::class,
        'init' => InitCommand::class,
    ];

    foreach ($scriptCommands as $name => $class) {
        $services->set('kanopi_firewall.command.' . $name, $class)
            ->args([
                service('kanopi_firewall.script_runner'),
                service('kanopi_firewall.effective_config'),
            ])
            ->tag('console.command', [
                // Pipe-separated: the first is the name, the rest are
                // aliases. That is AddConsoleCommandPass's own encoding.
                'command' => 'kanopi:firewall:' . $name . '|kfw:' . $name,
            ]);
    }

    // Registered on its own because it runs the bundle's own checks before
    // the script's, so it takes a collaborator the other wrappers do not.
    $services->set('kanopi_firewall.command.doctor', DoctorCommand::class)
        ->args([
            service('kanopi_firewall.script_runner'),
            service('kanopi_firewall.effective_config'),
            service('kanopi_firewall.integration_doctor'),
        ])
        ->tag('console.command', ['command' => 'kanopi:firewall:doctor|kfw:doctor']);

    // name => [class, the one service it needs]
    $nativeCommands = [
        'status' => [StatusCommand::class, 'kanopi_firewall.status_report'],
        'health' => [HealthCommand::class, 'kanopi_firewall.firewall_factory'],
        'rules' => [RulesCommand::class, 'kanopi_firewall.config_snapshot'],
        'config' => [ConfigCommand::class, 'kanopi_firewall.config_snapshot'],
        'block' => [BlockCommand::class, 'kanopi_firewall.block_manager'],
        'unblock' => [UnblockCommand::class, 'kanopi_firewall.block_manager'],
        'find-reference' => [FindReferenceCommand::class, 'kanopi_firewall.block_manager'],
    ];

    foreach ($nativeCommands as $name => [$class, $dependency]) {
        $services->set('kanopi_firewall.command.' . $name, $class)
            ->args([service($dependency)])
            ->tag('console.command', ['command' => 'kanopi:firewall:' . $name . '|kfw:' . $name]);
    }
};
