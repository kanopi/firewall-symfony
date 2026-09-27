<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-symfony package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\FirewallBundle\Tests\Unit\Command;

use Kanopi\FirewallBundle\Command\StorageFileWiring;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;

/**
 * What `kanopi:firewall:init` does to an application after writing the YAML.
 */
#[CoversClass(StorageFileWiring::class)]
final class StorageFileWiringTest extends TestCase
{
    /**
     * A throwaway project directory.
     */
    private string $project;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        $this->project = sys_get_temp_dir() . '/kanopi-firewall-wiring-' . bin2hex(random_bytes(4));
        (new Filesystem())->mkdir($this->project);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->project);
    }

    public function testANewApplicationGetsAllThreeHalves(): void
    {
        $lines = $this->wire();

        self::assertStringContainsString(
            'FIREWALL_STORAGE_FILE="%kernel.project_dir%/var/firewall/blocked.data"',
            $this->read('.env')
        );
        self::assertDirectoryExists($this->project . '/var/firewall', 'the library creates the file, not the directory');
        self::assertSame(
            [
                'kanopi_firewall' => [
                    'config_files' => ['%kernel.project_dir%/config/firewall.yml'],
                    'storage_file' => '%env(resolve:FIREWALL_STORAGE_FILE)%',
                ],
            ],
            Yaml::parse($this->read('config/packages/kanopi_firewall.yaml'))
        );
        self::assertCount(3, $lines);
    }

    public function testTheEnvBlockIsFlexsSoARecipeRecognisesIt(): void
    {
        $this->wire();

        self::assertStringContainsString('###> kanopi/firewall-symfony ###', $this->read('.env'));
        self::assertStringContainsString('###< kanopi/firewall-symfony ###', $this->read('.env'));
    }

    public function testAnExistingValueInEnvIsTheOperatorsAndIsKept(): void
    {
        $this->write('.env', "APP_ENV=dev\nFIREWALL_STORAGE_FILE=/srv/firewall/blocked.data\n");

        $lines = $this->wire();

        self::assertSame("APP_ENV=dev\nFIREWALL_STORAGE_FILE=/srv/firewall/blocked.data\n", $this->read('.env'));
        self::assertStringContainsString('already defines', $lines[0]);
    }

    public function testAnExportedValueCountsAsDefined(): void
    {
        $this->write('.env', "export FIREWALL_STORAGE_FILE=/srv/blocked.data\n");

        $this->wire();

        self::assertSame("export FIREWALL_STORAGE_FILE=/srv/blocked.data\n", $this->read('.env'));
    }

    public function testAnEnvWithNoTrailingNewlineIsAppendedToCleanly(): void
    {
        $this->write('.env', 'APP_ENV=dev');

        $this->wire();

        self::assertStringStartsWith("APP_ENV=dev\n\n###> kanopi/firewall-symfony ###", $this->read('.env'));
    }

    public function testAnExistingBundleConfigGetsTheLineAtItsOwnIndent(): void
    {
        $this->write('config/packages/kanopi_firewall.yaml', "kanopi_firewall:\n  mode: observe\n  config_files:\n    - '%kernel.project_dir%/config/firewall.yml'\n");

        $this->wire();

        $config = Yaml::parse($this->read('config/packages/kanopi_firewall.yaml'));

        self::assertIsArray($config);
        self::assertSame(
            [
                'storage_file' => '%env(resolve:FIREWALL_STORAGE_FILE)%',
                'mode' => 'observe',
                'config_files' => ['%kernel.project_dir%/config/firewall.yml'],
            ],
            $config['kanopi_firewall']
        );
    }

    public function testABundleConfigThatAlreadySetsStorageFileIsKept(): void
    {
        $original = "kanopi_firewall:\n    storage_file: '/srv/blocked.data'\n";
        $this->write('config/packages/kanopi_firewall.yaml', $original);

        $this->wire();

        self::assertSame($original, $this->read('config/packages/kanopi_firewall.yaml'));
    }

    public function testABundleConfigItCannotReadIsReportedRatherThanRewritten(): void
    {
        $original = "kanopi_firewall: { mode: observe }\n";
        $this->write('config/packages/kanopi_firewall.yaml', $original);

        $lines = $this->wire();

        self::assertSame($original, $this->read('config/packages/kanopi_firewall.yaml'));
        self::assertStringContainsString(StorageFileWiring::STORAGE_FILE_LINE, $lines[2]);
    }

    public function testAnOutputOutsideTheProjectIsListedAsItIs(): void
    {
        (new StorageFileWiring($this->project))->apply('/etc/firewall/site.yml', $this->project);

        $config = Yaml::parse($this->read('config/packages/kanopi_firewall.yaml'));

        self::assertIsArray($config);
        self::assertIsArray($config['kanopi_firewall']);
        self::assertSame(['/etc/firewall/site.yml'], $config['kanopi_firewall']['config_files']);
    }

    public function testARelativeOutputIsResolvedAgainstWhereTheScriptRan(): void
    {
        (new StorageFileWiring($this->project))->apply('site/firewall.yml', $this->project . '/config');

        $config = Yaml::parse($this->read('config/packages/kanopi_firewall.yaml'));

        self::assertIsArray($config);
        self::assertIsArray($config['kanopi_firewall']);
        self::assertSame(['%kernel.project_dir%/config/site/firewall.yml'], $config['kanopi_firewall']['config_files']);
    }

    public function testAnExistingDirectoryIsNotAnError(): void
    {
        (new Filesystem())->mkdir($this->project . '/var/firewall');

        self::assertSame('var/firewall/ already exists.', $this->wire()[1]);
    }

    public function testAProjectItCannotWriteToIsReportedRatherThanFatal(): void
    {
        // A read-only checkout: the YAML was written somewhere else, and
        // this still has to say what to do by hand rather than throw.
        chmod($this->project, 0500);

        try {
            if (is_writable($this->project)) {
                self::markTestSkipped('Running as a user who can write a read-only directory.');
            }

            $lines = (new StorageFileWiring($this->project))->apply('/etc/firewall.yml', $this->project);
        } finally {
            chmod($this->project, 0700);
        }

        self::assertStringContainsString(StorageFileWiring::ENV_BLOCK, $lines[0], 'what to add by hand');
        self::assertStringContainsString('Could not create', $lines[1]);
        self::assertStringContainsString('Could not create', $lines[2]);
        self::assertStringContainsString(StorageFileWiring::STORAGE_FILE_LINE, $lines[2]);
    }

    public function testFilesItCannotWriteAreReportedWithWhatToAdd(): void
    {
        // The directories exist and are writable; the files are not. Each
        // write says what it would have added.
        $this->write('.env', "APP_ENV=dev\n");
        $this->write('config/packages/kanopi_firewall.yaml', "kanopi_firewall:\n    mode: observe\n");
        chmod($this->project . '/.env', 0400);
        chmod($this->project . '/config/packages/kanopi_firewall.yaml', 0400);

        try {
            if (is_writable($this->project . '/.env')) {
                self::markTestSkipped('Running as a user who can write a read-only file.');
            }

            $lines = $this->wire();
        } finally {
            chmod($this->project . '/.env', 0600);
            chmod($this->project . '/config/packages/kanopi_firewall.yaml', 0600);
        }

        self::assertStringContainsString('Could not write', $lines[0]);
        self::assertStringContainsString('Could not write', $lines[2]);
        self::assertStringContainsString(StorageFileWiring::STORAGE_FILE_LINE, $lines[2]);
        self::assertSame("APP_ENV=dev\n", $this->read('.env'));
    }

    public function testABundleConfigDirectoryItCannotWriteIntoIsReported(): void
    {
        (new Filesystem())->mkdir($this->project . '/config/packages');
        chmod($this->project . '/config/packages', 0500);

        try {
            if (is_writable($this->project . '/config/packages')) {
                self::markTestSkipped('Running as a user who can write a read-only directory.');
            }

            $lines = $this->wire();
        } finally {
            chmod($this->project . '/config/packages', 0700);
        }

        self::assertStringContainsString('Could not write', $lines[2]);
    }

    /**
     * Run the wiring as `init` would, with the default output.
     *
     * @return array<int, string>
     *   What it reported.
     */
    private function wire(): array
    {
        return (new StorageFileWiring($this->project))->apply('config/firewall.yml', $this->project);
    }

    /**
     * A file under the project.
     */
    private function read(string $path): string
    {
        return (string) file_get_contents($this->project . '/' . $path);
    }

    /**
     * Write a file under the project, making its directory.
     */
    private function write(string $path, string $contents): void
    {
        (new Filesystem())->dumpFile($this->project . '/' . $path, $contents);
    }
}
