<?php

declare(strict_types=1);

namespace Remediate\Channel\Tests;

use PHPUnit\Framework\TestCase;
use Remediate\Channel\BuildCommand;
use Remediate\Engine\Advisory\Db\Database;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The build command without the network: the FriendsOfPHP feed reads a local checkout, --include adds
 * a Packagist-shaped file, the exploit feeds read local copies, and what comes out is a database the
 * plugin's own reader opens.
 */
final class BuildCommandTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/composer-remediate-db-test-' . bin2hex(random_bytes(4));
        mkdir($this->dir . '/security-advisories/acme/helper', 0700, true);
        mkdir($this->dir . '/security-advisories/acme/broken', 0700, true);
        file_put_contents($this->dir . '/security-advisories/acme/helper/CVE-2026-00002.yaml', <<<'YAML'
title: Synthetic FriendsOfPHP advisory for acme/helper
link: https://example.invalid/advisories/CVE-2026-00002
cve: CVE-2026-00002
branches:
    1.0.x:
        time: 2026-02-01 09:00:00
        versions: ['>=1.0.0', '<1.0.9']
reference: composer://acme/helper
YAML);
        file_put_contents($this->dir . '/security-advisories/acme/broken/BROKEN.yaml', "branches: [\nreference: composer://acme/broken\n");
        file_put_contents($this->dir . '/private.json', json_encode(['advisories' => ['acme/vuln-lib' => [[
            'advisoryId' => 'ACME-2026-001',
            'affectedVersions' => '<1.2.0',
            'title' => 'Synthetic private advisory',
            'cve' => 'CVE-2026-00001',
            'severity' => 'high',
            'reportedAt' => '2026-01-15 10:00:00',
        ]]]], JSON_THROW_ON_ERROR));
    }

    protected function tearDown(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($this->dir);
    }

    /** @param array<string, mixed> $options */
    private function build(array $options): CommandTester
    {
        $tester = new CommandTester(new BuildCommand());
        $tester->execute($options + [
            '--source' => ['friendsofphp'],
            '--friendsofphp-path' => $this->dir . '/security-advisories',
            '--include' => [$this->dir . '/private.json'],
            '--enrich' => ['none'],
            '--temp-dir' => $this->dir . '/tmp',
        ]);

        return $tester;
    }

    public function testBuildsFromLocalFeedsAndTheReaderOpensTheResult(): void
    {
        $db = $this->dir . '/advisories.sqlite';
        $tester = $this->build(['--output' => $db]);

        self::assertSame(0, $tester->getStatusCode(), $tester->getDisplay(true));
        self::assertFileExists($db);
        $shown = $tester->getDisplay(true);
        self::assertStringContainsString('Advisory database written: ' . $db, $shown);
        self::assertStringContainsString('2 advisories from 2 source records, 0 with conflicting ranges, 1 coverage gap,', $shown);
        self::assertStringContainsString('composer remediate --database-location=' . $db, $shown);

        $database = Database::open($db, hash_file('sha256', $db) ?: '');
        $advisories = $database->advisoriesFor(['acme/helper', 'acme/vuln-lib']);
        self::assertCount(1, $advisories['acme/helper']);
        self::assertCount(1, $advisories['acme/vuln-lib']);
        self::assertSame('CVE-2026-00001', $advisories['acme/vuln-lib'][0]->cve);
        $meta = $database->meta();
        self::assertSame('1', $meta['gap_count']);
        $sources = json_decode($meta['sources'], true);
        self::assertIsArray($sources);
        self::assertSame(['FriendsOfPHP', 'local:private.json'], array_column($sources, 'name'));
    }

    public function testLocalExploitFeedsEnrichTheDatabase(): void
    {
        $epss = $this->dir . '/epss.csv';
        $kev = $this->dir . '/kev.json';
        file_put_contents($epss, "#model_version:v2025.03.14,score_date:2026-09-09T00:00:00+0000\ncve,epss,percentile\nCVE-2026-00001,0.93412,0.99871\nCVE-2026-00002,0.5,0.5\n");
        file_put_contents($kev, json_encode(['catalogVersion' => '2026.09.09', 'dateReleased' => '2026-09-09T14:00:00Z', 'vulnerabilities' => [['cveID' => 'CVE-2026-00001', 'dateAdded' => '2026-02-01', 'knownRansomwareCampaignUse' => 'Known']]], JSON_THROW_ON_ERROR));
        $db = $this->dir . '/enriched.sqlite';

        $tester = $this->build(['--output' => $db, '--enrich' => ['epss', 'kev'], '--epss-file' => $epss, '--kev-file' => $kev]);

        self::assertSame(0, $tester->getStatusCode(), $tester->getDisplay(true));
        self::assertStringContainsString('exploit data (EPSS / CISA KEV) for 2 CVEs', $tester->getDisplay(true));
        $advisory = Database::open($db, hash_file('sha256', $db) ?: '')->advisoriesFor(['acme/vuln-lib'])['acme/vuln-lib'][0];
        self::assertSame(0.93412, $advisory->epss);
        self::assertSame('2026-02-01', $advisory->kevAdded?->format('Y-m-d'));
    }

    public function testAnUnknownFeedIsAUsageError(): void
    {
        $tester = $this->build(['--source' => ['nvd', 'osv']]);

        self::assertSame(BuildCommand::EXIT_USAGE, $tester->getStatusCode());
        self::assertStringContainsString('Unknown source(s) nvd; choose from packagist, osv, friendsofphp, drupal', $tester->getDisplay(true));
    }

    public function testAnUnknownEnrichmentIsAUsageError(): void
    {
        $tester = $this->build(['--enrich' => ['nvd']]);

        self::assertSame(BuildCommand::EXIT_USAGE, $tester->getStatusCode());
        self::assertStringContainsString('Unknown enrichment(s) nvd; choose from epss, kev or none', $tester->getDisplay(true));
    }

    public function testAFeedThatCannotBeReadFailsTheBuildAndWritesNothing(): void
    {
        // A private file is the operator's own data: one that cannot be read fails the build rather
        // than being skipped, the same way the plugin refuses an unreadable --advisories-file.
        $db = $this->dir . '/none.sqlite';
        $tester = $this->build(['--output' => $db, '--include' => [$this->dir . '/missing.json']]);

        self::assertSame(BuildCommand::EXIT_FAILED, $tester->getStatusCode(), $tester->getDisplay(true));
        self::assertStringContainsString('Build failed:', $tester->getDisplay(true));
        self::assertFileDoesNotExist($db);
    }
}
