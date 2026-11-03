<?php

declare(strict_types=1);

namespace Remediate\Channel;

use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\Db\DatabaseBuilder;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Advisory\Db\Merger;
use Remediate\Engine\Advisory\Db\OperatorConfiguration;
use Remediate\Engine\Planner;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `bin/build-advisory-db`: fetch the selected feeds, merge, enrich, write one SQLite file. The release
 * workflow runs it; so does anyone building a database with private advisories for their own use.
 *
 * Exit codes: 0 written, 1 an option this cannot act on, 2 a feed that could not be read (nothing is
 * written: a database missing a public feed would answer "not affected" for everything that feed
 * knows about, and the client refuses to use such a build in place of the published one).
 */
final class BuildCommand extends Command
{
    public const EXIT_USAGE = 1;
    public const EXIT_FAILED = 2;

    protected function configure(): void
    {
        $this
            ->setName('build')
            ->setDescription('Build the advisory database (SQLite) from the feeds: Packagist, OSV, FriendsOfPHP and Drupal.org, with EPSS and CISA KEV exploit data')
            ->setDefinition([
                new InputOption('output', 'o', InputOption::VALUE_REQUIRED, 'Where to write the database', 'advisories.sqlite'),
                new InputOption('source', 's', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Feed to include: ' . implode(', ', Feeds::SOURCES) . ' (repeatable; default all)'),
                new InputOption('friendsofphp-path', null, InputOption::VALUE_REQUIRED, 'Local checkout of FriendsOfPHP/security-advisories to read instead of downloading'),
                new InputOption('include', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Additional JSON file in the Packagist API shape with private or organisational advisories (repeatable)'),
                new InputOption('enrich', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Exploit data to attach to the CVEs: epss (FIRST exploit probability), kev (CISA Known Exploited Vulnerabilities), or none (repeatable; default both)'),
                new InputOption('epss-file', null, InputOption::VALUE_REQUIRED, 'Local copy of the EPSS scores CSV (plain or .gz) to read instead of downloading'),
                new InputOption('kev-file', null, InputOption::VALUE_REQUIRED, 'Local copy of the CISA KEV catalogue JSON to read instead of downloading'),
                new InputOption('temp-dir', null, InputOption::VALUE_REQUIRED, 'Where downloaded archives are unpacked', sys_get_temp_dir() . '/composer-remediate-db'),
            ])
            ->setHelp(<<<'HELP'
Pulls every advisory for the Packagist ecosystem from the selected feeds (plus any <info>--include</info>
files with private advisories), normalises the version ranges to Composer constraints, merges records
that share an identifier (CVE, GHSA, PKSA, FriendsOfPHP file), keeps every source's range and flags
disagreements, and writes a single SQLite file that <info>composer remediate</info> reads.

Every CVE in the database is enriched with its EPSS exploit probability and its CISA KEV listing when
present (<info>--enrich</info>). A feed that cannot be fetched fails the build; an enrichment that cannot
be fetched is recorded in the database's metadata and the build continues without it.

The file is portable: publish it on a web server or as a release asset with a <info>.sha256</info>
sidecar (or a latest.json) and point clients at the URL with <info>--database-location</info>, or read
it directly with <info>composer remediate --database-location=<path></info>.
HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $errors = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        $str = static fn (string $name): ?string => is_string($v = $input->getOption($name)) && $v !== '' ? $v : null;
        $list = static fn (string $name): array => array_values(array_filter(array_map('strval', (array) $input->getOption($name)), static fn (string $v): bool => $v !== ''));
        $path = (string) $input->getOption('output');
        $tempDir = (string) $input->getOption('temp-dir');

        $downloader = (new OperatorConfiguration())->httpDownloader();
        try {
            $sources = Feeds::sources($downloader, $tempDir, $list('source'), $str('friendsofphp-path'), $list('include'));
            $enrichments = Feeds::enrichments($downloader, $tempDir, $list('enrich'), $str('epss-file'), $str('kev-file'));
        } catch (\InvalidArgumentException $e) {
            $errors->writeln('<error>' . self::safe($e->getMessage()) . '</error>');

            return self::EXIT_USAGE;
        }

        $log = static function (string $message) use ($errors): void {
            $errors->writeln('<comment>' . self::safe($message) . '</comment>');
        };
        try {
            $result = (new DatabaseBuilder($sources, new Merger(), new DatabaseWriter(), $enrichments))->build($path, $log, ['engine_version' => Planner::engineVersion()]);
        } catch (AdvisoryLookupFailed|\RuntimeException $e) {
            $errors->writeln('<error>Build failed: ' . self::safe($e->getMessage()) . '</error>');

            return self::EXIT_FAILED;
        }

        $output->writeln(sprintf('<info>Advisory database written:</info> %s', $result['path']));
        $output->writeln(sprintf('  %d advisories from %d source records, %d with conflicting ranges, %d coverage gap%s, %.1f MB', $result['advisories'], $result['records'], $result['conflicts'], $result['gaps'], $result['gaps'] === 1 ? '' : 's', $result['bytes'] / 1048576));
        if ($result['gaps'] > 0) {
            $output->writeln('  Coverage gaps are upstream records the build could not interpret; they are stored in the database and reported by composer remediate for packages in the lock. List them with composer remediate:db-status.');
        }
        if ($enrichments !== []) {
            $output->writeln(self::safe(sprintf('  exploit data (EPSS / CISA KEV) for %d CVE%s%s', $result['exploits'], $result['exploits'] === 1 ? '' : 's', $result['enrichment_errors'] !== [] ? '; unavailable: ' . implode('; ', $result['enrichment_errors']) : '')));
        }
        $output->writeln(sprintf('  dataset hash %s', $result['hash']));
        $output->writeln(sprintf('Use it with: <comment>composer remediate --database-location=%s</comment>', $result['path']));

        return 0;
    }

    /** Console markup in text that came from a feed or a file name is not markup. */
    private static function safe(string $text): string
    {
        return str_replace(['<', '>'], ['\\<', '\\>'], $text);
    }
}
