# composer-remediate-db

[![Advisory database](https://github.com/hexblot/composer-remediate-db/actions/workflows/advisory-db.yml/badge.svg)](https://github.com/hexblot/composer-remediate-db/releases/tag/advisory-db-latest)
[![ci](https://github.com/hexblot/composer-remediate-db/actions/workflows/ci.yml/badge.svg)](https://github.com/hexblot/composer-remediate-db/actions/workflows/ci.yml)

The release channel for the advisory database that
[composer-remediate](https://github.com/hexblot/composer-remediate) reads. A scheduled workflow builds
the database from the public feeds (Packagist, OSV, FriendsOfPHP and Drupal.org, with EPSS and CISA KEV
exploit data attached) and publishes it as GitHub releases whenever the dataset changes. Fork this
repository to run a channel of your own, with the feeds you choose and advisories of your own included.

The feed readers live here, in `src/`: what each upstream publishes, how its version ranges are read,
and which exploit data is attached. The database format, the merge and the file writer come from the
plugin, which this repository depends on at a pinned version, so a database built here is one the
plugin's reader opens. `bin/build-advisory-db` runs a build; the workflow is the schedule and the
publication around it.

## The published database

```text
https://github.com/hexblot/composer-remediate-db/releases/download/advisory-db-latest/advisories.sqlite
https://github.com/hexblot/composer-remediate-db/releases/download/advisory-db-latest/latest.json
https://github.com/hexblot/composer-remediate-db/releases/download/db-2026-10-08.00/advisories.sqlite
```

Releases are tagged `db-YYYY-MM-DD.HH`; `advisory-db-latest` is a moving pointer to the newest one. Pin
the dated URL in CI configurations that must be reproducible and use the pointer for convenience. Each
release carries the database, its sha256 sidecar, `latest.json` (version, dataset hash, sha256,
publication time, per-source record counts, which plugin version built it) and a GitHub
build-provenance attestation:

```bash
gh attestation verify advisories.sqlite --repo hexblot/composer-remediate-db
sha256sum -c advisories.sqlite.sha256
```

The workflow runs every six hours and publishes only when the dataset hash moved, so `published_at` says
when the data last changed and the workflow's run history says whether ingestion is healthy. A build
that shrinks the dataset by more than 5% is refused rather than published, and a failing run opens an
issue in this repository.

### Pointing a client at it

composer-remediate reads this channel by default from the release after 0.11. Any version can be
pointed at it explicitly:

```bash
composer remediate --database-location=https://github.com/hexblot/composer-remediate-db/releases/download/advisory-db-latest/advisories.sqlite
```

or with `REMEDIATE_DATABASE`, or `extra.remediate.database` in `composer.json`. The client verifies every
download against the publisher's `latest.json` or sha256 sidecar; see
[the advisory database page](https://hexblot.github.io/composer-remediate/advisory-database/) for what is
and is not verified.

### The legacy location

Until this repository existed the database was published from the plugin's own releases, at
`https://github.com/hexblot/composer-remediate/releases/download/advisory-db-latest/advisories.sqlite`,
which is where every client up to 0.11 looks. A workflow in the plugin's repository keeps that
`advisory-db-latest` pointer current from this channel: it fetches what was published here, checks the
checksum and the attestation, and republishes the same bytes there. Those clients keep working; the mirror
stops when composer-remediate 1.0 is released, so a pinned configuration should move to the URL above
before then. Dated releases are no longer created at the old location.

## Building a database by hand

```bash
composer install
bin/build-advisory-db --output=advisories.sqlite
bin/build-advisory-db --output=advisories.sqlite --source=osv --source=friendsofphp --enrich=none
bin/build-advisory-db --output=advisories.sqlite --include=security/private-advisories.json
```

A build with no options reproduces what the reference channel publishes, feeds permitting. `--source`
and `--enrich` choose the feeds; `--include` merges a JSON file in the Packagist API shape with private
or organisational advisories (`advisories/README.md` has the shape); `--friendsofphp-path`, `--epss-file`
and `--kev-file` read local copies instead of downloading. The file is read directly with
`composer remediate --database-location=<path>`, or published on any https server with a `.sha256`
sidecar or a `latest.json` for other machines to keep current from. A build with `--include` carries
advisories you did not publish: it is created readable by its owner only, and a database meant to be
shared is copied or published deliberately.

A public feed that cannot be read fails the build, since a database missing one would answer "not
affected" for everything that feed knows about. An exploit feed that cannot be read is recorded in the
database's metadata and the build goes on without it.

## Running your own channel

1. Fork this repository (public, so the attestation step works; a private fork needs GitHub Enterprise for
   attestations, or drop that step).
2. Edit the `env` block at the top of `.github/workflows/advisory-db.yml`: `DB_SOURCES` and `DB_ENRICH`
   choose the feeds, `DB_INCLUDE` names JSON files under `advisories/` with advisories of your own (see
   `advisories/README.md`).
3. In the repository settings, create an environment named `advisory-db` and limit its deployment
   branches to `main`. GitHub enforces that before the publish job starts, so a workflow dispatched from
   any other branch can build but never publish.
4. Dispatch the workflow once with `force` checked. From then on it runs on its schedule.
5. Point your projects at your fork's `advisory-db-latest` URL as above. For a database you do not
   publish yourself, pin the digest you trust with `--database-sha256`.

The plugin version is pinned exactly in `composer.json`, so what builds the database changes only when
someone changes it: bump the pin to move the channel to a newer plugin. The version used is recorded in
every `latest.json` as `built_with`. A feed reader of your own is a class implementing the plugin's
`AdvisorySourceInterface`, added to `src/Feeds.php`.

## Development

```bash
composer install
composer check        # phpstan, then the tests
```

The tests read no feed: each reader is exercised against scripted responses, and the build command
against a local FriendsOfPHP checkout and local exploit files. The `ci` workflow runs them on every
push and, once, a real build with the channel's own feeds, so that a reader broken by an upstream
change is found by a pull request rather than by the schedule.

## Licences

The code here is MIT. The database aggregates data published under the feeds' own terms, listed on
[the advisory database page](https://hexblot.github.io/composer-remediate/advisory-database/#data-licences).
