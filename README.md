# composer-remediate-db

[![Advisory database](https://github.com/hexblot/composer-remediate-db/actions/workflows/advisory-db.yml/badge.svg)](https://github.com/hexblot/composer-remediate-db/releases/tag/advisory-db-latest)

The release channel for the advisory database that
[composer-remediate](https://github.com/hexblot/composer-remediate) reads. A scheduled workflow builds
the database from the public feeds (Packagist, OSV, FriendsOfPHP and Drupal.org, with EPSS and CISA KEV
exploit data attached) and publishes it as GitHub releases whenever the dataset changes. Fork this
repository to run a channel of your own, with the feeds you choose and advisories of your own included.

This repository holds no PHP code of its own. The build is `composer remediate:db-build`, shipped with
the plugin; what lives here is the schedule, the publication and the configuration.

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
which is where every client up to 0.11 looks. The workflow here mirrors the `advisory-db-latest` pointer to
that location, same bytes and same attestation, so those clients keep working. The mirror stops when
composer-remediate 1.0 is released; a pinned configuration should move to the URL above before then, and
dated releases are no longer created there.

## Running your own channel

1. Fork this repository (public, so the attestation step works; a private fork needs GitHub Enterprise for
   attestations, or drop that step).
2. Edit the `env` block at the top of `.github/workflows/advisory-db.yml`: `DB_SOURCES` and `DB_ENRICH`
   choose the feeds, `DB_INCLUDE` names JSON files under `advisories/` with advisories of your own (see
   `advisories/README.md`), and `LEGACY_REPOSITORY` should be empty.
3. In the repository settings, create an environment named `advisory-db` and limit its deployment
   branches to `main`. GitHub enforces that before the publish job starts, so a workflow dispatched from
   any other branch can build but never publish.
4. Dispatch the workflow once with `force` checked. From then on it runs on its schedule.
5. Point your projects at your fork's `advisory-db-latest` URL as above. For a database you do not
   publish yourself, pin the digest you trust with `--database-sha256`.

The plugin version is pinned exactly in `composer.json`, so what builds the database changes only when
someone changes it: bump the pin to move the channel to a newer plugin. The
version used is recorded in every `latest.json` as `built_with`.

## Licences

The workflow and configuration here are MIT. The database aggregates data published under the feeds'
own terms, listed on
[the advisory database page](https://hexblot.github.io/composer-remediate/advisory-database/#data-licences).
