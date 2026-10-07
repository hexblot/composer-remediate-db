# Private advisories

A fork that carries advisories of its own puts them here as JSON files in the shape of Packagist's
`/api/security-advisories/` response (see
[the advisory database page](https://hexblot.github.io/composer-remediate/advisory-database/#private-advisories))
and names them in the `DB_INCLUDE` list at the top of `.github/workflows/advisory-db.yml`. Every
database the channel publishes then carries them alongside the public feeds. The reference channel
includes nothing: this directory is empty on purpose.
