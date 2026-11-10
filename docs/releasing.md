# Releasing

Every module releases together under one version, `v<version>`, to Maven Central under the
`ai.keycard` group. `keycard-bom` pins them, so a consumer picks one version for all of them.

## The path a change takes

1. A PR merges to `main` with a squash subject such as `feat(oauth): device grant`.
2. `main.yml` runs `scripts/changelog.py changes`, which asks commitizen whether anything since
   the last `v*` tag matches the release types below.
3. If so, it calls `bump-package.yml`, which runs `scripts/bump_package.py`: `cz bump
   --files-only` rewrites `.cz.toml`, `gradle.properties` and `CHANGELOG.md`, the release app
   opens a bump PR, merges it once checks are green, and creates `v<version>` at the squash SHA.
4. That tag triggers `release.yml`, which checks the tag against `gradle.properties`, builds and
   tests every module, signs them, uploads one deployment to the Central Portal, releases it,
   and waits until `keycard-bom` resolves from `repo1.maven.org`.

## Commit types

Releasable types are `feat`, `fix`, `refactor`, `perf`, `test`, `build`, `ci` and `revert`;
`docs`, `chore` and `style` never cut a release. The scope is free-form (`feat(spring):`,
`fix(mcp):`, or none), because every module ships together. `feat` is a minor, `fix`,
`refactor` and `perf` are patches, and `!` before the colon is a major. While
`major_version_zero = true` in `.cz.toml` a major lands as a minor; flip it to `false` at 1.0.0.

Squash merges are what `main` sees, so the PR title is the commit subject. CI validates PR
commit messages with `cz check`.

Never hand-edit the version in `gradle.properties` or `.cz.toml`, or `CHANGELOG.md`: `cz bump`
owns all three, and `changelog.py check-drift` fails CI when the two version lines disagree.

## Repo settings this depends on

| Setting | Value |
| --- | --- |
| Variable `SDK_RELEASE_APP_ID` | the Keycard SDK Release app id |
| Secret `SDK_RELEASE_PRIVATE_KEY` | that app's private key |
| Environment `release` | holds the five secrets below; restrict it to `v*` tags |
| Allow auto-merge, squash merge | enabled |

`main.yml` skips the bump while `SDK_RELEASE_APP_ID` is unset and logs a warning, so an
unconfigured repo is visible rather than quiet.

| `release` secret | What it is |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` | the user-token name from central.sonatype.com, Account, Generate User Token |
| `MAVEN_CENTRAL_PASSWORD` | the user-token password from the same screen |
| `SIGNING_KEY` | the ASCII-armored private OpenPGP key (`gpg --armor --export-secret-keys <id>`) |
| `SIGNING_KEY_ID` | the key's last 8 hex digits |
| `SIGNING_KEY_PASSWORD` | the key's passphrase |

The `ai.keycard` namespace is verified on the Central Portal through a DNS TXT record on
keycard.ai.

## Key custody and rotation

The signing key and the Portal token live only in the `release` environment and in the
company password manager, owned by the SDK team. Nobody signs a release from a laptop.

The public half of the signing key must be on a keyserver Central checks
(`gpg --keyserver keys.openpgp.org --send-keys <id>`), or Central rejects the deployment.
Give the key a two-year expiry and calendar the renewal.

To rotate the signing key: generate a new key, publish its public half, replace `SIGNING_KEY`,
`SIGNING_KEY_ID` and `SIGNING_KEY_PASSWORD`, run a release, and only then revoke the old key.
Artifacts already on Central stay verifiable against the old public key.

To rotate the Portal token: generate a new user token, replace the two `MAVEN_CENTRAL_*`
secrets, then revoke the old token on the Portal. If the token or key leaks, revoke first and
replace second; a release can wait.

## The first release

`v0.1.0` is tagged by hand, because until a `v*` tag exists commitizen counts every commit ever
made and the first automated bump would skip to 0.2.0. `main.yml` holds off until the tag
exists.

```sh
git checkout main && git pull
python3 scripts/changelog.py check-drift      # gradle.properties and .cz.toml both say 0.1.0
git tag v0.1.0 && git push origin v0.1.0      # release.yml publishes
```

Then check the artifacts from a clean Gradle and a clean Maven project outside the repo.

## Proving the pipeline without a real change

Run `bump-package.yml` from the Actions tab with `increment` forced to `patch`. It opens a bump
PR, merges it, tags it, and the tag publishes. Do this only once the first release is out;
every run publishes a real version.

## When something goes wrong

| What happened | What to do |
| --- | --- |
| The bump PR merged but no tag appeared (the merge wait timed out) | Re-run `bump-package.yml`. `bump_package.py` finds the merged bump commit without a tag and pushes the tag instead of bumping again. |
| `release.yml` failed before the Portal upload | Fix the cause and re-run the workflow on the same tag. |
| The Portal rejected the deployment (a signature or POM problem) | Nothing was released. Fix it on `main` and cut the next patch; Central never accepts the same version twice. |
| The release succeeded but `keycard-bom` didn't resolve within 30 minutes | Check the deployment on the Portal. Publication sometimes lags, and re-running only the wait is safe. |
