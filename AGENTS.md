# AGENTS.md

Context for coding agents working in `keycardai/java-sdk`. `CLAUDE.md` points here.

## What this repo is

The Keycard Java SDK: a Gradle multi-module build (Kotlin DSL) publishing to Maven Central under group `ai.keycard`. Every module releases together under one lockstep version (`version=` in `gradle.properties`).

| Module | Package | What it is | Depends on |
| --- | --- | --- | --- |
| `keycard-oauth` | `ai.keycard.oauth` | OAuth 2.0 for Keycard zones: token exchange, client credentials, auth code + PKCE, device grant, DCR, discovery, UserInfo, credentials, JWT/JWKS verification, AccessContext. Only runtime dep: Nimbus JOSE + JWT. | none |
| `keycard-spiffe` | `ai.keycard.spiffe` | SPIFFE JWT-SVID workload identity source (Preview). Separate so `keycard-oauth` never pulls in gRPC. | oauth |
| `keycard-mcp` | `ai.keycard.mcp` | MCP server auth on Jakarta Servlet 6.0: bearer filter, metadata servlets, grant filter. Servlet API is `compileOnlyApi`, rewritten to `provided` in the POM. | oauth |
| `keycard-spring-boot-starter` | `ai.keycard.spring.boot` | Spring Boot 4 auto-configuration on Spring Security's resource server, `@KeycardGrant` | mcp |
| `keycard-a2a` | `ai.keycard.a2a` | Agent-to-agent delegation over A2A 1.0 | oauth |
| `keycard-bom` | | `java-platform` BOM pinning every module to one version | all |

- Dependency direction: everything builds on `keycard-oauth`. Keep its runtime deps to Nimbus only (no Jackson; see `docs/idiom-profile.md`, JSON).
- New modules must be added to `settings.gradle.kts` and to `keycard-bom`'s constraints.
- `build-logic/` holds the convention plugins every module applies instead of configuring itself:
  - `keycard.java-library`: `--release 17`, `-Xlint:all -Werror -parameters`, Javadoc `-Xdoclint:all -Werror`, JSpecify as `api`, JUnit Jupiter + AssertJ for tests, Spotless with palantir-java-format, `Automatic-Module-Name` = `ai.keycard.<module>`, LICENSE in every jar.
  - `keycard.publishing`: `com.vanniktech.maven.publish` to Central, POM metadata, signing only when `signingInMemoryKey` is set.
- Versions live in `gradle/libs.versions.toml`. `settings.gradle.kts` sets `FAIL_ON_PROJECT_REPOS`, so do not add repositories in module builds.
- `examples/` (`mcp-server-servlet`, `mcp-server-spring-ai`, `a2a-delegation`) are separate Gradle builds that consume the SDK from source via `includeBuild("../..")`.
- Design reference: `docs/idiom-profile.md` (how the shared contract maps to Java, with reasons), `docs/conformance-report.md`, `docs/releasing.md`.

## Setup, build, test (as CI runs them)

JDK 17 or newer. Always use the wrapper.

```sh
./gradlew build publishToMavenLocal --console=plain   # compile, tests, Javadoc, spotlessCheck, every module
examples/mcp-server-servlet/bin/selftest
examples/a2a-delegation/bin/selftest
examples/mcp-server-spring-ai/bin/selftest
```

- CI (`.github/workflows/ci.yml`) runs the above on Temurin 17, 21 and 25. Bytecode is always `--release 17`, so do not use APIs newer than 17.
- Format before pushing: `./gradlew spotlessApply` (`build` fails on `spotlessCheck`).
- Warnings are errors, including Javadoc. Every public type and member needs Javadoc.
- Release script job, Python 3.12 and `pip install commitizen==4.19.2`:
  - `python3 -m unittest discover -s scripts -p 'test_*.py' -v`
  - `python3 scripts/changelog.py check-drift` (`.cz.toml` vs `gradle.properties`)
  - on PRs: `python3 scripts/changelog.py validate "origin/<base>"` and `cz check --message "<PR title>"`

## Commits, scopes, releases

From `.cz.toml` and `docs/releasing.md`:

- Accepted types (`schema_pattern`): `feat`, `fix`, `refactor`, `perf`, `build`, `revert`, `docs`, `chore`, `style`, `test`, `ci` (and `bump`, the release app's subject).
- Scope is free-form or omitted (`feat(oauth):`, `fix(mcp,spring):`, `test(examples):`): every module ships together, so the scope only documents what changed.
- Releasable: `feat` (minor), `fix`, `refactor`, `perf`, `build`, `revert` (patch). `docs`, `chore`, `style`, `test`, `ci` never cut a release.
- Breaking: `!` before the colon or a `BREAKING CHANGE:` footer. While `major_version_zero = true` a major lands as a minor.
- PRs are squash-merged, so the PR title becomes the commit subject on `main` and decides the release. CI checks the title and re-checks on edit.
- Flow: merge to `main` runs `main.yml`, which calls `bump-package.yml` (`scripts/bump_package.py`). The release app opens and merges a bump PR and tags `v<version>`; `release.yml` publishes every module to Central.
- Never hand-edit the version in `gradle.properties`, `.cz.toml` or the README install snippets, or `CHANGELOG.md`. `cz bump` owns them and `check-drift` fails CI on a mismatch.

## Spec first

- Behavior shared across the Keycard SDKs is defined in `keycardai/keycard-sdk-spec`. A contract change starts as a spec PR there, then is implemented here against that spec's Unit Tests rows.
- Conformance tests are named for the spec row they implement (`@DisplayName("row 4: ...")`), so a reviewer can diff a suite against its spec table. Keep that naming; extra Java-specific tests carry no row number.

## Testing rule

- Module tests are hermetic: they run against `StubZone`, an in-process authorization server on the JDK `HttpServer`, in `keycard-oauth/src/testFixtures`. Other modules use it via `testImplementation(testFixtures(project(":keycard-oauth")))`. Test fixtures are excluded from published artifacts.
- No WireMock or MockWebServer; keep the test classpath as small as the runtime one.
- The `bin/selftest` scripts are hermetic end-to-end checks against a stub zone, run in CI.
- Live coverage against real zones belongs to the eval in `keycardai/templates`.

## Idioms and gotchas

See `docs/idiom-profile.md` for the full table. Short form:

- Sync and blocking API, thread-safe internals. No `CompletableFuture` twins.
- Builders for anything with optional inputs, static factories for small required-only types, records for values.
- Unchecked exceptions rooted at `KeycardException`; `retryable()` is computed at construction.
- `java.time` types and an injectable `Clock` (and `Sleeper` for waits); `Optional` only on return values.
- JSpecify `@NullMarked` packages.
- HTTP through `java.net.http.HttpClient` behind `KeycardHttpTransport`; every request bounded by `fetchTimeout` (default 10 seconds); no hidden retries.
- No implicit environment reads. Exceptions: `FileTokenSource` path discovery and `CredentialDiscovery.discover(env)` where the caller passes the env map.
- `keycard-spiffe` needs a native gRPC transport chosen by the application at runtime.
- `CODEOWNERS`: `@keycardai/engineering` owns everything.
