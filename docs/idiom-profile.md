# Java idiom profile

How the Keycard SDK contract maps onto Java. Each decision carries its reason, so a later
change can argue with the reason rather than the rule. Where the shared contract names an
operation (`verifyTokenForZone`, `exchangeToken`), Java keeps the name in camelCase.

## Decisions

| Category | Java transform |
|---|---|
| Naming | `camelCase` methods, `PascalCase` types. Spec names map directly (`verifyTokenForZone`, `exchangeToken`). |
| Coordinates | groupId `ai.keycard` (reverse of keycard.ai, which Central verifies by DNS TXT), artifactIds `keycard-<module>`, packages `ai.keycard.<module>`. The `keycard-` prefix keeps jar filenames unambiguous in flattened `lib/` directories, which matters in fat-jar deployments. |
| Async model | Sync and blocking, like Go and Ruby. Callers on Java 21+ get cheap blocking through virtual threads without us shipping a second API. No `CompletableFuture` twins in v1. Internals are thread-safe (servlet containers and long-running service engines are both multi-threaded). |
| Calling convention | Builders for anything with optional inputs (`TokenExchangeRequest.builder()`), static factories for small required-only types, records for immutable values. Builders are the Java analog of kwargs and options objects. |
| Errors | Unchecked exceptions rooted at `KeycardException extends RuntimeException`; spec categories become subclasses: `ConfigurationException`, `NetworkException` (JDK exception as the cause), `HttpStatusException` (non-2xx, `status()` and `body()`), its subclass `OAuthErrorException` (RFC 6749 §5.2 `error`, `errorDescription`, `errorUri`), `OAuthProtocolException` (a broken response, `code()` such as `issuer_mismatch`, `invalid_metadata`, `invalid_response`), and later `TokenVerificationException`. `retryable()` is a final method computed at construction per base.md; the permanent-code set is exported as `OAuthErrorCodes.PERMANENT`. Unchecked because checked exceptions break lambdas and streams and modern Java libraries (Spring, the MCP SDK) don't use them. Causes chain through the standard `cause`. |
| Host-framework shape | Jakarta Servlet `Filter` for enforcement, `HttpServlet` for metadata, request attributes `ai.keycard.authInfo` / `ai.keycard.accessContext` plus static accessors (`KeycardRequest.accessContext(request)`). In Spring, a `SecurityFilterChain` customizer, a `JwtDecoder` adapter and a `HandlerMethodArgumentResolver` for `AccessContext`. |
| Operation shape | Flat methods on client objects, matching Python, TS and Ruby. |
| Native values | `java.time.Instant` / `Duration`, `java.time.Clock` for the spec's clock override, `java.security.PrivateKey` / `PublicKey` (Nimbus `JWK` where a JWK is the natural form), `URI` for URLs, `Map<String, Object>` for raw claims, `Optional` only on return values. |
| Null-safety | JSpecify annotations (`@NullMarked` packages), the convention Spring Framework 7 adopted. |
| HTTP | `java.net.http.HttpClient` behind a small `KeycardHttpTransport` interface, injectable per client; callers can also pass their own configured `HttpClient` (corporate proxy, custom truststore, mTLS). Zero dependencies, HTTP/2, in the JDK since 11. OkHttp is out: OkHttp 4 and 5 are Kotlin and pull the Kotlin stdlib, which is one more item in a regulated shop's dependency review. No hidden retries, per base.md. Bounded requests: every request carries a timeout (`fetchTimeout` on each client builder, default 10 seconds), and the JDK transport bounds the whole exchange with it. `HttpRequest.Builder.timeout` alone stops counting once headers arrive, so the transport sends asynchronously and awaits the future for the timeout, then cancels it. A timeout is a `NetworkException` whose cause is `HttpTimeoutException`; an interrupted caller gets a `NetworkException` whose cause is `InterruptedException`, with its interrupt flag left set. |
| JWT / JWKS | `com.nimbusds:nimbus-jose-jwt` (10.x). Spring Security already depends on it, so most Spring apps get it for free. Keycard keeps its own keyring on top of Nimbus's JWK parsing rather than Nimbus's `JWKSourceBuilder`, because jwks-caching.md fixes behavior Nimbus's cache doesn't match (`kid` required, bounded 256-entry cache with oldest-first eviction, single-flight cold fetch, non-sticky transient failures with a 1-minute `negative_ttl`). |
| JSON | No Jackson in `keycard-oauth`. Nimbus's public `JSONObjectUtils` parses and writes the flat documents the SDK handles (token responses, discovery, DCR, agent cards, JSON-RPC envelopes), and public types are records, not Jackson-annotated beans. Reason: in 2026 Jackson is split into 2.x (`com.fasterxml.jackson`) and 3.x (`tools.jackson`, Spring Boot 4's default), and the MCP SDK had to ship `mcp-json-jackson2` and `mcp-json-jackson3` adapters to cope. Picking either one forces it onto half the user base; picking neither leaves the core with exactly one runtime dependency. Verify that the pinned Nimbus release shades Gson (10.2 un-shaded it, 10.3 re-shaded it). |
| Configuration | Constructor-injected, no implicit environment reads (base.md). Blessed exceptions: `FileTokenSource` path discovery through the platform variables in spec order, and the explicit `CredentialDiscovery.discover(Map<String,String> env)` factory (callers pass `System.getenv()` themselves). The Spring starter binds `keycard.*` properties, and Spring's relaxed binding lets `KEYCARD_ZONE_URL` populate `keycard.zone-url`; that's the application's own configuration system rather than the SDK reading the environment, and the starter's docs say so. |
| Credential operations | `Credential` has base.md's one required operation, `prepareTokenExchangeRequest(TokenExchangeContext)`. Client authentication (base spec-version 5) is a separate `ClientAuthenticator` interface, `authenticate(issuer, endpoint)` returning a `ClientAuthentication` of headers and form fields, which `ClientSecret`, `WebIdentity` and `WorkloadIdentity` implement. A separate interface rather than a default method, so a caller's own `Credential` lambda keeps compiling and an operation that needs client authentication can reject one without it at build time (`ConfigurationException`). Multi-zone `ClientSecret.perZone(Map<URI, ClientSecret>)` is keyed by issuer and fails closed with a `ConfigurationException` before any request. |
| Verifier shape | One `TokenVerifier` with `verifyToken` and `verifyTokenForZone`, the TS / Python / Ruby shape. |

## Tooling

- Java floor 17. Every module compiles with `--release 17`, so the bytecode and the JDK API
  surface are 17's whichever JDK runs Gradle, and CI runs the whole build on 17, 21 and 25.
  Reasons for 17: Spring Boot 4 still floors at 17, the MCP Java SDK requires 17, regulated
  shops tend to run the oldest supported LTS, and nothing in the SDK needs a 21 feature
  (records and sealed interfaces are final in 17; virtual threads help callers without our
  code using them). `keycard-spring-ai` may floor at 21 on its own if Spring AI 2.0 requires it.
- Build: Gradle with the Kotlin DSL and a version catalog. Reasons: the `java-test-fixtures` plugin gives every module the same stub
  zone (the analog of Ruby's `spec/support`), and the `com.vanniktech.maven.publish` plugin
  produces sources jars, javadoc jars, signatures and Central Portal uploads from one block.
  Maven would work (the MCP SDK, LangChain4j and a2a-java all use it) and consumers only ever
  see the generated POMs, so this is a maintainer-side choice that's cheap to revisit.
- Tests: JUnit Jupiter (JUnit 6 floors at Java 17), AssertJ, and the JDK's
  `com.sun.net.httpserver.HttpServer` for stub zones, so the test classpath stays as small as
  the runtime one. No WireMock or MockWebServer (OkHttp again).
- Format and lint: Spotless with palantir-java-format; Error Prone + NullAway once JSpecify
  annotations are in.
- JPMS: `Automatic-Module-Name` manifest entries in v1 (what the MCP SDK does), real
  `module-info.java` later.
- Javadoc on every public type from day one, because Central rejects a release without a
  javadoc jar and javadoc.io renders it for free.

## Layout

```
java-sdk/
  settings.gradle.kts, build.gradle.kts, gradle/libs.versions.toml, gradle.properties (version=)
  build-logic/              convention plugins: keycard.java-library (compile, test, Javadoc, Spotless) and keycard.publishing
  keycard-oauth/            src/main, src/test, src/testFixtures (StubZone, shared by every module's tests)
  keycard-spiffe/
  keycard-mcp/
  keycard-spring-boot-starter/   package ai.keycard.spring.boot
  keycard-a2a/
  keycard-bom/
  examples/                 engine-obo/, mcp-server-servlet/, mcp-server-spring-ai/, a2a-delegation/
                            (each a separate Gradle build using includeBuild("../.."))
  docs/                     idiom-profile.md, conformance-report.md, releasing.md, launch-checklist.md
  scripts/                  changelog.py, bump_package.py (ported from ruby-sdk)
```

Examples consume the SDK through Gradle composite builds (`includeBuild`), the analog of
Bundler's `path:`, so they run against unpublished code.
