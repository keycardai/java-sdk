# Keycard Java SDK

Java SDK for the Keycard agentic identity platform, built to the same contract as the
[Python](https://github.com/keycardai/python-sdk),
[TypeScript](https://github.com/keycardai/typescript-sdk),
[Go](https://github.com/keycardai/go-sdk) and
[Ruby](https://github.com/keycardai/ruby-sdk) SDKs.

Preview: the API may change before 1.0. Where it stands against the shared specs, row by
row and against a live zone, is in [docs/conformance-report.md](docs/conformance-report.md).

## Install

Every module is on Maven Central under the `ai.keycard` group and releases under one
version. Import `keycard-bom` and leave the version off each module. Requires Java 17 or
newer.

Gradle:

```kotlin
dependencies {
    implementation(platform("ai.keycard:keycard-bom:0.1.0"))
    implementation("ai.keycard:keycard-oauth")
}
```

Maven:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>ai.keycard</groupId>
      <artifactId>keycard-bom</artifactId>
      <version>0.1.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependencies>
  <dependency>
    <groupId>ai.keycard</groupId>
    <artifactId>keycard-oauth</artifactId>
  </dependency>
</dependencies>
```

Add the other modules below the same way.

## Modules

| Artifact | Package | Purpose |
| --- | --- | --- |
| [`keycard-oauth`](keycard-oauth) | `ai.keycard.oauth` | OAuth 2.0 for Keycard zones: token exchange (RFC 8693) with actor tokens, client credentials, authorization code with PKCE, the device grant (RFC 8628), DCR (RFC 7591), discovery (RFC 8414), UserInfo, credentials (client secret, workload identity, WebIdentity, environment discovery), JWT/JWKS verification, AccessContext |
| [`keycard-spiffe`](keycard-spiffe) | `ai.keycard.spiffe` | JWT-SVIDs from the SPIFFE Workload API as a workload identity source (Preview) |
| [`keycard-mcp`](keycard-mcp) | `ai.keycard.mcp` | MCP server auth on Jakarta Servlet: bearer filter (RFC 6750), metadata servlets (RFC 9728/8414), grant filter |
| [`keycard-spring-boot-starter`](keycard-spring-boot-starter) | `ai.keycard.spring.boot` | Spring Boot 4 auto-configuration on Spring Security's resource server, with `@KeycardGrant` |
| [`keycard-a2a`](keycard-a2a) | `ai.keycard.a2a` | Agent-to-agent delegation over A2A 1.0 |
| `ai.keycard:keycard-bom` | | Pins every module to one version |

`keycard-oauth` is the foundation, and its only runtime dependency is
[Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt). The other modules
depend on it. `keycard-spiffe` is separate because the SPIFFE client pulls in gRPC.

## Examples

| Example | Shows |
| --- | --- |
| [engine-obo](examples/engine-obo) | A workload authenticated by a SPIFFE JWT-SVID exchanging a user's token, actor chains, the device grant, WebIdentity, and the core live rows |
| [mcp-server-servlet](examples/mcp-server-servlet) | An MCP server on the official MCP Java SDK behind `keycard-mcp` |
| [mcp-server-spring-ai](examples/mcp-server-spring-ai) | A Spring AI 2.0 MCP server behind the Spring Boot starter |
| [a2a-delegation](examples/a2a-delegation) | Agent A delegating to agent B, which runs on the official a2a-java codec |

Each has a `bin/selftest` that needs no zone, or a live run against one.
`examples/live-e2e` runs every live suite against a sandbox zone.

## Building

Requires JDK 17 or newer. Every module compiles to Java 17 bytecode whichever JDK runs the
build.

```sh
./gradlew build                 # compile, test, Javadoc, format check
./gradlew spotlessApply         # format
./gradlew publishToMavenLocal   # install to ~/.m2 for local consumers
```

Tests run against `StubZone`, an in-process authorization server in
`keycard-oauth/src/testFixtures`. Other modules use it through
`testImplementation(testFixtures(project(":keycard-oauth")))`.

How the shared contract maps onto Java, and why, is in
[docs/idiom-profile.md](docs/idiom-profile.md).

## License

MIT, see [LICENSE](LICENSE). Keycard trademarks are covered separately in
[TRADEMARKS.md](TRADEMARKS.md).
