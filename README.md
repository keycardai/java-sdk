# Keycard Java SDK

Java SDK for the Keycard agentic identity platform, built to the same contract as the
[Python](https://github.com/keycardai/python-sdk),
[TypeScript](https://github.com/keycardai/typescript-sdk),
[Go](https://github.com/keycardai/go-sdk) and
[Ruby](https://github.com/keycardai/ruby-sdk) SDKs.

Nothing is published yet. The modules below are scaffolding; the first release will be
`keycard-oauth` and `keycard-spiffe` under the `ai.keycard` group on Maven Central.

## Modules

| Artifact | Package | Purpose |
| --- | --- | --- |
| `ai.keycard:keycard-oauth` | `ai.keycard.oauth` | OAuth 2.0 primitives: token exchange (RFC 8693) with actor tokens, client credentials, workload identity, authorization code with PKCE, DCR (RFC 7591), discovery (RFC 8414), JWT/JWKS verification, AccessContext |
| `ai.keycard:keycard-spiffe` | `ai.keycard.spiffe` | JWT-SVIDs from the SPIFFE Workload API as a workload identity source |
| `ai.keycard:keycard-mcp` | `ai.keycard.mcp` | MCP server auth on Jakarta Servlet: bearer filter (RFC 6750), metadata servlets (RFC 9728/8414), grant filter |
| `ai.keycard:keycard-spring-boot-starter` | `ai.keycard.spring.boot` | Spring Boot auto-configuration |
| `ai.keycard:keycard-a2a` | `ai.keycard.a2a` | Agent-to-agent delegation |
| `ai.keycard:keycard-bom` | | Pins every module to one version |

`keycard-oauth` is the foundation, and its only runtime dependency is
[Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt). The other modules
depend on it. `keycard-spiffe` is separate because the SPIFFE client pulls in gRPC.

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
