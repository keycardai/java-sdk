# keycard-spiffe

> Preview: the API may change before 1.0.

JWT-SVIDs from the SPIFFE Workload API as a Keycard workload identity. A separate module so
`keycard-oauth` never pulls in gRPC.

```kotlin
implementation("ai.keycard:keycard-spiffe:0.1.0")
runtimeOnly("io.spiffe:grpc-netty-linux:0.8.17")   // or grpc-netty-macos / -macos-aarch64
```

```java
URI zone = URI.create("https://acme.keycard.cloud");
SpiffeJwtSvidSource svid = SpiffeJwtSvidSource.builder(zone.toString()).build();   // audience: the zone

TokenExchangeClient exchange = TokenExchangeClient.builder(zone)
        .credential(WorkloadIdentity.builder(svid).clientId(v2ClientId).build())
        .build();
TokenResponse token = exchange.exchangeToken(userAccessToken, URI.create("https://api.example.com"));
```

The socket comes from `SPIFFE_ENDPOINT_SOCKET` unless you pass `socketPath(...)`. Without a
Workload API connection, spiffe-helper can write the SVID to a file, which
`FileTokenSource.of(path)` in `keycard-oauth` reads with no gRPC at all.

The same source can also be passed to `TokenExchangeClient.Builder.actor(...)` to send the SVID
as the RFC 8693 actor token, which nests your workload over any earlier actor in `act`. That
option is a Preview too, and the zone accepts actor tokens only from v1 token credentials.

Javadoc: <https://javadoc.io/doc/ai.keycard/keycard-spiffe>
