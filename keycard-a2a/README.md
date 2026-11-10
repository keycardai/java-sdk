# keycard-a2a

Agent-to-agent delegation: call another agent on the user's behalf. The client discovers the
target's agent card, exchanges the user's token for one scoped to the target (the user stays the
subject, and the zone records your agent in `act`), and sends the message over A2A JSON-RPC.

```kotlin
implementation("ai.keycard:keycard-a2a:0.1.0")
```

```java
DelegationClient delegation = DelegationClient.builder(URI.create("https://acme.keycard.cloud"))
        .credential(ClientSecret.of(agentClientId, agentSecret))
        .build();

DelegationResult result = delegation.invoke(
        URI.create("https://agent-b.example"), userAccessToken, A2aProtocol.textMessage("Summarize my week"));
result.text().ifPresent(System.out::println);
```

The client speaks A2A 1.0 (`SendMessage`, `A2A-Version: 1.0`). For an agent that only speaks
0.3, `protocolVersion(A2aProtocol.LEGACY_PROTOCOL_VERSION)` switches the whole envelope.
Agent cards are cached for 15 minutes; share a `ServiceDiscovery` between clients to share the
cache. The module has no dependency on an A2A SDK, so the agent you call can be built with any of
them; [examples/a2a-delegation](../examples/a2a-delegation) calls an agent on the official
a2a-java codec.

Javadoc: <https://javadoc.io/doc/ai.keycard/keycard-a2a>
