package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.WorkloadIdentityRuntimeException;
import ai.keycard.oauth.testing.StubZone;
import java.net.URI;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The actor-source surface proposed for token-exchange.md under SDK-49: an {@code
 * IdentityTokenSource} on the client supplies {@code actor_token} on every exchange. Not yet a
 * spec table; these rows become one when the proposal lands.
 */
class ActorTokenSourceTest {

    private static final URI RESOURCE = URI.create("https://api.example.com");

    @Test
    @DisplayName("the actor source's token is fetched on every exchange and sent with the jwt type")
    void actorFetchedPerRequest() {
        try (StubZone zone = zone()) {
            AtomicInteger calls = new AtomicInteger();
            TokenExchangeClient client = TokenExchangeClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.of(() -> "svid-assertion"))
                    .actor(() -> "svid-actor-" + calls.incrementAndGet())
                    .build();

            client.exchangeToken("user-token", RESOURCE);
            client.exchangeToken("user-token", RESOURCE);

            List<StubZone.RecordedRequest> requests = zone.requests(StubZone.TOKEN_PATH);
            assertThat(requests.get(0).formParams())
                    .containsEntry("actor_token", List.of("svid-actor-1"))
                    .containsEntry("actor_token_type", List.of(TokenTypes.JWT))
                    .containsEntry("subject_token", List.of("user-token"))
                    .containsEntry("client_assertion", List.of("svid-assertion"));
            assertThat(requests.get(1).formParams()).containsEntry("actor_token", List.of("svid-actor-2"));
        }
    }

    @Test
    @DisplayName("an actor token set on the request wins over the source")
    void requestActorWins() {
        try (StubZone zone = zone()) {
            TokenExchangeClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.of(() -> "svid"))
                    .actor(() -> "from-source")
                    .build()
                    .exchangeToken(TokenExchangeRequest.builder("user-token")
                            .actorToken("explicit", TokenTypes.JWT)
                            .build());

            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).formParams())
                    .containsEntry("actor_token", List.of("explicit"));
        }
    }

    @Test
    @DisplayName("an actor source failure is a runtime error and nothing is sent")
    void actorFailure() {
        try (StubZone zone = zone()) {
            TokenExchangeClient client = TokenExchangeClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.of(() -> "svid"))
                    .actor(() -> {
                        throw new IllegalStateException("workload API down");
                    })
                    .build();

            assertThatThrownBy(() -> client.exchangeToken("user-token", RESOURCE))
                    .isInstanceOfSatisfying(
                            WorkloadIdentityRuntimeException.class,
                            e -> assertThat(e.source()).isEqualTo("custom"));
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"xt\"}");
        return zone;
    }
}
