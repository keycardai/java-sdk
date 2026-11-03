package ai.keycard.oauth.testing;

import static org.assertj.core.api.Assertions.assertThat;

import ai.keycard.oauth.testing.StubZone.StubResponse;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class StubZoneTest {

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void servesDiscoveryForItsOwnIssuer() throws Exception {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            HttpResponse<String> response = get(zone.url(StubZone.DISCOVERY_PATH));

            assertThat(response.statusCode()).isEqualTo(200);
            Map<String, Object> metadata = JSONObjectUtils.parse(response.body());
            assertThat(metadata)
                    .containsEntry("issuer", zone.issuer().toString())
                    .containsEntry(
                            "token_endpoint", zone.url(StubZone.TOKEN_PATH).toString());
        }
    }

    @Test
    void recordsFormEncodedTokenRequests() throws Exception {
        try (StubZone zone = StubZone.start()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"t\",\"token_type\":\"Bearer\"}");

            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(zone.url(StubZone.TOKEN_PATH))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    "grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&scope=a+b"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(response.statusCode()).isEqualTo(200);
            List<StubZone.RecordedRequest> requests = zone.requests(StubZone.TOKEN_PATH);
            assertThat(requests).hasSize(1);
            assertThat(requests.get(0).header("CONTENT-TYPE")).isEqualTo("application/x-www-form-urlencoded");
            assertThat(requests.get(0).formParams())
                    .containsEntry("grant_type", List.of("client_credentials"))
                    .containsEntry("resource", List.of("https://api.example.com"))
                    .containsEntry("scope", List.of("a b"));
        }
    }

    @Test
    void scriptedHandlerSeesEachRequest() throws Exception {
        try (StubZone zone = StubZone.start()) {
            zone.respondWith(
                    "GET", "/echo", request -> StubResponse.json(200, "{\"q\":\"" + request.rawQuery() + "\"}"));

            HttpResponse<String> response = get(zone.url("/echo?x=1"));

            assertThat(response.body()).isEqualTo("{\"q\":\"x=1\"}");
        }
    }

    @Test
    void unscriptedRouteAnswers404WithAnOAuthError() throws Exception {
        try (StubZone zone = StubZone.start()) {
            HttpResponse<String> response = get(zone.url("/nope"));

            assertThat(response.statusCode()).isEqualTo(404);
            assertThat(JSONObjectUtils.parse(response.body())).containsEntry("error", "not_found");
            assertThat(zone.requests()).hasSize(1);
        }
    }

    private HttpResponse<String> get(URI uri) throws Exception {
        return http.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }
}
