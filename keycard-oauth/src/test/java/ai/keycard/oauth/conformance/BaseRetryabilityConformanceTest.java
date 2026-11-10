package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthErrorCodes;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import java.net.ConnectException;
import java.net.http.HttpTimeoutException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** base.md (spec-version 5), Retryability. */
class BaseRetryabilityConformanceTest {

    @Test
    @DisplayName("permanent table: exactly access_denied, expired_token, insufficient_authorization, invalid_client")
    void permanentSet() {
        assertThat(OAuthErrorCodes.PERMANENT)
                .containsExactlyInAnyOrder(
                        "access_denied", "expired_token", "insufficient_authorization", "invalid_client");
        assertThatThrownBy(() -> OAuthErrorCodes.PERMANENT.add("invalid_grant"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("authorization-server errors: retryable unless the code is permanent")
    void oauthErrors() {
        for (String code : OAuthErrorCodes.PERMANENT) {
            assertThat(oauthError(code).retryable()).as(code).isFalse();
        }
        for (String code : List.of(
                "invalid_grant",
                "invalid_request",
                "invalid_scope",
                "unauthorized_client",
                "unsupported_grant_type",
                "server_error",
                "temporarily_unavailable",
                "invalid_target")) {
            assertThat(oauthError(code).retryable()).as(code).isTrue();
        }
    }

    @Test
    @DisplayName("serialized codes: membership in the exported set agrees with the typed classification")
    void exportedSetAgreesWithTypedErrors() {
        Set<String> codes = Set.of(
                "access_denied",
                "expired_token",
                "insufficient_authorization",
                "invalid_client",
                "invalid_grant",
                "server_error",
                "slow_down",
                "authorization_pending");
        for (String code : codes) {
            assertThat(oauthError(code).retryable()).as(code).isEqualTo(!OAuthErrorCodes.isPermanent(code));
        }
    }

    @Test
    @DisplayName("authorization-server errors: invalid_response for a malformed response is retryable")
    void invalidResponse() {
        assertThat(new OAuthProtocolException("no access_token", OAuthProtocolException.INVALID_RESPONSE).retryable())
                .isTrue();
    }

    @Test
    @DisplayName("HTTP errors: 429 and 5xx retryable, every other 4xx not")
    void httpErrors() {
        for (int status : List.of(429, 500, 502, 503, 504)) {
            assertThat(new HttpStatusException("x", status, "").retryable())
                    .as("%d", status)
                    .isTrue();
        }
        for (int status : List.of(400, 401, 403, 404, 405, 409, 410, 422)) {
            assertThat(new HttpStatusException("x", status, "").retryable())
                    .as("%d", status)
                    .isFalse();
        }
    }

    @Test
    @DisplayName("network errors: always retryable")
    void networkErrors() {
        assertThat(new NetworkException("x", new ConnectException("refused")).retryable())
                .isTrue();
        assertThat(new NetworkException("x", new HttpTimeoutException("timeout")).retryable())
                .isTrue();
    }

    @Test
    @DisplayName("configuration and every other error: not retryable by default")
    void everythingElse() {
        assertThat(new ConfigurationException("x").retryable()).isFalse();
        assertThat(new KeycardException("x").retryable()).isFalse();
        assertThat(new OAuthProtocolException("x", OAuthProtocolException.ISSUER_MISMATCH).retryable())
                .isFalse();
        assertThat(new OAuthProtocolException("x", OAuthProtocolException.INVALID_METADATA).retryable())
                .isFalse();
    }

    @Test
    @DisplayName("an OAuth error carries the wire fields and is also an HTTP error")
    void oauthErrorFields() {
        OAuthErrorException e = new OAuthErrorException(
                "token request failed", 400, "{}", "invalid_grant", "code expired", "https://docs/x");

        assertThat(e).isInstanceOf(HttpStatusException.class);
        assertThat(e.status()).isEqualTo(400);
        assertThat(e.error()).isEqualTo("invalid_grant");
        assertThat(e.errorDescription()).isEqualTo("code expired");
        assertThat(e.errorUri()).isEqualTo("https://docs/x");
    }

    private static OAuthErrorException oauthError(String code) {
        return new OAuthErrorException("x", 400, "", code, null, null);
    }
}
