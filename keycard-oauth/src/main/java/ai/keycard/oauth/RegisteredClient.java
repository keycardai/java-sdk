package ai.keycard.oauth;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * An RFC 7591 §3.2.1 registration response. The server's view of the registered metadata, and
 * any authorization-server-specific fields, are in {@link #raw()}.
 *
 * @param clientId the issued client id
 * @param clientSecret the issued secret, for a confidential client
 * @param clientIdIssuedAt when the client id was issued
 * @param clientSecretExpiresAt when the secret expires; {@link Instant#EPOCH} means never
 * @param registrationAccessToken the token for managing the registration
 * @param registrationClientUri the endpoint for managing the registration
 * @param raw the complete response
 */
public record RegisteredClient(
        String clientId,
        @Nullable String clientSecret,
        @Nullable Instant clientIdIssuedAt,
        @Nullable Instant clientSecretExpiresAt,
        @Nullable String registrationAccessToken,
        @Nullable URI registrationClientUri,
        Map<String, Object> raw) {

    /**
     * Freezes the raw response.
     *
     * @param clientId the issued client id
     * @param clientSecret the issued secret, or {@code null}
     * @param clientIdIssuedAt when the client id was issued, or {@code null}
     * @param clientSecretExpiresAt when the secret expires, or {@code null}
     * @param registrationAccessToken the management token, or {@code null}
     * @param registrationClientUri the management endpoint, or {@code null}
     * @param raw the complete response
     */
    public RegisteredClient {
        Objects.requireNonNull(clientId, "clientId");
        raw = Collections.unmodifiableMap(new LinkedHashMap<>(raw));
    }

    /**
     * The client secret as a credential.
     *
     * @return a {@link ClientSecret} for this client
     * @throws ConfigurationException when the server issued no secret (a public client)
     */
    public ClientSecret toClientSecret() {
        if (clientSecret == null) {
            throw new ConfigurationException("client " + clientId + " was registered without a secret");
        }
        return ClientSecret.of(clientId, clientSecret);
    }

    /**
     * Names the client, never the secret or the registration token.
     *
     * @return a description without secrets
     */
    @Override
    public String toString() {
        return "RegisteredClient[clientId=" + clientId + ", clientSecret="
                + (clientSecret == null ? "absent" : "present") + ", clientSecretExpiresAt=" + clientSecretExpiresAt
                + ", registrationClientUri=" + registrationClientUri + "]";
    }
}
