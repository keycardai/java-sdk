package ai.keycard.oauth;

import java.net.URI;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The inputs a {@link Credential} prepares a token-exchange request from.
 *
 * @param subjectToken the token being exchanged
 * @param resource the target resource (RFC 8707), or {@code null}
 * @param issuer the zone's issuer, which picks the zone for a multi-zone credential
 * @param resourceClientId the OAuth client id the zone registered for the resource server, when
 *     known; an assertion-based credential signs it as {@code iss} and {@code sub}
 * @param tokenEndpoint the zone's token endpoint the request goes to, when the client has
 *     discovered it; an assertion-based credential signs it as {@code aud}
 */
public record TokenExchangeContext(
        String subjectToken,
        @Nullable URI resource,
        URI issuer,
        @Nullable String resourceClientId,
        @Nullable URI tokenEndpoint) {

    /**
     * Validates the required components.
     *
     * @param subjectToken the token being exchanged, non-empty
     * @param resource the target resource, or {@code null}
     * @param issuer the zone's issuer
     * @param resourceClientId the resource server's client id, or {@code null}
     * @param tokenEndpoint the token endpoint, or {@code null}
     */
    public TokenExchangeContext {
        Objects.requireNonNull(subjectToken, "subjectToken");
        Objects.requireNonNull(issuer, "issuer");
        if (subjectToken.isEmpty()) {
            throw new ConfigurationException("subjectToken must not be empty");
        }
    }

    /**
     * A context without a known token endpoint.
     *
     * @param subjectToken the token being exchanged
     * @param resource the target resource, or {@code null}
     * @param issuer the zone's issuer
     * @param resourceClientId the resource server's client id, or {@code null}
     */
    public TokenExchangeContext(
            String subjectToken, @Nullable URI resource, URI issuer, @Nullable String resourceClientId) {
        this(subjectToken, resource, issuer, resourceClientId, null);
    }

    /**
     * This context with the token endpoint the request goes to.
     *
     * @param tokenEndpoint the discovered token endpoint
     * @return the new context
     */
    public TokenExchangeContext withTokenEndpoint(URI tokenEndpoint) {
        return new TokenExchangeContext(subjectToken, resource, issuer, resourceClientId, tokenEndpoint);
    }

    /**
     * A context with no resource client id.
     *
     * @param subjectToken the token being exchanged
     * @param resource the target resource, or {@code null}
     * @param issuer the zone's issuer
     * @return the context
     */
    public static TokenExchangeContext of(String subjectToken, @Nullable URI resource, URI issuer) {
        return new TokenExchangeContext(subjectToken, resource, issuer, null, null);
    }

    /**
     * Never prints the subject token.
     *
     * @return the context without the token
     */
    @Override
    public String toString() {
        return "TokenExchangeContext[resource=" + resource + ", issuer=" + issuer + ", resourceClientId="
                + resourceClientId + ", tokenEndpoint=" + tokenEndpoint + "]";
    }
}
