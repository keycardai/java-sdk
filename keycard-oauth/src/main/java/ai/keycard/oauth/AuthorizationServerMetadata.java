package ai.keycard.oauth;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * OAuth 2.0 authorization server metadata (RFC 8414), including the OpenID Connect Discovery 1.0
 * members Keycard zones serve from the same document.
 *
 * <p>Only {@code issuer} is required. An absent endpoint is {@code null}, and an absent list is
 * empty. The whole document, unknown fields included, stays reachable through {@link #raw()} and
 * {@link #get(String)}.
 *
 * @param issuer the issuer identifier
 * @param tokenEndpoint where to POST token requests
 * @param authorizationEndpoint where to send users for the authorization code flow
 * @param jwksUri where to fetch the zone's public keys
 * @param registrationEndpoint where to register clients dynamically (RFC 7591)
 * @param userinfoEndpoint where to fetch the signed-in user's identity claims
 * @param endSessionEndpoint where to send the browser to end the zone session
 * @param deviceAuthorizationEndpoint where to POST device authorization requests (RFC 8628)
 * @param grantTypesSupported the grant types the server accepts
 * @param tokenEndpointAuthMethodsSupported the client authentication methods the token endpoint
 *     accepts
 * @param responseTypesSupported the response types the server supports
 * @param raw the complete document as parsed
 */
public record AuthorizationServerMetadata(
        URI issuer,
        @Nullable URI tokenEndpoint,
        @Nullable URI authorizationEndpoint,
        @Nullable URI jwksUri,
        @Nullable URI registrationEndpoint,
        @Nullable URI userinfoEndpoint,
        @Nullable URI endSessionEndpoint,
        @Nullable URI deviceAuthorizationEndpoint,
        List<String> grantTypesSupported,
        List<String> tokenEndpointAuthMethodsSupported,
        List<String> responseTypesSupported,
        Map<String, Object> raw) {

    /**
     * Freezes the lists and the raw document.
     *
     * @param issuer the issuer identifier
     * @param tokenEndpoint the token endpoint, or {@code null}
     * @param authorizationEndpoint the authorization endpoint, or {@code null}
     * @param jwksUri the JWKS URI, or {@code null}
     * @param registrationEndpoint the registration endpoint, or {@code null}
     * @param userinfoEndpoint the userinfo endpoint, or {@code null}
     * @param endSessionEndpoint the end-session endpoint, or {@code null}
     * @param deviceAuthorizationEndpoint the device authorization endpoint, or {@code null}
     * @param grantTypesSupported supported grant types
     * @param tokenEndpointAuthMethodsSupported supported token endpoint auth methods
     * @param responseTypesSupported supported response types
     * @param raw the complete document
     */
    public AuthorizationServerMetadata {
        Objects.requireNonNull(issuer, "issuer");
        grantTypesSupported = List.copyOf(grantTypesSupported);
        tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
        responseTypesSupported = List.copyOf(responseTypesSupported);
        raw = Collections.unmodifiableMap(new LinkedHashMap<>(raw));
    }

    /**
     * A field from the complete document, including fields this type doesn't model.
     *
     * @param field the metadata field name, such as {@code revocation_endpoint}
     * @return the parsed JSON value, or {@code null} when the document omits it
     */
    public @Nullable Object get(String field) {
        return raw.get(field);
    }
}
