package ai.keycard.oauth;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * RFC 7591 §2 client metadata for {@link ClientRegistrationClient#register}. Every field is
 * optional; only the fields set are sent, and the authorization server defaults the rest.
 *
 * <pre>{@code
 * ClientRegistrationRequest request = ClientRegistrationRequest.builder()
 *         .clientName("Payments CLI")
 *         .redirectUris(URI.create("http://127.0.0.1:8765/callback"))
 *         .grantTypes("authorization_code", "refresh_token")
 *         .tokenEndpointAuthMethod("none")
 *         .build();
 * }</pre>
 */
public final class ClientRegistrationRequest {

    private final Map<String, Object> metadata;

    private ClientRegistrationRequest(Map<String, Object> metadata) {
        this.metadata = Collections.unmodifiableMap(metadata);
    }

    /**
     * A builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The JSON body: the additional metadata, then the named fields over it.
     *
     * @return the metadata
     */
    public Map<String, Object> metadata() {
        return metadata;
    }

    @Override
    public String toString() {
        return "ClientRegistrationRequest" + metadata.keySet();
    }

    /** Configures a {@link ClientRegistrationRequest}. */
    public static final class Builder {

        private final Map<String, Object> named = new LinkedHashMap<>();
        private final Map<String, Object> additional = new LinkedHashMap<>();

        private Builder() {}

        /**
         * {@code client_name}.
         *
         * @param clientName the human-readable name
         * @return this builder
         */
        public Builder clientName(String clientName) {
            return put("client_name", clientName);
        }

        /**
         * {@code redirect_uris}.
         *
         * @param redirectUris the redirect URIs
         * @return this builder
         */
        public Builder redirectUris(URI... redirectUris) {
            List<String> values = new ArrayList<>();
            for (URI uri : redirectUris) {
                values.add(uri.toString());
            }
            return put("redirect_uris", values);
        }

        /**
         * {@code grant_types}.
         *
         * @param grantTypes the grant types
         * @return this builder
         */
        public Builder grantTypes(String... grantTypes) {
            return put("grant_types", List.of(grantTypes));
        }

        /**
         * {@code response_types}.
         *
         * @param responseTypes the response types
         * @return this builder
         */
        public Builder responseTypes(String... responseTypes) {
            return put("response_types", List.of(responseTypes));
        }

        /**
         * {@code scope}, sent space-separated.
         *
         * @param scopes the scopes
         * @return this builder
         */
        public Builder scope(String... scopes) {
            return put("scope", String.join(" ", scopes));
        }

        /**
         * {@code token_endpoint_auth_method}, such as {@code client_secret_basic}, {@code
         * private_key_jwt} or {@code none}.
         *
         * @param method the method
         * @return this builder
         */
        public Builder tokenEndpointAuthMethod(String method) {
            return put("token_endpoint_auth_method", method);
        }

        /**
         * {@code jwks_uri}, where the client publishes its keys.
         *
         * @param jwksUri the URL
         * @return this builder
         */
        public Builder jwksUri(URI jwksUri) {
            return put("jwks_uri", jwksUri.toString());
        }

        /**
         * {@code jwks}, the client's keys inline, such as {@code WebIdentity.publicJwks().toJSONObject()}.
         *
         * @param jwks the key set as JSON
         * @return this builder
         */
        public Builder jwks(Map<String, Object> jwks) {
            return put("jwks", Map.copyOf(jwks));
        }

        /**
         * {@code client_uri}.
         *
         * @param uri the URL
         * @return this builder
         */
        public Builder clientUri(URI uri) {
            return put("client_uri", uri.toString());
        }

        /**
         * {@code logo_uri}.
         *
         * @param uri the URL
         * @return this builder
         */
        public Builder logoUri(URI uri) {
            return put("logo_uri", uri.toString());
        }

        /**
         * {@code tos_uri}.
         *
         * @param uri the URL
         * @return this builder
         */
        public Builder tosUri(URI uri) {
            return put("tos_uri", uri.toString());
        }

        /**
         * {@code policy_uri}.
         *
         * @param uri the URL
         * @return this builder
         */
        public Builder policyUri(URI uri) {
            return put("policy_uri", uri.toString());
        }

        /**
         * {@code software_id}.
         *
         * @param softwareId the identifier
         * @return this builder
         */
        public Builder softwareId(String softwareId) {
            return put("software_id", softwareId);
        }

        /**
         * {@code software_version}.
         *
         * @param softwareVersion the version
         * @return this builder
         */
        public Builder softwareVersion(String softwareVersion) {
            return put("software_version", softwareVersion);
        }

        /**
         * Vendor or authorization-server-specific fields, merged into the body. A named field set
         * on this builder wins over the same key here.
         *
         * @param metadata the extra fields
         * @return this builder
         */
        public Builder additionalMetadata(Map<String, Object> metadata) {
            additional.putAll(metadata);
            return this;
        }

        /**
         * Builds the request.
         *
         * @return the request
         */
        public ClientRegistrationRequest build() {
            Map<String, Object> body = new LinkedHashMap<>(additional);
            body.putAll(named);
            return new ClientRegistrationRequest(body);
        }

        private Builder put(String name, @Nullable Object value) {
            named.put(name, Objects.requireNonNull(value, name));
            return this;
        }
    }
}
