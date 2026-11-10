package ai.keycard.oauth;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * An RFC 8693 token-exchange request. Build one with {@link #builder(String)}; a {@link
 * Credential} prepares one with its client authentication already in place.
 *
 * @param grantType the grant type, default {@link TokenTypes#TOKEN_EXCHANGE_GRANT}
 * @param subjectToken the token being exchanged
 * @param subjectTokenType the subject token's type, default {@link TokenTypes#ACCESS_TOKEN}
 * @param resource the target resource (RFC 8707), or {@code null}
 * @param audience the target audience, an alternative to {@code resource}, or {@code null}
 * @param scope space-separated scopes requested for the issued token, or {@code null}
 * @param requestedTokenType the requested type of the issued token, or {@code null}
 * @param actorToken the acting party's token, for delegation, or {@code null}
 * @param actorTokenType the actor token's type, set whenever {@code actorToken} is
 * @param clientAssertion a client authentication assertion, or {@code null}
 * @param clientAssertionType the assertion's type, set whenever {@code clientAssertion} is
 * @param clientId the {@code client_id} form parameter some credentials send, or {@code null}
 */
public record TokenExchangeRequest(
        String grantType,
        String subjectToken,
        String subjectTokenType,
        @Nullable URI resource,
        @Nullable String audience,
        @Nullable String scope,
        @Nullable String requestedTokenType,
        @Nullable String actorToken,
        @Nullable String actorTokenType,
        @Nullable String clientAssertion,
        @Nullable String clientAssertionType,
        @Nullable String clientId) {

    /**
     * Validates the request: a non-empty subject token, and a type for every token or assertion.
     *
     * @param grantType the grant type
     * @param subjectToken the subject token
     * @param subjectTokenType the subject token's type
     * @param resource the target resource, or {@code null}
     * @param audience the target audience, or {@code null}
     * @param scope the requested scopes, or {@code null}
     * @param requestedTokenType the requested token type, or {@code null}
     * @param actorToken the actor token, or {@code null}
     * @param actorTokenType the actor token's type, or {@code null}
     * @param clientAssertion the client assertion, or {@code null}
     * @param clientAssertionType the assertion's type, or {@code null}
     * @param clientId the client id form parameter, or {@code null}
     */
    public TokenExchangeRequest {
        Objects.requireNonNull(grantType, "grantType");
        Objects.requireNonNull(subjectToken, "subjectToken");
        Objects.requireNonNull(subjectTokenType, "subjectTokenType");
        if (subjectToken.isEmpty()) {
            throw new ConfigurationException("subjectToken must not be empty");
        }
        if (actorToken != null && actorTokenType == null) {
            throw new ConfigurationException("actorTokenType is required when actorToken is set");
        }
        if (clientAssertion != null && clientAssertionType == null) {
            throw new ConfigurationException("clientAssertionType is required when clientAssertion is set");
        }
    }

    /**
     * A builder for a request exchanging {@code subjectToken}.
     *
     * @param subjectToken the token being exchanged
     * @return a new builder
     */
    public static Builder builder(String subjectToken) {
        return new Builder(subjectToken);
    }

    /**
     * A builder pre-filled with this request's fields.
     *
     * @return a new builder
     */
    public Builder toBuilder() {
        Builder b = new Builder(subjectToken);
        b.grantType = grantType;
        b.subjectTokenType = subjectTokenType;
        b.resource = resource;
        b.audience = audience;
        b.scope = scope;
        b.requestedTokenType = requestedTokenType;
        b.actorToken = actorToken;
        b.actorTokenType = actorTokenType;
        b.clientAssertion = clientAssertion;
        b.clientAssertionType = clientAssertionType;
        b.clientId = clientId;
        return b;
    }

    /** The form parameters to POST, in wire order, omitting unset fields. */
    Map<String, List<String>> formParameters() {
        Map<String, List<String>> form = new LinkedHashMap<>();
        put(form, "grant_type", grantType);
        put(form, "subject_token", subjectToken);
        put(form, "subject_token_type", subjectTokenType);
        put(form, "resource", resource == null ? null : resource.toString());
        put(form, "audience", audience);
        put(form, "scope", scope);
        put(form, "requested_token_type", requestedTokenType);
        put(form, "actor_token", actorToken);
        put(form, "actor_token_type", actorTokenType);
        put(form, "client_assertion", clientAssertion);
        put(form, "client_assertion_type", clientAssertionType);
        put(form, "client_id", clientId);
        return form;
    }

    private static void put(Map<String, List<String>> form, String name, @Nullable String value) {
        if (value != null) {
            form.computeIfAbsent(name, n -> new ArrayList<>()).add(value);
        }
    }

    /**
     * Never prints the subject token, actor token or client assertion.
     *
     * @return the request without its secrets
     */
    @Override
    public String toString() {
        return "TokenExchangeRequest[grantType=" + grantType + ", subjectTokenType=" + subjectTokenType
                + ", resource=" + resource + ", audience=" + audience + ", scope=" + scope
                + ", requestedTokenType=" + requestedTokenType + ", actorTokenType=" + actorTokenType
                + ", clientAssertionType=" + clientAssertionType + ", clientId=" + clientId + "]";
    }

    /** Builds a {@link TokenExchangeRequest}. */
    public static final class Builder {

        private String grantType = TokenTypes.TOKEN_EXCHANGE_GRANT;
        private final String subjectToken;
        private String subjectTokenType = TokenTypes.ACCESS_TOKEN;
        private @Nullable URI resource;
        private @Nullable String audience;
        private @Nullable String scope;
        private @Nullable String requestedTokenType;
        private @Nullable String actorToken;
        private @Nullable String actorTokenType;
        private @Nullable String clientAssertion;
        private @Nullable String clientAssertionType;
        private @Nullable String clientId;

        private Builder(String subjectToken) {
            this.subjectToken = Objects.requireNonNull(subjectToken, "subjectToken");
        }

        /**
         * The grant type. Defaults to {@link TokenTypes#TOKEN_EXCHANGE_GRANT}.
         *
         * @param grantType the grant type URN
         * @return this builder
         */
        public Builder grantType(String grantType) {
            this.grantType = Objects.requireNonNull(grantType, "grantType");
            return this;
        }

        /**
         * The subject token's type. Defaults to {@link TokenTypes#ACCESS_TOKEN}.
         *
         * @param subjectTokenType the type URN
         * @return this builder
         */
        public Builder subjectTokenType(String subjectTokenType) {
            this.subjectTokenType = Objects.requireNonNull(subjectTokenType, "subjectTokenType");
            return this;
        }

        /**
         * The target resource (RFC 8707).
         *
         * @param resource the resource, or {@code null} for none
         * @return this builder
         */
        public Builder resource(@Nullable URI resource) {
            this.resource = resource;
            return this;
        }

        /**
         * The target audience.
         *
         * @param audience the audience, or {@code null} for none
         * @return this builder
         */
        public Builder audience(@Nullable String audience) {
            this.audience = audience;
            return this;
        }

        /**
         * Space-separated scopes for the issued token.
         *
         * @param scope the scopes, or {@code null} for none
         * @return this builder
         */
        public Builder scope(@Nullable String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * The requested type of the issued token.
         *
         * @param requestedTokenType the type URN, or {@code null} for none
         * @return this builder
         */
        public Builder requestedTokenType(@Nullable String requestedTokenType) {
            this.requestedTokenType = requestedTokenType;
            return this;
        }

        /**
         * The acting party's token and its type (RFC 8693 §2.1).
         *
         * @param actorToken the actor token
         * @param actorTokenType its type URN, such as {@link TokenTypes#JWT}
         * @return this builder
         */
        public Builder actorToken(String actorToken, String actorTokenType) {
            this.actorToken = Objects.requireNonNull(actorToken, "actorToken");
            this.actorTokenType = Objects.requireNonNull(actorTokenType, "actorTokenType");
            return this;
        }

        /**
         * A client authentication assertion and its type.
         *
         * @param clientAssertion the assertion
         * @param clientAssertionType its type URN, such as {@link TokenTypes#JWT_BEARER_ASSERTION}
         * @return this builder
         */
        public Builder clientAssertion(String clientAssertion, String clientAssertionType) {
            this.clientAssertion = Objects.requireNonNull(clientAssertion, "clientAssertion");
            this.clientAssertionType = Objects.requireNonNull(clientAssertionType, "clientAssertionType");
            return this;
        }

        /**
         * The {@code client_id} form parameter.
         *
         * @param clientId the client id, or {@code null} for none
         * @return this builder
         */
        public Builder clientId(@Nullable String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Builds the request.
         *
         * @return the request
         * @throws ConfigurationException when the subject token is empty
         */
        public TokenExchangeRequest build() {
            return new TokenExchangeRequest(
                    grantType,
                    subjectToken,
                    subjectTokenType,
                    resource,
                    audience,
                    scope,
                    requestedTokenType,
                    actorToken,
                    actorTokenType,
                    clientAssertion,
                    clientAssertionType,
                    clientId);
        }
    }
}
