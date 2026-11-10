package ai.keycard.oauth;

import java.net.URI;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A {@code client_credentials} token request (RFC 6749 §4.4). Every field is optional.
 *
 * @param scope space-separated scopes for the token, or {@code null}
 * @param resource the RFC 8707 resource the token is for, or {@code null}
 * @param clientAssertion a caller-supplied client assertion, or {@code null}; when set it
 *     authenticates the request on its own and the client's credential is not used
 * @param clientAssertionType the assertion's type, set whenever {@code clientAssertion} is
 */
public record ClientCredentialsRequest(
        @Nullable String scope,
        @Nullable URI resource,
        @Nullable String clientAssertion,
        @Nullable String clientAssertionType) {

    /** A request with no scope, no resource and no assertion. */
    public static final ClientCredentialsRequest EMPTY = new ClientCredentialsRequest(null, null, null, null);

    /**
     * Validates that an assertion carries its type.
     *
     * @param scope the scopes, or {@code null}
     * @param resource the resource, or {@code null}
     * @param clientAssertion the assertion, or {@code null}
     * @param clientAssertionType the assertion's type, or {@code null}
     */
    public ClientCredentialsRequest {
        if (clientAssertion != null && clientAssertionType == null) {
            throw new ConfigurationException("clientAssertionType is required when clientAssertion is set");
        }
    }

    /**
     * A builder for a request.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Never prints the client assertion.
     *
     * @return the request without the assertion
     */
    @Override
    public String toString() {
        return "ClientCredentialsRequest[scope=" + scope + ", resource=" + resource + ", clientAssertionType="
                + clientAssertionType + "]";
    }

    /** Builds a {@link ClientCredentialsRequest}. */
    public static final class Builder {

        private @Nullable String scope;
        private @Nullable URI resource;
        private @Nullable String clientAssertion;
        private @Nullable String clientAssertionType;

        private Builder() {}

        /**
         * Space-separated scopes for the token.
         *
         * @param scope the scopes, or {@code null} for none
         * @return this builder
         */
        public Builder scope(@Nullable String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * The RFC 8707 resource the token is for.
         *
         * @param resource the resource, or {@code null} for none
         * @return this builder
         */
        public Builder resource(@Nullable URI resource) {
            this.resource = resource;
            return this;
        }

        /**
         * A caller-supplied client assertion, which replaces the client's credential for this
         * request.
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
         * Builds the request.
         *
         * @return the request
         */
        public ClientCredentialsRequest build() {
            return new ClientCredentialsRequest(scope, resource, clientAssertion, clientAssertionType);
        }
    }
}
