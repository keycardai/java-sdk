package ai.keycard.oauth;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Authenticates a workload with a platform-signed OIDC token as its client assertion (RFC 7523
 * {@code jwt-bearer}). One credential for every platform; an {@link IdentityTokenSource} supplies
 * the token.
 *
 * <pre>{@code
 * WorkloadIdentity credential = WorkloadIdentity.builder(FileTokenSource.builder().build())
 *         .clientId("my-app-credential")
 *         .build();
 * }</pre>
 *
 * <p>The source is called on every request and its token is never cached here. The token is
 * opaque to the credential: it is sent as returned, never decoded, and the zone validates it.
 */
public final class WorkloadIdentity implements Credential, ClientAuthenticator {

    private final IdentityTokenSource source;
    private final @Nullable String clientId;

    private WorkloadIdentity(Builder builder) {
        this.source = builder.source;
        this.clientId = builder.clientId;
    }

    /**
     * A builder for a credential backed by {@code source}.
     *
     * @param source supplies the platform token; a lambda works
     * @return a new builder
     */
    public static Builder builder(IdentityTokenSource source) {
        return new Builder(source);
    }

    /**
     * A credential backed by {@code source}, with no {@code client_id}.
     *
     * @param source supplies the platform token
     * @return the credential
     */
    public static WorkloadIdentity of(IdentityTokenSource source) {
        return builder(source).build();
    }

    /**
     * A token-exchange request carrying the source's current token as {@code client_assertion}, the
     * access-token subject type, and {@code client_id} when configured.
     *
     * @param context the subject token, resource and zone
     * @return the request
     * @throws WorkloadIdentityRuntimeException when the source fails
     */
    @Override
    public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
        return TokenExchangeRequest.builder(context.subjectToken())
                .subjectTokenType(TokenTypes.ACCESS_TOKEN)
                .resource(context.resource())
                .clientAssertion(fetch(), TokenTypes.JWT_BEARER_ASSERTION)
                .clientId(clientId)
                .build();
    }

    /**
     * Form fields carrying the source's current token: {@code client_assertion}, {@code
     * client_assertion_type}, and {@code client_id} when configured. No headers.
     *
     * @param issuer the zone's issuer; unused, since the platform token isn't zone-specific
     * @param endpoint the request's URL; unused, since the platform fixed the token's audience
     * @return the authentication
     * @throws WorkloadIdentityRuntimeException when the source fails
     */
    @Override
    public ClientAuthentication authenticate(URI issuer, URI endpoint) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("client_assertion", fetch());
        fields.put("client_assertion_type", TokenTypes.JWT_BEARER_ASSERTION);
        if (clientId != null) {
            fields.put("client_id", clientId);
        }
        return ClientAuthentication.formFields(fields);
    }

    /**
     * The configured {@code client_id}.
     *
     * @return the id, or {@code null} when none is configured
     */
    public @Nullable String clientId() {
        return clientId;
    }

    @Override
    public String toString() {
        return "WorkloadIdentity[source=" + source + ", clientId=" + clientId + "]";
    }

    private String fetch() {
        String token;
        try {
            token = source.identityToken();
        } catch (WorkloadIdentityRuntimeException | WorkloadIdentityConfigurationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new WorkloadIdentityRuntimeException(
                    "the identity token source failed: " + e.getClass().getSimpleName(),
                    WorkloadIdentityRuntimeException.SOURCE_CUSTOM,
                    e);
        }
        if (token == null || token.isEmpty()) {
            throw new WorkloadIdentityRuntimeException(
                    "the identity token source returned an empty token",
                    WorkloadIdentityRuntimeException.SOURCE_CUSTOM,
                    null);
        }
        return token;
    }

    /** Configures a {@link WorkloadIdentity}. */
    public static final class Builder {

        private final IdentityTokenSource source;
        private @Nullable String clientId;

        private Builder(IdentityTokenSource source) {
            this.source = Objects.requireNonNull(source, "source");
        }

        /**
         * The Keycard application credential's id, sent as the {@code client_id} form parameter. A
         * token-federation (v2) application credential requires it.
         *
         * @param clientId the id
         * @return this builder
         * @throws ConfigurationException when the id is empty
         */
        public Builder clientId(String clientId) {
            Objects.requireNonNull(clientId, "clientId");
            if (clientId.isEmpty()) {
                throw new ConfigurationException("clientId must not be empty");
            }
            this.clientId = clientId;
            return this;
        }

        /**
         * Builds the credential.
         *
         * @return the credential
         */
        public WorkloadIdentity build() {
            return new WorkloadIdentity(this);
        }
    }
}
