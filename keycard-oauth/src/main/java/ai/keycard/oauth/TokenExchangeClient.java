package ai.keycard.oauth;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * RFC 8693 token exchange against one Keycard zone: trade a subject token for a token scoped to a
 * downstream resource, optionally naming an acting workload, or impersonate a user.
 *
 * <pre>{@code
 * TokenExchangeClient client = TokenExchangeClient.builder(URI.create("https://acme.keycard.cloud"))
 *         .credential(WorkloadIdentity.of(svidSource))
 *         .actor(svidSource)                       // optional: delegation with an actor token
 *         .build();
 * TokenResponse token = client.exchangeToken(userAccessToken, URI.create("https://api.example.com"));
 * }</pre>
 *
 * <p>Client authentication comes from the request when it already carries a {@code
 * client_assertion}, and from the credential otherwise (a Basic header for {@link ClientSecret},
 * form fields for {@link WorkloadIdentity}). The token endpoint is discovered once and cached. Each
 * call sends one token request; nothing is retried and no token is cached. Safe to share between
 * threads.
 */
public final class TokenExchangeClient {

    private static final String SUBSTITUTE_USER_HEADER = encodeJson(orderedMap("typ", "vnd.kc.su+jwt", "alg", "none"));

    private final URI issuer;
    private final @Nullable Credential credential;
    private final @Nullable IdentityTokenSource actor;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final AuthorizationServerMetadataCache metadata;

    private TokenExchangeClient(URI issuer, TokenExchangeClient template) {
        this.issuer = issuer;
        this.credential = template.credential;
        this.actor = template.actor;
        this.transport = template.transport;
        this.fetchTimeout = template.fetchTimeout;
        this.metadata = template.metadata;
    }

    private TokenExchangeClient(Builder builder) {
        this.issuer = builder.issuer;
        this.credential = builder.credential;
        this.actor = builder.actor;
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
        this.metadata = builder.metadataCache != null
                ? builder.metadataCache
                : AuthorizationServerMetadataCache.builder()
                        .discovery(AuthorizationServerDiscovery.builder()
                                .transport(builder.transport)
                                .fetchTimeout(builder.fetchTimeout)
                                .build())
                        .clock(builder.clock)
                        .discoveryTtl(builder.discoveryTtl)
                        .negativeTtl(builder.negativeTtl)
                        .build();
    }

    /**
     * A builder for a client against one zone.
     *
     * @param issuer the zone's issuer, such as {@code https://acme.keycard.cloud}
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        return new Builder(issuer);
    }

    /**
     * Exchanges a subject token for a token targeting {@code resource}, with the request the
     * credential prepares.
     *
     * @param subjectToken the token being exchanged, typically the caller's access token
     * @param resource the target resource, or {@code null}
     * @return the issued token
     * @throws ConfigurationException when the client has no credential
     * @throws OAuthErrorException when the zone answers with an OAuth error, such as {@code
     *     invalid_grant} or {@code invalid_target}
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse exchangeToken(String subjectToken, @Nullable URI resource) {
        return exchangeToken(subjectToken, resource, null);
    }

    /**
     * Exchanges a subject token for a token targeting {@code resource} with the given scopes, with
     * the request the credential prepares.
     *
     * @param subjectToken the token being exchanged, typically the caller's access token
     * @param resource the target resource, or {@code null}
     * @param scope space-separated scopes, or {@code null} for the server's defaults
     * @return the issued token
     * @throws ConfigurationException when the client has no credential
     * @throws OAuthErrorException when the zone answers with an OAuth error, such as {@code
     *     invalid_grant} or {@code invalid_target}
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse exchangeToken(String subjectToken, @Nullable URI resource, @Nullable String scope) {
        if (credential == null) {
            throw new ConfigurationException("exchangeToken(subjectToken, resource) needs a credential");
        }
        TokenExchangeRequest request =
                credential.prepareTokenExchangeRequest(TokenExchangeContext.of(subjectToken, resource, issuer)
                        .withTokenEndpoint(metadata.tokenEndpoint(issuer)));
        if (scope != null) {
            request = request.toBuilder().scope(scope).build();
        }
        return exchangeToken(request);
    }

    /**
     * Sends a token-exchange request. When the client has an {@linkplain Builder#actor actor
     * source} and the request carries no actor token, the source's current token is sent as {@code
     * actor_token} with type {@link TokenTypes#JWT}.
     *
     * @param request the request
     * @return the issued token
     * @throws ConfigurationException when the request carries no assertion and the client has no
     *     credential that can authenticate it
     * @throws OAuthErrorException when the zone answers with an OAuth error
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse exchangeToken(TokenExchangeRequest request) {
        TokenExchangeRequest withActor = request;
        if (actor != null && request.actorToken() == null) {
            withActor = request.toBuilder()
                    .actorToken(fetchActor(actor), TokenTypes.JWT)
                    .build();
        }
        return send(withActor);
    }

    /**
     * Impersonates a user: exchanges a client-built substitute-user token for a token whose {@code
     * sub} is {@code userIdentifier}. No actor token is sent; the zone identifies the acting party
     * from client authentication.
     *
     * @param userIdentifier the target user
     * @param resource the target resource, required
     * @param scope space-separated scopes, or {@code null} for the server's defaults
     * @return the issued token
     * @throws ConfigurationException when the user identifier is empty or the resource is missing
     * @throws OAuthErrorException with {@code invalid_grant} for an unknown user, or {@code
     *     unauthorized_client} when this client may not impersonate
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse impersonate(String userIdentifier, URI resource, @Nullable String scope) {
        Objects.requireNonNull(userIdentifier, "userIdentifier");
        if (userIdentifier.isEmpty()) {
            throw new ConfigurationException("userIdentifier must not be empty");
        }
        if (resource == null) {
            throw new ConfigurationException("impersonation requires a resource");
        }
        TokenExchangeRequest.Builder request = TokenExchangeRequest.builder(substituteUserToken(userIdentifier))
                .subjectTokenType(TokenTypes.SUBSTITUTE_USER)
                .resource(resource)
                .scope(scope);
        return send(request.build());
    }

    /**
     * Impersonates a user with the server's default scopes.
     *
     * @param userIdentifier the target user
     * @param resource the target resource
     * @return the issued token
     * @throws ConfigurationException when the user identifier is empty or the resource is missing
     * @throws OAuthErrorException when the zone answers with an OAuth error
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse impersonate(String userIdentifier, URI resource) {
        return impersonate(userIdentifier, resource, null);
    }

    /**
     * A client for another zone sharing this one's credential, actor, transport and caches (the
     * caches are keyed by issuer, so zones stay isolated). With a multi-zone {@link ClientSecret},
     * the new zone's pair is used, and a zone the credential doesn't hold fails closed before any
     * token request.
     *
     * @param zoneIssuer the other zone's issuer
     * @return the client for that zone
     * @throws ConfigurationException when the issuer isn't an absolute http(s) URL
     */
    public TokenExchangeClient forZone(URI zoneIssuer) {
        AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(zoneIssuer, "zoneIssuer"));
        return new TokenExchangeClient(zoneIssuer, this);
    }

    /**
     * The zone this client exchanges tokens with.
     *
     * @return the issuer
     */
    public URI issuer() {
        return issuer;
    }

    private TokenResponse send(TokenExchangeRequest request) {
        if (request.clientAssertion() == null && !(credential instanceof ClientAuthenticator)) {
            throw new ConfigurationException(
                    "token exchange needs client authentication: a credential that provides it, or a clientAssertion on the request");
        }
        URI endpoint = metadata.tokenEndpoint(issuer);
        ClientAuthentication auth = request.clientAssertion() != null
                ? new ClientAuthentication(Map.of(), Map.of())
                : ((ClientAuthenticator) Objects.requireNonNull(credential)).authenticate(issuer, endpoint);
        return TokenEndpoint.post(transport, endpoint, request.formParameters(), auth, fetchTimeout, "token exchange");
    }

    /** {@code base64url(header).base64url(payload).} with {@code alg: none} and no signature. */
    static String substituteUserToken(String userIdentifier) {
        return SUBSTITUTE_USER_HEADER + "." + encodeJson(orderedMap("sub", userIdentifier)) + ".";
    }

    private static String fetchActor(IdentityTokenSource source) {
        String token;
        try {
            token = source.identityToken();
        } catch (WorkloadIdentityRuntimeException | WorkloadIdentityConfigurationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new WorkloadIdentityRuntimeException(
                    "the actor token source failed: " + e.getClass().getSimpleName(),
                    WorkloadIdentityRuntimeException.SOURCE_CUSTOM,
                    e);
        }
        if (token == null || token.isEmpty()) {
            throw new WorkloadIdentityRuntimeException(
                    "the actor token source returned an empty token",
                    WorkloadIdentityRuntimeException.SOURCE_CUSTOM,
                    null);
        }
        return token;
    }

    private static Map<String, Object> orderedMap(String... keysAndValues) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            map.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return map;
    }

    private static String encodeJson(Map<String, Object> json) {
        return Base64URL.encode(JSONObjectUtils.toJSONString(json).getBytes(StandardCharsets.UTF_8))
                .toString();
    }

    /** Configures a {@link TokenExchangeClient}. */
    public static final class Builder {

        private final URI issuer;
        private @Nullable Credential credential;
        private @Nullable IdentityTokenSource actor;
        private KeycardHttpTransport transport;
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration discoveryTtl = AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL;
        private Duration negativeTtl = AuthorizationServerMetadataCache.DEFAULT_NEGATIVE_TTL;
        private Clock clock = Clock.systemUTC();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder(URI issuer) {
            AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
            this.issuer = issuer;
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * The credential that authenticates this client and prepares its requests.
         *
         * @param credential the credential
         * @return this builder
         */
        public Builder credential(Credential credential) {
            this.credential = Objects.requireNonNull(credential, "credential");
            return this;
        }

        /**
         * An acting workload for delegation (RFC 8693 §2.1): its token is fetched on every exchange
         * and sent as {@code actor_token} with type {@link TokenTypes#JWT}, unless the request sets
         * its own. The zone verifies it like a workload-identity client assertion and nests it in
         * the issued token's {@code act} claim. Never sent on {@link #impersonate}.
         *
         * <p><b>Preview.</b> This option is proposed for the shared SDK specification and not yet
         * settled there. Today the zone accepts only an external workload JWT as the actor, matched
         * against a v1 token credential (resolved by issuer and subject); a v2 credential can't be
         * an actor. That rule may change, and this option with it. To record the calling workload
         * in {@code act} without an actor token, authenticate with {@link WorkloadIdentity} alone:
         * the zone then names the caller as the actor.
         *
         * @param actor supplies the actor's JWT, such as a SPIFFE JWT-SVID
         * @return this builder
         */
        public Builder actor(IdentityTokenSource actor) {
            this.actor = Objects.requireNonNull(actor, "actor");
            return this;
        }

        /**
         * The transport for discovery and token requests. Defaults to {@link
         * KeycardHttpTransport#create()}.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(KeycardHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Sends requests through a caller-configured JDK client.
         *
         * @param client the client
         * @return this builder
         */
        public Builder httpClient(HttpClient client) {
            return transport(KeycardHttpTransport.of(client));
        }

        /**
         * The bound on each discovery and token request. Defaults to 10 seconds.
         *
         * @param fetchTimeout a positive duration
         * @return this builder
         * @throws ConfigurationException when the duration is zero or negative
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            if (fetchTimeout.isNegative() || fetchTimeout.isZero()) {
                throw new ConfigurationException("fetchTimeout must be positive, got " + fetchTimeout);
            }
            this.fetchTimeout = fetchTimeout;
            return this;
        }

        /**
         * How long the discovered token endpoint is reused. Defaults to 1 hour.
         *
         * @param discoveryTtl a positive duration
         * @return this builder
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            this.discoveryTtl = Objects.requireNonNull(discoveryTtl, "discoveryTtl");
            return this;
        }

        /**
         * How long a deterministic discovery failure is remembered. Defaults to 1 minute.
         *
         * @param negativeTtl a duration of zero or more
         * @return this builder
         */
        public Builder negativeTtl(Duration negativeTtl) {
            this.negativeTtl = Objects.requireNonNull(negativeTtl, "negativeTtl");
            return this;
        }

        /**
         * The clock for discovery TTLs. Defaults to the system UTC clock.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * A metadata cache to share with other clients. When set, it replaces the cache this
         * builder would otherwise create, and the TTL and clock settings here are not used.
         *
         * @param metadataCache the shared cache
         * @return this builder
         */
        public Builder metadataCache(AuthorizationServerMetadataCache metadataCache) {
            this.metadataCache = Objects.requireNonNull(metadataCache, "metadataCache");
            return this;
        }

        /**
         * Builds the client.
         *
         * @return the client
         * @throws ConfigurationException when a TTL is out of range
         */
        public TokenExchangeClient build() {
            return new TokenExchangeClient(this);
        }
    }
}
