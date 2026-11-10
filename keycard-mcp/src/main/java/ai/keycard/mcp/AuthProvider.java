package ai.keycard.mcp;

import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.TokenVerifier;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/**
 * The delegated-access side of an MCP server: holds the zone and the application credential,
 * builds the inbound {@link TokenVerifier}, and hands out {@linkplain #grant(String...) grant
 * filters} that exchange the caller's token for one token per downstream resource.
 *
 * <pre>{@code
 * AuthProvider provider = AuthProvider.builder(URI.create("https://acme.keycard.cloud"))
 *         .credential(ClientSecret.of(clientId, clientSecret))
 *         .audiences("https://mcp.example.com/mcp")
 *         .build();
 *
 * context.addFilter(new FilterHolder(RequireBearerAuthFilter.builder(provider.tokenVerifier()).build()), "/mcp/*", REQUEST);
 * context.addFilter(new FilterHolder(provider.grant("https://api.example.com")), "/mcp/*", REQUEST);
 * }</pre>
 *
 * <p>A multi-zone {@link ClientSecret} makes the provider multi-zone: the verifier trusts every
 * zone the credential holds, and a grant exchanges at the zone that issued the caller's token.
 * Safe to share between threads.
 */
public final class AuthProvider {

    private final URI zoneUrl;
    private final List<URI> issuers;
    private final TokenVerifier tokenVerifier;
    private final TokenExchangeClient exchangeClient;

    private AuthProvider(Builder builder) {
        this.zoneUrl = builder.zoneUrl;
        Set<URI> trusted = new LinkedHashSet<>();
        trusted.add(zoneUrl);
        if (builder.credential instanceof ClientSecret secret) {
            trusted.addAll(secret.zones());
        }
        this.issuers = List.copyOf(trusted);

        TokenVerifier.Builder verifier = TokenVerifier.builder(issuers.toArray(URI[]::new))
                .transport(builder.transport)
                .fetchTimeout(builder.fetchTimeout)
                .clock(builder.clock);
        if (builder.audiences.length > 0) {
            verifier.audiences(builder.audiences);
        }
        this.tokenVerifier = verifier.build();

        TokenExchangeClient.Builder exchange = TokenExchangeClient.builder(zoneUrl)
                .transport(builder.transport)
                .fetchTimeout(builder.fetchTimeout)
                .clock(builder.clock);
        if (builder.credential != null) {
            exchange.credential(builder.credential);
        }
        this.exchangeClient = exchange.build();
    }

    /**
     * A builder for a provider in one zone.
     *
     * @param zoneUrl the zone's issuer, such as {@code https://acme.keycard.cloud}
     * @return a new builder
     */
    public static Builder builder(URI zoneUrl) {
        return new Builder(zoneUrl);
    }

    /**
     * The verifier for inbound bearer tokens, trusting every zone this provider serves. Pass it to
     * {@link RequireBearerAuthFilter#builder(TokenVerifier)}.
     *
     * @return the shared verifier
     */
    public TokenVerifier tokenVerifier() {
        return tokenVerifier;
    }

    /**
     * The zones this provider trusts: its zone URL, plus every zone of a multi-zone credential.
     *
     * @return the issuers
     */
    public List<URI> issuers() {
        return issuers;
    }

    /**
     * A filter that exchanges the verified caller's token for one token per resource before the
     * handler runs. It must sit behind {@link RequireBearerAuthFilter}.
     *
     * @param resources the downstream resources, as absolute URIs
     * @return the filter; configure impersonation and scopes with its {@code with} methods
     * @throws ConfigurationException when no resource is given or one isn't an absolute URI
     */
    public GrantFilter grant(String... resources) {
        return new GrantFilter(this, List.of(resources), null, resource -> null);
    }

    /**
     * Exchanges a subject token for one token per resource at this provider's zone.
     *
     * @param subjectToken the caller's access token
     * @param resources the downstream resources
     * @return a new context holding each token or each resource's error; it never throws for a
     *     failed exchange
     */
    public AccessContext exchangeTokens(String subjectToken, String... resources) {
        return exchangeTokensForZone(zoneUrl, subjectToken, resources);
    }

    /**
     * Exchanges a subject token for one token per resource at one of this provider's zones.
     *
     * @param issuer the zone to exchange at
     * @param subjectToken the caller's access token
     * @param resources the downstream resources
     * @return a new context holding each token or each resource's error, or a context-wide error
     *     when this provider doesn't serve the zone
     */
    public AccessContext exchangeTokensForZone(URI issuer, String subjectToken, String... resources) {
        AccessContext context = new AccessContext();
        exchange(context, issuer.toString(), subjectToken, List.of(resources), null, resource -> null);
        return context;
    }

    /**
     * Fills {@code context} with one exchange per resource. Each failure is recorded against its
     * resource; a zone this provider doesn't serve is recorded as a context-wide error.
     */
    void exchange(
            AccessContext context,
            String tokenIssuer,
            String subjectToken,
            List<String> resources,
            @Nullable String userIdentifier,
            Function<String, @Nullable String> scopes) {
        Optional<URI> zone = served(tokenIssuer);
        if (zone.isEmpty()) {
            context.setError(new ConfigurationException(
                    "the caller's token was issued by " + tokenIssuer + ", a zone this provider doesn't serve"));
            return;
        }
        TokenExchangeClient client = zone.get().equals(zoneUrl) ? exchangeClient : exchangeClient.forZone(zone.get());
        for (String resource : resources) {
            URI target = URI.create(resource);
            String scope = scopes.apply(resource);
            try {
                TokenResponse token = userIdentifier != null
                        ? client.impersonate(userIdentifier, target, scope)
                        : client.exchangeToken(subjectToken, target, scope);
                context.setToken(resource, token);
            } catch (KeycardException e) {
                context.setResourceError(resource, e);
            }
        }
    }

    private Optional<URI> served(String tokenIssuer) {
        String wanted = stripSlash(tokenIssuer);
        for (URI issuer : issuers) {
            if (stripSlash(issuer.toString()).equals(wanted)) {
                return Optional.of(issuer);
            }
        }
        return Optional.empty();
    }

    static List<String> checkResources(List<String> resources) {
        if (resources.isEmpty()) {
            throw new ConfigurationException("a grant needs at least one resource");
        }
        List<String> checked = new ArrayList<>(resources.size());
        for (String resource : resources) {
            Objects.requireNonNull(resource, "resource");
            URI uri;
            try {
                uri = URI.create(resource);
            } catch (IllegalArgumentException e) {
                throw new ConfigurationException("the resource " + resource + " is not a valid URI", e);
            }
            if (!uri.isAbsolute()) {
                throw new ConfigurationException("the resource " + resource + " must be an absolute URI");
            }
            checked.add(resource);
        }
        return List.copyOf(checked);
    }

    private static String stripSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    /** Configures an {@link AuthProvider}. */
    public static final class Builder {

        private final URI zoneUrl;
        private @Nullable Credential credential;
        private String[] audiences = new String[0];
        private KeycardHttpTransport transport = KeycardHttpTransport.create();
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Clock clock = Clock.systemUTC();

        private Builder(URI zoneUrl) {
            this.zoneUrl = Objects.requireNonNull(zoneUrl, "zoneUrl");
        }

        /**
         * The application credential that authenticates token exchanges. Without one, grants
         * record a configuration error per resource.
         *
         * @param credential the credential; a multi-zone {@link ClientSecret} makes the provider
         *     multi-zone
         * @return this builder
         */
        public Builder credential(Credential credential) {
            this.credential = Objects.requireNonNull(credential, "credential");
            return this;
        }

        /**
         * Audiences enforced on inbound tokens, normally this server's resource identifier.
         *
         * @param audiences the accepted audiences
         * @return this builder
         */
        public Builder audiences(String... audiences) {
            this.audiences = audiences.clone();
            return this;
        }

        /**
         * The transport for discovery, JWKS and token requests.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(KeycardHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Sends requests through this JDK client.
         *
         * @param client the client
         * @return this builder
         */
        public Builder httpClient(HttpClient client) {
            return transport(KeycardHttpTransport.of(client));
        }

        /**
         * The bound on each outbound request.
         *
         * @param fetchTimeout the timeout; defaults to {@link KeycardHttpTransport#DEFAULT_TIMEOUT}
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            this.fetchTimeout = Objects.requireNonNull(fetchTimeout, "fetchTimeout");
            return this;
        }

        /**
         * The clock for token expiry and cache lifetimes.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Builds the provider.
         *
         * @return the provider
         */
        public AuthProvider build() {
            return new AuthProvider(this);
        }
    }
}
