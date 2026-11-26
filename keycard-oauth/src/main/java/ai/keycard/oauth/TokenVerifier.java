package ai.keycard.oauth;

import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Verifies bearer tokens for a resource server: a {@link JwtVerifier} over a {@link JwksKeyring},
 * returning an {@link AccessToken}. Build one per server with the trusted zone issuer or issuers;
 * key and discovery caches are keyed by issuer, so no zone's keys are served for another.
 *
 * <pre>{@code
 * TokenVerifier verifier = TokenVerifier.builder(URI.create("https://acme.keycard.cloud"))
 *         .audiences("https://api.example.com")
 *         .build();
 * AccessToken caller = verifier.verifyToken(bearerToken);
 * }</pre>
 *
 * <p>Without audiences the verifier accepts a token minted for any resource in the zone, so
 * construction logs one warning through {@link System#getLogger(String)}.
 */
public final class TokenVerifier {

    private static final System.Logger LOG = System.getLogger(TokenVerifier.class.getName());

    private final List<URI> issuers;
    private final String[] audiences;
    private final Map<URI, String> audiencesByIssuer;
    private final String[] algorithms;
    private final Duration clockSkew;
    private final Clock clock;
    private final JwksKeyring keyring;
    private final @Nullable JwtVerifier verifier;
    private final Map<URI, JwtVerifier> scopedVerifiers;

    private TokenVerifier(Builder builder) {
        this.issuers = List.copyOf(builder.issuers);
        this.audiences = builder.audiences;
        this.audiencesByIssuer = builder.audiencesByIssuer;
        this.algorithms = builder.algorithms;
        this.clockSkew = builder.clockSkew;
        this.clock = builder.clock;
        this.keyring = builder.keyring != null
                ? builder.keyring
                : JwksKeyring.builder()
                        .transport(builder.transport)
                        .fetchTimeout(builder.fetchTimeout)
                        .keyTtl(builder.keyTtl)
                        .discoveryTtl(builder.discoveryTtl)
                        .clock(builder.clock)
                        .build();
        this.verifier = audiencesByIssuer.isEmpty() ? jwtVerifier(issuers, audiences) : null;
        Map<URI, JwtVerifier> scoped = new HashMap<>();
        for (URI issuer : issuers) {
            String[] expected = audiencesByIssuer.isEmpty() ? audiences : new String[] {audiencesByIssuer.get(issuer)};
            scoped.put(issuer, jwtVerifier(List.of(issuer), expected));
        }
        this.scopedVerifiers = Map.copyOf(scoped);
        if (audiences.length == 0 && audiencesByIssuer.isEmpty() && !builder.allowAnyAudience) {
            LOG.log(
                    Level.WARNING,
                    "TokenVerifier has no audiences configured, so it accepts a token minted for any resource in the "
                            + "zone; configure resource_identifier on the resource server or audiences(...) on the verifier.");
        }
    }

    /**
     * A builder trusting tokens from these zone issuers.
     *
     * @param issuers the trusted issuers
     * @return a new builder
     * @throws ConfigurationException when no issuer is given
     */
    public static Builder builder(URI... issuers) {
        return new Builder(List.of(issuers));
    }

    /**
     * Verifies a token against every trusted issuer.
     *
     * @param token the compact JWT
     * @return the verified token
     * @throws InvalidTokenException when verification fails
     * @throws JwksException when the issuer's keys can't be fetched
     */
    public AccessToken verifyToken(String token) {
        if (verifier == null) {
            throw new InvalidTokenException("this verifier requires a request-selected zone");
        }
        return new AccessToken(token, verifier.verify(token));
    }

    /**
     * Verifies a token pinned to one zone. A token another zone minted is rejected before key
     * resolution, and a zone this verifier doesn't trust fails closed.
     *
     * @param token the compact JWT
     * @param issuer the zone's issuer, resolved from the request
     * @return the verified token
     * @throws InvalidTokenException when the zone isn't trusted or verification fails
     * @throws JwksException when the zone's keys can't be fetched
     */
    public AccessToken verifyTokenForZone(String token, URI issuer) {
        JwtVerifier scoped = scopedVerifiers.get(issuer);
        if (scoped == null) {
            throw new InvalidTokenException("zone " + issuer + " is not configured on this verifier");
        }
        return new AccessToken(token, scoped.verify(token));
    }

    /** Drops every cached key and discovery result. */
    public void clearCache() {
        keyring.clear();
    }

    /**
     * The trusted issuers.
     *
     * @return the issuers, in configuration order
     */
    public List<URI> issuers() {
        return issuers;
    }

    /**
     * The global audience list, empty when unrestricted or configured per issuer.
     *
     * @return the global audiences
     */
    public List<String> audiences() {
        return List.of(audiences);
    }

    /**
     * The exact audience required for each issuer when the request selects the zone.
     *
     * @return the per-issuer audience configuration
     */
    public Map<URI, String> audiencesByIssuer() {
        return audiencesByIssuer;
    }

    private JwtVerifier jwtVerifier(List<URI> trusted, String[] expectedAudiences) {
        JwtVerifier.Builder builder = JwtVerifier.builder(trusted.toArray(URI[]::new))
                .algorithms(algorithms)
                .clockSkew(clockSkew)
                .keyring(keyring)
                .clock(clock);
        if (expectedAudiences.length > 0) {
            builder.audiences(expectedAudiences);
        }
        return builder.build();
    }

    /** Configures a {@link TokenVerifier}. */
    public static final class Builder {

        private final List<URI> issuers;
        private String[] audiences = new String[0];
        private Map<URI, String> audiencesByIssuer = Map.of();
        private boolean allowAnyAudience;
        private String[] algorithms = {"RS256"};
        private Duration clockSkew = Duration.ZERO;
        private KeycardHttpTransport transport;
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration keyTtl = JwksKeyring.DEFAULT_KEY_TTL;
        private Duration discoveryTtl = AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL;
        private Clock clock = Clock.systemUTC();
        private @Nullable JwksKeyring keyring;

        private Builder(List<URI> issuers) {
            List<URI> values = new ArrayList<>();
            for (URI issuer : issuers) {
                values.add(Objects.requireNonNull(issuer, "issuer"));
            }
            if (values.isEmpty()) {
                throw new ConfigurationException("TokenVerifier requires at least one trusted issuer");
            }
            this.issuers = values;
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * This server's registered resource identifiers; a token's {@code aud} must contain one.
         *
         * @param audiences the accepted audiences
         * @return this builder
         * @throws ConfigurationException when no audience is supplied
         */
        public Builder audiences(String... audiences) {
            if (audiences.length == 0) {
                throw new ConfigurationException("audiences must not be empty");
            }
            this.audiences = audiences.clone();
            return this;
        }

        /**
         * Requires one exact audience for each request-selected issuer.
         *
         * @param audiences the mapping, covering all trusted issuers
         * @return this builder
         */
        public Builder audiencesByIssuer(Map<URI, String> audiences) {
            if (!audiences.keySet().equals(Set.copyOf(issuers))
                    || audiences.values().stream().anyMatch(String::isBlank)) {
                throw new ConfigurationException("per-issuer audiences must cover exactly the trusted issuers");
            }
            this.audiencesByIssuer = Map.copyOf(audiences);
            return this;
        }

        /**
         * Explicitly skips audience validation while retaining all other verification.
         *
         * @return this builder
         */
        public Builder allowAnyAudience() {
            this.allowAnyAudience = true;
            return this;
        }

        /**
         * Allowed algorithms. Defaults to {@code RS256}.
         *
         * @param algorithms values from {@link JwtVerifier#SUPPORTED_ALGORITHMS}
         * @return this builder
         */
        public Builder algorithms(String... algorithms) {
            this.algorithms = algorithms.clone();
            return this;
        }

        /**
         * Leeway on {@code exp} and {@code nbf}. Defaults to zero.
         *
         * @param clockSkew a duration of zero or more
         * @return this builder
         */
        public Builder clockSkew(Duration clockSkew) {
            this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
            return this;
        }

        /**
         * The transport for discovery and JWKS requests.
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
         * The bound on each discovery and JWKS request. Defaults to 10 seconds.
         *
         * @param fetchTimeout a positive duration
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            this.fetchTimeout = Objects.requireNonNull(fetchTimeout, "fetchTimeout");
            return this;
        }

        /**
         * How long keys are cached. Defaults to 5 minutes.
         *
         * @param keyTtl a positive duration
         * @return this builder
         */
        public Builder keyTtl(Duration keyTtl) {
            this.keyTtl = Objects.requireNonNull(keyTtl, "keyTtl");
            return this;
        }

        /**
         * How long the discovered {@code jwks_uri} is reused. Defaults to 1 hour.
         *
         * @param discoveryTtl a positive duration
         * @return this builder
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            this.discoveryTtl = Objects.requireNonNull(discoveryTtl, "discoveryTtl");
            return this;
        }

        /**
         * The clock for expiry and caches. Defaults to the system UTC clock.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * A keyring to use instead of building one, such as one shared with another verifier.
         *
         * @param keyring the keyring
         * @return this builder
         */
        public Builder keyring(JwksKeyring keyring) {
            this.keyring = Objects.requireNonNull(keyring, "keyring");
            return this;
        }

        /**
         * Builds the verifier.
         *
         * @return the verifier
         * @throws ConfigurationException for an unsupported algorithm or out-of-range setting
         */
        public TokenVerifier build() {
            if ((allowAnyAudience && (audiences.length > 0 || !audiencesByIssuer.isEmpty()))
                    || (audiences.length > 0 && !audiencesByIssuer.isEmpty())) {
                throw new ConfigurationException("conflicting audience policies");
            }
            return new TokenVerifier(this);
        }
    }
}
