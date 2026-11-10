package ai.keycard.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;

/**
 * Resolves verification keys from an issuer's published JWKS and caches them (jwks-caching.md).
 *
 * <ul>
 *   <li>The issuer's {@code jwks_uri} comes from discovery, cached for {@code discoveryTtl}, and
 *       must share the issuer's origin.
 *   <li>The last key set per {@code jwks_uri} is kept for {@code keyTtl} (default 5 minutes) and
 *       consulted before any fetch.
 *   <li>A {@code kid} the cached set lacks triggers a refetch only once the set is at least {@code
 *       jwksRefetchCooldown} old (default 30 seconds); sooner, it is a {@link
 *       JwksException.KeyNotFound} with no network call. Forged tokens naming random {@code kid}s
 *       therefore cost at most one fetch per cooldown.
 *   <li>Concurrent fetches for one {@code jwks_uri} share a single request, whatever {@code kid}
 *       each caller wants. Failures are never cached.
 * </ul>
 *
 * <p>The cache belongs to this instance and is safe to use from many threads.
 */
public final class JwksKeyring implements VerificationKeyring {

    /** Default key lifetime: 5 minutes. */
    public static final Duration DEFAULT_KEY_TTL = Duration.ofMinutes(5);

    /** Default shortest interval between unknown-{@code kid} refetches: 30 seconds. */
    public static final Duration DEFAULT_JWKS_REFETCH_COOLDOWN = Duration.ofSeconds(30);

    /** Most converted keys held at once; the oldest is evicted first. */
    public static final int MAX_KEYS = 256;

    private final AuthorizationServerMetadataCache metadata;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final Duration keyTtl;
    private final Duration refetchCooldown;
    private final Clock clock;

    private final ConcurrentHashMap<URI, KeySet> keySets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, URI> jwksUriByIssuer = new ConcurrentHashMap<>();
    private final Map<String, CachedKey> keys = new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, CachedKey> eldest) {
            return size() > MAX_KEYS;
        }
    };
    private final SingleFlight<URI, KeySet> fetches = new SingleFlight<>();

    private JwksKeyring(Builder builder) {
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
        this.keyTtl = builder.keyTtl;
        this.refetchCooldown = builder.refetchCooldown;
        this.clock = builder.clock;
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
     * A keyring with default settings.
     *
     * @return a new keyring
     */
    public static JwksKeyring create() {
        return builder().build();
    }

    /**
     * A builder for a configured keyring.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Resolves the key for {@code (issuer, kid)}.
     *
     * @param issuer the token's issuer, already checked against the verifier's trusted set
     * @param kid the token header's key id
     * @return the public key
     * @throws JwksException.Discovery when discovery fails or has no {@code jwks_uri}
     * @throws JwksException.UriValidation when the {@code jwks_uri} is cross-origin
     * @throws JwksException.Fetch when the key set can't be fetched or parsed
     * @throws JwksException.KeyNotFound when the key set holds no such {@code kid}
     */
    @Override
    public PublicKey resolve(URI issuer, String kid) {
        URI jwksUri = jwksUri(issuer);
        String cacheKey = jwksUri + "#" + kid;
        Instant now = clock.instant();
        synchronized (keys) {
            CachedKey cached = keys.get(cacheKey);
            if (cached != null && now.isBefore(cached.expiresAt())) {
                return cached.key();
            }
        }

        KeySet set = keySets.get(jwksUri);
        boolean fresh = set != null && now.isBefore(set.fetchedAt().plus(keyTtl));
        if (!fresh || (set.find(kid) == null && cooldownPassed(set, now))) {
            KeySet stale = set;
            set = fetches.run(jwksUri, () -> fetchUnlessNewer(jwksUri, stale), "the JWKS at " + jwksUri);
        }

        JWK jwk = set.find(kid);
        if (jwk == null) {
            throw new JwksException.KeyNotFound("no key with kid " + kid + " in the JWKS for " + issuer);
        }
        PublicKey key = toPublicKey(jwk, kid);
        synchronized (keys) {
            keys.put(cacheKey, new CachedKey(key, set.fetchedAt().plus(keyTtl)));
        }
        return key;
    }

    /**
     * Drops the key set, converted keys and any in-flight fetch for one issuer, so the next lookup
     * fetches regardless of the cooldown.
     *
     * @param issuer the issuer to forget
     */
    public void invalidate(URI issuer) {
        URI jwksUri = jwksUriByIssuer.remove(key(issuer));
        metadata.invalidate(issuer);
        if (jwksUri != null) {
            keySets.remove(jwksUri);
            fetches.forget(jwksUri);
            String prefix = jwksUri + "#";
            synchronized (keys) {
                keys.keySet().removeIf(k -> k.startsWith(prefix));
            }
        }
    }

    /** Drops every cached key set, key and discovery result. */
    public void clear() {
        jwksUriByIssuer.clear();
        keySets.clear();
        fetches.forgetAll();
        metadata.clear();
        synchronized (keys) {
            keys.clear();
        }
    }

    private URI jwksUri(URI issuer) {
        URI jwksUri;
        try {
            jwksUri = metadata.requireEndpoint(issuer, "jwks_uri", AuthorizationServerMetadata::jwksUri);
        } catch (KeycardException e) {
            throw new JwksException.Discovery("JWKS discovery for " + issuer + " failed: " + e.getMessage(), e);
        }
        if (!sameOrigin(issuer, jwksUri)) {
            throw new JwksException.UriValidation(
                    "jwks_uri " + jwksUri + " does not share the origin of issuer " + issuer);
        }
        jwksUriByIssuer.put(key(issuer), jwksUri);
        return jwksUri;
    }

    private boolean cooldownPassed(KeySet set, Instant now) {
        return !now.isBefore(set.fetchedAt().plus(refetchCooldown));
    }

    /**
     * Fetches the key set unless another caller stored a newer one while this caller waited to
     * lead, in which case that one is reused.
     */
    private KeySet fetchUnlessNewer(URI jwksUri, @Nullable KeySet stale) {
        KeySet current = keySets.get(jwksUri);
        if (current != null && current != stale) {
            return current;
        }
        KeySet fetched = fetch(jwksUri);
        keySets.put(jwksUri, fetched);
        return fetched;
    }

    private KeySet fetch(URI jwksUri) {
        TransportResponse response;
        try {
            response = transport.send(
                    TransportRequest.get(jwksUri, fetchTimeout).withHeader("Accept", "application/json"));
        } catch (NetworkException e) {
            if (e.getCause() instanceof InterruptedException) {
                // The caller was cancelled; rethrow as is so waiting callers fetch again rather
                // than inheriting the cancellation.
                throw e;
            }
            throw new JwksException.Fetch("fetching the JWKS at " + jwksUri + " failed", e, true);
        }
        if (!response.isSuccess()) {
            HttpStatusException status = new HttpStatusException(
                    "JWKS request returned HTTP " + response.status(), response.status(), response.body());
            throw new JwksException.Fetch(
                    "the JWKS at " + jwksUri + " returned HTTP " + response.status(), status, status.retryable());
        }
        try {
            return new KeySet(JWKSet.parse(response.body()), clock.instant());
        } catch (ParseException e) {
            throw new JwksException.Fetch("the JWKS at " + jwksUri + " is not a key set", e, false);
        }
    }

    private static PublicKey toPublicKey(JWK jwk, String kid) {
        try {
            if (jwk instanceof RSAKey rsa) {
                return rsa.toRSAPublicKey();
            }
            if (jwk instanceof ECKey ec) {
                return ec.toECPublicKey();
            }
        } catch (JOSEException e) {
            throw new JwksException.Fetch("key " + kid + " in the JWKS is malformed", e, false);
        }
        throw new JwksException.KeyNotFound("key " + kid + " is a " + jwk.getKeyType() + " key, not RSA or EC");
    }

    static boolean sameOrigin(URI a, URI b) {
        return a.getScheme() != null
                && a.getScheme().equalsIgnoreCase(Objects.toString(b.getScheme(), ""))
                && a.getHost() != null
                && a.getHost().equalsIgnoreCase(Objects.toString(b.getHost(), ""))
                && port(a) == port(b);
    }

    private static int port(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        String scheme = Objects.toString(uri.getScheme(), "").toLowerCase(Locale.ROOT);
        return scheme.equals("https") ? 443 : scheme.equals("http") ? 80 : -1;
    }

    private static String key(URI issuer) {
        String value = issuer.toString();
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private record KeySet(JWKSet set, Instant fetchedAt) {

        @Nullable
        JWK find(String kid) {
            JWK jwk = set.getKeyByKeyId(kid);
            if (jwk == null || (jwk.getKeyUse() != null && jwk.getKeyUse() != KeyUse.SIGNATURE)) {
                return null;
            }
            return jwk;
        }
    }

    private record CachedKey(PublicKey key, Instant expiresAt) {}

    /** Configures a {@link JwksKeyring}. */
    public static final class Builder {

        private KeycardHttpTransport transport;
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration keyTtl = DEFAULT_KEY_TTL;
        private Duration discoveryTtl = AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL;
        private Duration negativeTtl = AuthorizationServerMetadataCache.DEFAULT_NEGATIVE_TTL;
        private Duration refetchCooldown = DEFAULT_JWKS_REFETCH_COOLDOWN;
        private Clock clock = Clock.systemUTC();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder() {
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * The transport for discovery and JWKS requests. Defaults to {@link
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
         * The bound on each discovery and JWKS request. Defaults to 10 seconds.
         *
         * @param fetchTimeout a positive duration
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            this.fetchTimeout = positive(fetchTimeout, "fetchTimeout");
            return this;
        }

        /**
         * How long a fetched key set and its keys are served. Defaults to 5 minutes.
         *
         * @param keyTtl a positive duration
         * @return this builder
         */
        public Builder keyTtl(Duration keyTtl) {
            this.keyTtl = positive(keyTtl, "keyTtl");
            return this;
        }

        /**
         * How long the discovered {@code jwks_uri} is reused. Defaults to 1 hour.
         *
         * @param discoveryTtl a positive duration
         * @return this builder
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            this.discoveryTtl = positive(discoveryTtl, "discoveryTtl");
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
         * The shortest interval between two fetches of one {@code jwks_uri} caused by an unknown
         * {@code kid}. Defaults to 30 seconds; zero fetches on every miss.
         *
         * @param jwksRefetchCooldown a duration of zero or more
         * @return this builder
         */
        public Builder jwksRefetchCooldown(Duration jwksRefetchCooldown) {
            if (jwksRefetchCooldown.isNegative()) {
                throw new ConfigurationException("jwksRefetchCooldown must not be negative");
            }
            this.refetchCooldown = jwksRefetchCooldown;
            return this;
        }

        /**
         * The clock for TTLs and the cooldown. Defaults to the system UTC clock.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * A metadata cache to share with token clients. When set, the discovery TTL settings here
         * are not used.
         *
         * @param metadataCache the shared cache
         * @return this builder
         */
        public Builder metadataCache(AuthorizationServerMetadataCache metadataCache) {
            this.metadataCache = Objects.requireNonNull(metadataCache, "metadataCache");
            return this;
        }

        /**
         * Builds the keyring.
         *
         * @return the keyring
         */
        public JwksKeyring build() {
            return new JwksKeyring(this);
        }

        private static Duration positive(Duration value, String name) {
            if (value.isNegative() || value.isZero()) {
                throw new ConfigurationException(name + " must be positive, got " + value);
            }
            return value;
        }
    }
}
