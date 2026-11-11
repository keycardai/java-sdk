package ai.keycard.oauth;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;

/**
 * Caches authorization server metadata per issuer, following base.md's metadata-caching rules.
 *
 * <ul>
 *   <li>Successful discovery is reused for {@code discoveryTtl} (default 1 hour).
 *   <li>A transient failure (network error, timeout, interruption, HTTP 429 or 5xx) is never
 *       recorded, so the next call fetches again.
 *   <li>A deterministic failure (any other HTTP 4xx, an issuer mismatch, a malformed document) is
 *       recorded for {@code negativeTtl} (default 1 minute, 0 to disable) and rethrown until then.
 *   <li>Concurrent callers on a cold issuer share one in-flight fetch. If the thread doing that
 *       fetch is interrupted, the waiting callers start a fresh fetch rather than inheriting its
 *       cancellation.
 * </ul>
 *
 * <p>The cache belongs to this instance; nothing is shared between instances. It is safe to use
 * from many threads.
 */
public final class AuthorizationServerMetadataCache {

    /** How long successful discovery is reused by default: 1 hour. */
    public static final Duration DEFAULT_DISCOVERY_TTL = Duration.ofHours(1);

    /** How long a deterministic failure is remembered by default: 1 minute. */
    public static final Duration DEFAULT_NEGATIVE_TTL = Duration.ofMinutes(1);

    private final AuthorizationServerDiscovery discovery;
    private final Clock clock;
    private final Duration discoveryTtl;
    private final Duration negativeTtl;
    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final SingleFlight<String, AuthorizationServerMetadata> inFlight = new SingleFlight<>();

    private AuthorizationServerMetadataCache(Builder builder) {
        this.discovery = builder.discovery;
        this.clock = builder.clock;
        this.discoveryTtl = builder.discoveryTtl;
        // The default failure TTL shrinks to fit a short discovery TTL, so setting only
        // discoveryTtl (as TokenVerifier and the clients do) never fails; an explicit longer
        // negativeTtl is still a configuration error.
        this.negativeTtl =
                builder.negativeTtl.equals(DEFAULT_NEGATIVE_TTL) && builder.negativeTtl.compareTo(discoveryTtl) > 0
                        ? discoveryTtl
                        : builder.negativeTtl;
        if (negativeTtl.compareTo(discoveryTtl) > 0) {
            throw new ConfigurationException(
                    "negativeTtl (" + negativeTtl + ") must not exceed discoveryTtl (" + discoveryTtl + ")");
        }
    }

    /**
     * A cache with default discovery, clock and TTLs.
     *
     * @return a new cache
     */
    public static AuthorizationServerMetadataCache create() {
        return builder().build();
    }

    /**
     * A builder for a configured cache.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The issuer's metadata, from the cache when fresh and from discovery otherwise.
     *
     * @param issuer the authorization server's issuer identifier
     * @return the metadata
     * @throws KeycardException the discovery failure, as {@link
     *     AuthorizationServerDiscovery#discover(URI)} throws it; a remembered deterministic failure
     *     is rethrown as the same instance
     */
    public AuthorizationServerMetadata get(URI issuer) {
        String key = key(issuer);
        Entry entry = entries.get(key);
        if (entry != null && clock.instant().isBefore(entry.expiresAt())) {
            return entry.unwrap();
        }
        return inFlight.run(key, () -> fetch(key, issuer), "discovery of " + issuer);
    }

    /**
     * The issuer's token endpoint, from cached metadata.
     *
     * <p>Metadata without a {@code token_endpoint} is a deterministic discovery failure: it is
     * remembered for {@code negativeTtl} like any other, and discovery runs again after that.
     *
     * @param issuer the authorization server's issuer identifier
     * @return the token endpoint
     * @throws OAuthProtocolException with {@link OAuthProtocolException#INVALID_METADATA} when the
     *     metadata has no token endpoint
     * @throws KeycardException any discovery failure, as {@link #get(URI)} throws it
     */
    public URI tokenEndpoint(URI issuer) {
        return requireEndpoint(issuer, "token_endpoint", AuthorizationServerMetadata::tokenEndpoint);
    }

    /**
     * An endpoint from cached metadata. Its absence fails this lookup and shortens the cached
     * metadata's life to {@code negativeTtl}; lookups of other fields keep working meanwhile.
     *
     * @param field the metadata field name, for the error message
     * @param accessor reads the endpoint from the metadata
     */
    URI requireEndpoint(
            URI issuer,
            String field,
            java.util.function.Function<AuthorizationServerMetadata, @Nullable URI> accessor) {
        AuthorizationServerMetadata metadata = get(issuer);
        URI endpoint = accessor.apply(metadata);
        if (endpoint != null) {
            return endpoint;
        }
        // The metadata stays cached for lookups of other fields (the keyring needs jwks_uri, a
        // token client token_endpoint), but expires within negative_ttl so a corrected document
        // is picked up as base.md requires.
        String key = key(issuer);
        Instant limit = clock.instant().plus(negativeTtl);
        if (negativeTtl.isZero()) {
            entries.remove(key);
        } else {
            entries.computeIfPresent(
                    key,
                    (k, entry) -> entry.metadata() != null && entry.expiresAt().isAfter(limit)
                            ? new Entry(entry.metadata(), null, limit)
                            : entry);
        }
        throw new OAuthProtocolException(
                "metadata for " + issuer + " has no " + field, OAuthProtocolException.INVALID_METADATA);
    }

    /**
     * Drops the cached outcome for one issuer, so the next call fetches again.
     *
     * @param issuer the issuer to forget
     */
    public void invalidate(URI issuer) {
        entries.remove(key(issuer));
        inFlight.forget(key(issuer));
    }

    /** Drops every cached outcome. */
    public void clear() {
        entries.clear();
        inFlight.forgetAll();
    }

    private AuthorizationServerMetadata fetch(String key, URI issuer) {
        // Another caller may have finished a fetch while this one waited to lead.
        Entry entry = entries.get(key);
        if (entry != null && clock.instant().isBefore(entry.expiresAt())) {
            return entry.unwrap();
        }
        try {
            AuthorizationServerMetadata metadata = discovery.discover(issuer);
            entries.put(key, new Entry(metadata, null, clock.instant().plus(discoveryTtl)));
            return metadata;
        } catch (KeycardException e) {
            boolean interrupted = e.getCause() instanceof InterruptedException;
            if (!interrupted && !e.retryable() && !negativeTtl.isZero()) {
                entries.put(key, new Entry(null, e, clock.instant().plus(negativeTtl)));
            }
            throw e;
        }
    }

    private static String key(URI issuer) {
        String value = issuer.toString();
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private record Entry(
            @Nullable AuthorizationServerMetadata metadata,
            @Nullable KeycardException failure,
            Instant expiresAt) {

        AuthorizationServerMetadata unwrap() {
            if (failure != null) {
                throw failure;
            }
            return Objects.requireNonNull(metadata);
        }
    }

    /** Configures an {@link AuthorizationServerMetadataCache}. */
    public static final class Builder {

        private AuthorizationServerDiscovery discovery;
        private Clock clock = Clock.systemUTC();
        private Duration discoveryTtl = DEFAULT_DISCOVERY_TTL;
        private Duration negativeTtl = DEFAULT_NEGATIVE_TTL;

        private Builder() {
            this.discovery = AuthorizationServerDiscovery.create();
        }

        /**
         * The discovery operation to fetch with. Defaults to {@link
         * AuthorizationServerDiscovery#create()}.
         *
         * @param discovery the discovery operation
         * @return this builder
         */
        public Builder discovery(AuthorizationServerDiscovery discovery) {
            this.discovery = Objects.requireNonNull(discovery, "discovery");
            return this;
        }

        /**
         * The clock that decides when entries expire. Defaults to the system UTC clock.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * How long successful discovery is reused. Defaults to 1 hour.
         *
         * @param discoveryTtl a positive duration
         * @return this builder
         * @throws ConfigurationException when the duration is zero or negative
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            if (discoveryTtl.isNegative() || discoveryTtl.isZero()) {
                throw new ConfigurationException("discoveryTtl must be positive, got " + discoveryTtl);
            }
            this.discoveryTtl = discoveryTtl;
            return this;
        }

        /**
         * How long a deterministic failure is remembered. Defaults to 1 minute; zero disables it.
         * Must not exceed the discovery TTL.
         *
         * @param negativeTtl a duration of zero or more
         * @return this builder
         * @throws ConfigurationException when the duration is negative
         */
        public Builder negativeTtl(Duration negativeTtl) {
            if (negativeTtl.isNegative()) {
                throw new ConfigurationException("negativeTtl must not be negative, got " + negativeTtl);
            }
            this.negativeTtl = negativeTtl;
            return this;
        }

        /**
         * Builds the cache.
         *
         * @return the cache
         * @throws ConfigurationException when the negative TTL exceeds the discovery TTL
         */
        public AuthorizationServerMetadataCache build() {
            return new AuthorizationServerMetadataCache(this);
        }
    }
}
