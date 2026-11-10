package ai.keycard.spiffe;

import ai.keycard.oauth.IdentityTokenSource;
import ai.keycard.oauth.WorkloadIdentityConfigurationException;
import ai.keycard.oauth.WorkloadIdentityRuntimeException;
import io.spiffe.exception.JwtSourceException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.jwtsvid.JwtSvidSource;
import io.spiffe.workloadapi.DefaultJwtSource;
import io.spiffe.workloadapi.JwtSource;
import io.spiffe.workloadapi.JwtSourceOptions;
import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * An {@link IdentityTokenSource} that fetches JWT-SVIDs from the SPIFFE Workload API (a SPIRE
 * agent, for example), for use as a {@code WorkloadIdentity} client assertion or a token-exchange
 * actor token.
 *
 * <pre>{@code
 * try (SpiffeJwtSvidSource svids = SpiffeJwtSvidSource.builder("https://acme.keycard.cloud").build()) {
 *     TokenExchangeClient client = TokenExchangeClient.builder(URI.create("https://acme.keycard.cloud"))
 *             .credential(WorkloadIdentity.of(svids))
 *             .actor(svids)
 *             .build();
 * }
 * }</pre>
 *
 * <p>The Workload API connection opens on the first fetch, not at construction, and is closed by
 * {@link #close()}. Without an explicit {@link Builder#socketPath(String) socket path}, java-spiffe
 * reads {@code SPIFFE_ENDPOINT_SOCKET}, the SPIFFE platform convention. The application adds the
 * gRPC transport for its platform: {@code io.spiffe:grpc-netty-linux}, {@code grpc-netty-macos} or
 * {@code grpc-netty-macos-aarch64}.
 *
 * <p>Failures are {@link WorkloadIdentityRuntimeException}s with the source identifier {@value
 * #SOURCE}. A Workload API that can't be reached or can't issue an SVID is retryable, since a local
 * agent recovers on its own.
 */
public final class SpiffeJwtSvidSource implements IdentityTokenSource, AutoCloseable {

    /** This source's identifier on workload-identity exceptions. */
    public static final String SOURCE = "spiffe";

    /** The default wait for the Workload API to deliver its first bundle: 10 seconds. */
    public static final Duration DEFAULT_INIT_TIMEOUT = Duration.ofSeconds(10);

    private final String audience;
    private final @Nullable SpiffeId spiffeId;
    private final @Nullable String socketPath;
    private final Duration initTimeout;
    private final boolean ownsSource;
    private @Nullable JwtSvidSource source;

    private SpiffeJwtSvidSource(Builder builder) {
        this.audience = builder.audience;
        this.spiffeId = builder.spiffeId;
        this.socketPath = builder.socketPath;
        this.initTimeout = builder.initTimeout;
        this.source = builder.jwtSvidSource;
        this.ownsSource = builder.jwtSvidSource == null;
    }

    /**
     * A builder for a source fetching JWT-SVIDs for {@code audience}, typically the zone URL.
     *
     * @param audience the SVID audience
     * @return a new builder
     * @throws WorkloadIdentityConfigurationException when the audience is blank
     */
    public static Builder builder(String audience) {
        return new Builder(audience);
    }

    /**
     * Fetches a JWT-SVID for the configured audience, and SPIFFE ID when one is set.
     *
     * @return the SVID's compact JWT
     * @throws WorkloadIdentityRuntimeException when the Workload API can't be reached or can't
     *     issue an SVID
     */
    @Override
    public String identityToken() {
        JwtSvid svid;
        try {
            JwtSvidSource jwtSource = source();
            svid = spiffeId == null ? jwtSource.fetchJwtSvid(audience) : jwtSource.fetchJwtSvid(spiffeId, audience);
        } catch (JwtSvidException e) {
            throw new WorkloadIdentityRuntimeException(
                    "the SPIFFE Workload API could not issue a JWT-SVID for " + audience, SOURCE, e, true);
        }
        String token = svid.getToken();
        if (token == null || token.isEmpty()) {
            throw new WorkloadIdentityRuntimeException(
                    "the SPIFFE Workload API returned an empty JWT-SVID", SOURCE, null);
        }
        return token;
    }

    /** Closes the Workload API connection this source opened. An injected source is left open. */
    @Override
    public synchronized void close() {
        if (ownsSource && source instanceof JwtSource jwtSource) {
            try {
                jwtSource.close();
            } catch (IOException e) {
                // nothing useful to do with a failed close
            }
            source = null;
        }
    }

    @Override
    public String toString() {
        return "SpiffeJwtSvidSource[audience=" + audience + ", spiffeId=" + spiffeId + "]";
    }

    private synchronized JwtSvidSource source() {
        if (source != null) {
            return source;
        }
        JwtSourceOptions.Builder options = JwtSourceOptions.builder().initTimeout(initTimeout);
        if (socketPath != null) {
            options.spiffeSocketPath(socketPath);
        }
        try {
            source = DefaultJwtSource.newSource(options.build());
        } catch (SocketEndpointAddressException e) {
            throw new WorkloadIdentityConfigurationException(
                    "invalid SPIFFE Workload API socket address: " + e.getMessage(), SOURCE, e);
        } catch (JwtSourceException e) {
            throw new WorkloadIdentityRuntimeException(
                    "could not connect to the SPIFFE Workload API: " + e.getMessage(), SOURCE, e, true);
        } catch (RuntimeException e) {
            // java-spiffe throws IllegalStateException when no socket is configured and
            // SPIFFE_ENDPOINT_SOCKET is unset, or when no gRPC transport is on the classpath.
            throw new WorkloadIdentityConfigurationException(
                    "could not open the SPIFFE Workload API: " + e.getMessage(), SOURCE, e);
        }
        return source;
    }

    /** Configures a {@link SpiffeJwtSvidSource}. */
    public static final class Builder {

        private final String audience;
        private @Nullable SpiffeId spiffeId;
        private @Nullable String socketPath;
        private Duration initTimeout = DEFAULT_INIT_TIMEOUT;
        private @Nullable JwtSvidSource jwtSvidSource;

        private Builder(String audience) {
            Objects.requireNonNull(audience, "audience");
            if (audience.isBlank()) {
                throw new WorkloadIdentityConfigurationException("audience must not be empty", SOURCE, null);
            }
            this.audience = audience;
        }

        /**
         * The SPIFFE ID to fetch for, when the workload holds more than one.
         *
         * @param spiffeId a SPIFFE ID such as {@code spiffe://bank.example/engine}
         * @return this builder
         * @throws WorkloadIdentityConfigurationException when the ID doesn't parse
         */
        public Builder spiffeId(String spiffeId) {
            try {
                this.spiffeId = SpiffeId.parse(Objects.requireNonNull(spiffeId, "spiffeId"));
            } catch (RuntimeException e) {
                // java-spiffe throws its own InvalidSpiffeIdException, a RuntimeException.
                throw new WorkloadIdentityConfigurationException("invalid SPIFFE ID: " + spiffeId, SOURCE, e);
            }
            return this;
        }

        /**
         * The Workload API address, such as {@code unix:/run/spire/sockets/agent.sock}. Defaults to
         * {@code SPIFFE_ENDPOINT_SOCKET}.
         *
         * @param socketPath the socket address
         * @return this builder
         */
        public Builder socketPath(String socketPath) {
            this.socketPath = Objects.requireNonNull(socketPath, "socketPath");
            return this;
        }

        /**
         * How long the first connection waits for the Workload API. Defaults to 10 seconds.
         *
         * @param initTimeout a positive duration
         * @return this builder
         */
        public Builder initTimeout(Duration initTimeout) {
            if (initTimeout.isNegative() || initTimeout.isZero()) {
                throw new WorkloadIdentityConfigurationException(
                        "initTimeout must be positive, got " + initTimeout, SOURCE, null);
            }
            this.initTimeout = initTimeout;
            return this;
        }

        /**
         * An existing java-spiffe source to fetch from, shared with the rest of the application.
         * The caller keeps ownership and closes it.
         *
         * @param jwtSvidSource the source
         * @return this builder
         */
        public Builder jwtSvidSource(JwtSvidSource jwtSvidSource) {
            this.jwtSvidSource = Objects.requireNonNull(jwtSvidSource, "jwtSvidSource");
            return this;
        }

        /**
         * Builds the source without connecting.
         *
         * @return the source
         */
        public SpiffeJwtSvidSource build() {
            return new SpiffeJwtSvidSource(this);
        }
    }
}
