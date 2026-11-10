package ai.keycard.oauth;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

/**
 * Fetches an OIDC identity token for the default service account from the GCP metadata server.
 * Covers GKE, GCE and Cloud Run.
 *
 * <pre>{@code
 * GcpMetadataTokenSource source = GcpMetadataTokenSource.builder("https://acme.keycard.cloud").build();
 * }</pre>
 */
public final class GcpMetadataTokenSource implements IdentityTokenSource {

    /** The metadata server's base URL. */
    public static final URI DEFAULT_METADATA_URL = URI.create("http://metadata.google.internal");

    /** The default bound on each metadata request: 5 seconds. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    static final String IDENTITY_PATH = "/computeMetadata/v1/instance/service-accounts/default/identity";

    private final URI identityUrl;
    private final Duration timeout;
    private final KeycardHttpTransport transport;

    private GcpMetadataTokenSource(Builder builder) {
        String base = builder.metadataUrl.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        this.identityUrl = URI.create(base + IDENTITY_PATH + "?audience="
                + URLEncoder.encode(builder.audience, StandardCharsets.UTF_8) + "&format=full");
        this.timeout = builder.timeout;
        this.transport = builder.transport;
    }

    /**
     * A builder for a source requesting tokens for {@code audience}, typically the zone URL.
     *
     * @param audience the audience the token is minted for
     * @return a new builder
     * @throws WorkloadIdentityConfigurationException when the audience is blank
     */
    public static Builder builder(String audience) {
        return new Builder(audience);
    }

    /**
     * Requests a token from the metadata server.
     *
     * @return the token
     * @throws WorkloadIdentityRuntimeException when the server is unreachable, answers non-200, or
     *     returns an empty body; retryable when the cause was a network failure
     */
    @Override
    public String identityToken() {
        TransportResponse response;
        try {
            response =
                    transport.send(TransportRequest.get(identityUrl, timeout).withHeader("Metadata-Flavor", "Google"));
        } catch (KeycardException e) {
            throw new WorkloadIdentityRuntimeException(
                    "calling the GCP metadata server at " + identityUrl.getHost() + " failed (is this running on GCP?)",
                    WorkloadIdentityRuntimeException.SOURCE_GCP_METADATA,
                    e);
        }
        if (response.status() != 200) {
            throw new WorkloadIdentityRuntimeException(
                    "the GCP metadata server returned HTTP " + response.status(),
                    WorkloadIdentityRuntimeException.SOURCE_GCP_METADATA,
                    new HttpStatusException("metadata request failed", response.status(), response.body()));
        }
        String token = response.body().strip();
        if (token.isEmpty()) {
            throw new WorkloadIdentityRuntimeException(
                    "the GCP metadata server returned an empty token",
                    WorkloadIdentityRuntimeException.SOURCE_GCP_METADATA,
                    null);
        }
        return token;
    }

    @Override
    public String toString() {
        return "GcpMetadataTokenSource[" + identityUrl + "]";
    }

    /** Configures a {@link GcpMetadataTokenSource}. */
    public static final class Builder {

        private final String audience;
        private URI metadataUrl = DEFAULT_METADATA_URL;
        private Duration timeout = DEFAULT_TIMEOUT;
        private KeycardHttpTransport transport;

        private Builder(String audience) {
            Objects.requireNonNull(audience, "audience");
            if (audience.isBlank()) {
                throw new WorkloadIdentityConfigurationException(
                        "audience must not be empty", WorkloadIdentityRuntimeException.SOURCE_GCP_METADATA, null);
            }
            this.audience = audience;
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * The metadata server's base URL, for tests. Defaults to {@link #DEFAULT_METADATA_URL}.
         *
         * @param metadataUrl the base URL
         * @return this builder
         */
        public Builder metadataUrl(URI metadataUrl) {
            this.metadataUrl = Objects.requireNonNull(metadataUrl, "metadataUrl");
            return this;
        }

        /**
         * The bound on each metadata request. Defaults to 5 seconds.
         *
         * @param timeout a positive duration
         * @return this builder
         */
        public Builder timeout(Duration timeout) {
            if (timeout.isNegative() || timeout.isZero()) {
                throw new WorkloadIdentityConfigurationException(
                        "timeout must be positive, got " + timeout,
                        WorkloadIdentityRuntimeException.SOURCE_GCP_METADATA,
                        null);
            }
            this.timeout = timeout;
            return this;
        }

        /**
         * The transport for metadata requests. Defaults to {@link KeycardHttpTransport#create()}.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(KeycardHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Builds the source.
         *
         * @return the source
         */
        public GcpMetadataTokenSource build() {
            return new GcpMetadataTokenSource(this);
        }
    }
}
