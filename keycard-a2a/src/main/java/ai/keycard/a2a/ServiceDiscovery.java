package ai.keycard.a2a;

import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.TransportRequest;
import ai.keycard.oauth.TransportResponse;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves an agent's base URL to its agent card, fetched from {@link
 * A2aProtocol#AGENT_CARD_PATH} and cached per base URL (15 minutes by default). Safe to share
 * between threads.
 */
public final class ServiceDiscovery {

    /** How long a card is reused before it's fetched again. */
    public static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(15);

    private record Entry(AgentCard card, Instant fetchedAt) {}

    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final Duration cacheTtl;
    private final Clock clock;
    private final Map<String, Entry> cards = new ConcurrentHashMap<>();

    private ServiceDiscovery(Builder builder) {
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
        this.cacheTtl = builder.cacheTtl;
        this.clock = builder.clock;
    }

    /**
     * A discovery helper with the defaults.
     *
     * @return the helper
     */
    public static ServiceDiscovery create() {
        return builder().build();
    }

    /**
     * A builder for a discovery helper.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The agent's card, from the cache while it's fresh.
     *
     * @param baseUrl the agent's base URL
     * @return the card
     * @throws A2aDiscoveryException when the card can't be fetched, isn't JSON, or has no name
     */
    public AgentCard getCard(URI baseUrl) {
        String key = key(baseUrl);
        Entry entry = cards.get(key);
        if (entry != null && !clock.instant().isAfter(entry.fetchedAt().plus(cacheTtl))) {
            return entry.card();
        }
        return refresh(baseUrl);
    }

    /**
     * Fetches the agent's card now and replaces the cached one.
     *
     * @param baseUrl the agent's base URL
     * @return the card
     * @throws A2aDiscoveryException when the card can't be fetched, isn't JSON, or has no name
     */
    public AgentCard refresh(URI baseUrl) {
        String key = key(baseUrl);
        AgentCard card = fetch(URI.create(key + A2aProtocol.AGENT_CARD_PATH));
        cards.put(key, new Entry(card, clock.instant()));
        return card;
    }

    /** Drops every cached card. */
    public void clearCache() {
        cards.clear();
    }

    static String key(URI baseUrl) {
        String value = Objects.requireNonNull(baseUrl, "baseUrl").toString();
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private AgentCard fetch(URI url) {
        TransportResponse response;
        try {
            response = transport.send(TransportRequest.get(url, fetchTimeout).withHeader("Accept", "application/json"));
        } catch (KeycardException e) {
            throw new A2aDiscoveryException(
                    "agent card fetch from " + url + " failed: " + e.getMessage(), e, e.retryable());
        }
        if (!response.isSuccess()) {
            throw new A2aDiscoveryException(
                    "agent card fetch from " + url + " returned HTTP " + response.status(),
                    null,
                    HttpStatusException.isRetryableStatus(response.status()));
        }
        Map<String, Object> document;
        try {
            document = JSONObjectUtils.parse(response.body());
        } catch (ParseException e) {
            throw new A2aDiscoveryException("agent card from " + url + " is not a JSON object", e, false);
        }
        if (!(document.get("name") instanceof String name) || name.isEmpty()) {
            throw new A2aDiscoveryException("agent card from " + url + " is missing the required name", null, false);
        }
        return new AgentCard(name, document);
    }

    /** Configures a {@link ServiceDiscovery}. */
    public static final class Builder {

        private KeycardHttpTransport transport = KeycardHttpTransport.create();
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration cacheTtl = DEFAULT_CACHE_TTL;
        private Clock clock = Clock.systemUTC();

        private Builder() {}

        /**
         * The transport for card fetches.
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
         * The bound on each card fetch.
         *
         * @param fetchTimeout the timeout
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            this.fetchTimeout = Objects.requireNonNull(fetchTimeout, "fetchTimeout");
            return this;
        }

        /**
         * How long a card is reused.
         *
         * @param cacheTtl the lifetime; defaults to {@link #DEFAULT_CACHE_TTL}
         * @return this builder
         */
        public Builder cacheTtl(Duration cacheTtl) {
            this.cacheTtl = Objects.requireNonNull(cacheTtl, "cacheTtl");
            return this;
        }

        /**
         * The clock for cache lifetimes.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Builds the helper.
         *
         * @return the helper
         */
        public ServiceDiscovery build() {
            return new ServiceDiscovery(this);
        }
    }
}
