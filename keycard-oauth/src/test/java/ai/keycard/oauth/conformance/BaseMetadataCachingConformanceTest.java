package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AuthorizationServerDiscovery;
import ai.keycard.oauth.AuthorizationServerMetadata;
import ai.keycard.oauth.AuthorizationServerMetadataCache;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.TransportResponse;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.TestClock;
import java.net.ConnectException;
import java.net.URI;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * base.md (spec-version 5), Operational principles: discovery once per zone, metadata failures are
 * not sticky, and no global state.
 */
class BaseMetadataCachingConformanceTest {

    private static final URI ISSUER = URI.create("https://acme.keycard.cloud");
    private static final String METADATA = "{\"issuer\":\"https://acme.keycard.cloud\","
            + "\"token_endpoint\":\"https://acme.keycard.cloud/oauth/token\"}";

    private final TestClock clock = TestClock.start();

    @Test
    @DisplayName("discovery once per zone: reused until discovery_ttl elapses, then fetched again")
    void successIsCachedForDiscoveryTtl() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            AuthorizationServerMetadataCache cache = cache(Duration.ofHours(1), Duration.ofMinutes(1));

            AuthorizationServerMetadata first = cache.get(zone.issuer());
            clock.advance(Duration.ofMinutes(59));
            assertThat(cache.get(zone.issuer())).isSameAs(first);
            assertThat(cache.get(URI.create(zone.issuer() + "/"))).isSameAs(first);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);

            clock.advance(Duration.ofMinutes(1));
            cache.get(zone.issuer());
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("defaults: discovery_ttl 1 hour, negative_ttl 1 minute")
    void defaults() {
        assertThat(AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL).isEqualTo(Duration.ofHours(1));
        assertThat(AuthorizationServerMetadataCache.DEFAULT_NEGATIVE_TTL).isEqualTo(Duration.ofMinutes(1));
    }

    @Test
    @DisplayName("row 3: 5xx responses are paced; a 429 without Retry-After is not")
    void transientHttpFailuresAreNotCached() {
        for (int status : List.of(503, 500, 429)) {
            try (StubZone zone = StubZone.start()) {
                zone.respond("GET", StubZone.DISCOVERY_PATH, status, "{}");
                AuthorizationServerMetadataCache cache = cache(Duration.ofHours(1), Duration.ofMinutes(1));

                assertThatThrownBy(() -> cache.get(zone.issuer())).isInstanceOf(HttpStatusException.class);
                assertThatThrownBy(() -> cache.get(zone.issuer())).isInstanceOf(HttpStatusException.class);
                assertThat(zone.requests(StubZone.DISCOVERY_PATH))
                        .as("%d", status)
                        .hasSize(status == 429 ? 2 : 1);

                zone.serveDiscovery();
                clock.advance(Duration.ofMillis(1200));
                assertThat(cache.get(zone.issuer()).issuer()).isEqualTo(zone.issuer());
            }
        }
    }

    @Test
    @DisplayName("row 3: network failures use jittered exponential delays capped at 30 seconds")
    void networkFailuresAreNotCached() {
        AtomicInteger calls = new AtomicInteger();
        KeycardHttpTransport transport = request -> {
            if (calls.incrementAndGet() <= 7) {
                throw new NetworkException("refused", new ConnectException("refused"));
            }
            return ok(METADATA);
        };
        AuthorizationServerMetadataCache cache = cache(transport, Duration.ofHours(1), Duration.ofMinutes(1));

        long[] earliest = {800, 1600, 3200, 6400, 12800, 25600, 30000};
        long[] latest = {1200, 2400, 4800, 9600, 19200, 30000, 30000};
        for (int i = 0; i < earliest.length; i++) {
            assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(NetworkException.class);
            clock.advance(Duration.ofMillis(earliest[i] - 1));
            assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(NetworkException.class);
            assertThat(calls).hasValue(i + 1);
            clock.advance(Duration.ofMillis(latest[i] - earliest[i] + 1));
        }
        assertThat(cache.get(ISSUER).issuer()).isEqualTo(ISSUER);
        assertThat(calls).hasValue(8);
    }

    @Test
    @DisplayName("row 2: Retry-After seconds and dates gate requests, capped at 60 seconds")
    void retryAfter() {
        for (int status : List.of(429, 503)) {
            for (long delay : List.of(5L, 120L)) {
                for (DateTimeFormatter formatter : List.of(
                        DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'", Locale.US),
                        DateTimeFormatter.ofPattern("EEEE, dd-MMM-uu HH:mm:ss 'GMT'", Locale.US),
                        DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss uuuu", Locale.US))) {
                    assertRetryAfter(
                            status,
                            delay,
                            formatter.format(clock.instant().plusSeconds(delay).atZone(ZoneOffset.UTC)));
                }
                assertRetryAfter(status, delay, Long.toString(delay));
            }
        }
    }

    @Test
    @DisplayName("row 2: a malformed HTTP-date on a 429 does not pace the next fetch")
    void rejectsMalformedRetryAfterDates() {
        for (String header : List.of(
                "Tue, 10 Nov 2026 12:01 GMT",
                "Tue, 10 Nov 2026 12:01:00 +0000",
                "Tue, 10 Nov 2026 12:01:00 GMT junk",
                "Tue Nov 32 12:01:00 2026")) {
            AtomicInteger calls = new AtomicInteger();
            AuthorizationServerMetadataCache cache = cache(
                    request -> calls.incrementAndGet() == 1
                            ? new TransportResponse(429, Map.of("Retry-After", List.of(header)), "")
                            : ok(METADATA),
                    Duration.ofHours(1),
                    Duration.ofMinutes(1));
            assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(HttpStatusException.class);
            assertThat(cache.get(ISSUER).issuer()).isEqualTo(ISSUER);
            assertThat(calls).hasValue(2);
        }
    }

    @Test
    @DisplayName("row 3: an invalidated transient failure does not pace the next fetch")
    void invalidationDiscardsPendingFailure() {
        for (int status : List.of(400, 503)) {
            AtomicInteger calls = new AtomicInteger();
            AtomicReference<AuthorizationServerMetadataCache> cacheRef = new AtomicReference<>();
            AuthorizationServerMetadataCache cache = cache(
                    request -> {
                        if (calls.incrementAndGet() == 1) {
                            cacheRef.get().invalidate(ISSUER);
                            return new TransportResponse(status, Map.of("Retry-After", List.of("60")), "");
                        }
                        return ok(METADATA);
                    },
                    Duration.ofHours(1),
                    Duration.ofMinutes(1));
            cacheRef.set(cache);
            assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(HttpStatusException.class);
            assertThat(cache.get(ISSUER).issuer()).isEqualTo(ISSUER);
            assertThat(calls).hasValue(2);
        }
    }

    @Test
    @DisplayName("row 3: retry pacing evicts the oldest issuer when its cache is full")
    void boundsRetryCache() {
        AtomicInteger calls = new AtomicInteger();
        AuthorizationServerMetadataCache cache = cache(
                request -> {
                    calls.incrementAndGet();
                    return new TransportResponse(503, Map.of("Retry-After", List.of("60")), "");
                },
                Duration.ofHours(1),
                Duration.ofMinutes(1));
        for (int i = 0; i <= 128; i++) {
            URI issuer = URI.create("https://issuer" + i + ".example.com");
            assertThatThrownBy(() -> cache.get(issuer)).isInstanceOf(HttpStatusException.class);
        }
        assertThatThrownBy(() -> cache.get(URI.create("https://issuer128.example.com")))
                .isInstanceOf(HttpStatusException.class);
        assertThat(calls).hasValue(129);
        assertThatThrownBy(() -> cache.get(URI.create("https://issuer0.example.com")))
                .isInstanceOf(HttpStatusException.class);
        assertThat(calls).hasValue(130);
    }

    private void assertRetryAfter(int status, long delay, String header) {
        AtomicInteger calls = new AtomicInteger();
        AuthorizationServerMetadataCache cache = cache(
                request -> calls.incrementAndGet() == 1
                        ? new TransportResponse(status, Map.of("Retry-After", List.of(header)), "")
                        : ok(METADATA),
                Duration.ofHours(1),
                Duration.ofMinutes(1));
        assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(HttpStatusException.class);
        clock.advance(Duration.ofSeconds(Math.min(60, delay)).minusMillis(1));
        assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(HttpStatusException.class);
        assertThat(calls).hasValue(1);
        clock.advance(Duration.ofMillis(1));
        assertThat(cache.get(ISSUER).issuer()).isEqualTo(ISSUER);
        assertThat(calls).hasValue(2);
    }

    @Test
    @DisplayName("row 4: a successful fetch resets the backoff for the next refresh")
    void successResetsBackoff() {
        AtomicInteger calls = new AtomicInteger();
        AuthorizationServerMetadataCache cache = cache(
                request -> {
                    int call = calls.incrementAndGet();
                    if (call == 1 || call == 2 || call == 4) {
                        throw new NetworkException("refused", new ConnectException("refused"));
                    }
                    return ok(METADATA);
                },
                Duration.ofHours(1),
                Duration.ofMinutes(1));
        assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(NetworkException.class);
        clock.advance(Duration.ofMillis(1200));
        assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(NetworkException.class);
        clock.advance(Duration.ofMillis(2400));
        assertThat(cache.get(ISSUER).issuer()).isEqualTo(ISSUER);
        clock.advance(Duration.ofHours(1));
        assertThatThrownBy(() -> cache.get(ISSUER)).isInstanceOf(NetworkException.class);
        clock.advance(Duration.ofMillis(1200));
        assertThat(cache.get(ISSUER).issuer()).isEqualTo(ISSUER);
        assertThat(calls).hasValue(5);
    }

    @Test
    @DisplayName("row 5: deterministic failures (other 4xx, malformed, issuer mismatch) use negative_ttl only")
    void deterministicFailuresAreCachedForNegativeTtl() {
        for (String body : List.of("<html>", "{\"issuer\":\"https://other.example\"}")) {
            try (StubZone zone = StubZone.start()) {
                zone.respond("GET", StubZone.DISCOVERY_PATH, 200, body);
                assertNegativeCaching(zone, OAuthProtocolException.class);
            }
        }
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 404, "{}");
            assertNegativeCaching(zone, HttpStatusException.class);
        }
    }

    private void assertNegativeCaching(StubZone zone, Class<? extends RuntimeException> type) {
        AuthorizationServerMetadataCache cache = cache(Duration.ofHours(1), Duration.ofMinutes(1));

        RuntimeException first = catchThrown(() -> cache.get(zone.issuer()));
        assertThat(first).isInstanceOf(type);
        clock.advance(Duration.ofSeconds(59));
        assertThat(catchThrown(() -> cache.get(zone.issuer()))).isSameAs(first);
        assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);

        clock.advance(Duration.ofSeconds(1));
        zone.serveDiscovery();
        assertThat(cache.get(zone.issuer()).issuer()).isEqualTo(zone.issuer());
        assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
    }

    @Test
    @DisplayName("negative_ttl 0 records no failure at all")
    void negativeTtlZeroDisablesNegativeCaching() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 404, "{}");
            AuthorizationServerMetadataCache cache = cache(Duration.ofHours(1), Duration.ZERO);

            assertThatThrownBy(() -> cache.get(zone.issuer())).isInstanceOf(HttpStatusException.class);
            assertThatThrownBy(() -> cache.get(zone.issuer())).isInstanceOf(HttpStatusException.class);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("negative_ttl is never longer than discovery_ttl")
    void negativeTtlBoundedByDiscoveryTtl() {
        assertThatThrownBy(() -> cache(Duration.ofMinutes(1), Duration.ofMinutes(2)))
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> AuthorizationServerMetadataCache.builder().discoveryTtl(Duration.ZERO))
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> AuthorizationServerMetadataCache.builder().negativeTtl(Duration.ofSeconds(-1)))
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("concurrent cold-cache callers share one in-flight fetch")
    void concurrentColdCallersShareOneFetch() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        KeycardHttpTransport transport = request -> {
            calls.incrementAndGet();
            entered.countDown();
            awaitUninterruptibly(release);
            return ok(METADATA);
        };
        AuthorizationServerMetadataCache cache = cache(transport, Duration.ofHours(1), Duration.ofMinutes(1));

        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<AuthorizationServerMetadata>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> cache.get(ISSUER)));
            }
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            Thread.sleep(200);
            release.countDown();

            AuthorizationServerMetadata first = results.get(0).get(5, TimeUnit.SECONDS);
            for (Future<AuthorizationServerMetadata> result : results) {
                assertThat(result.get(5, TimeUnit.SECONDS)).isSameAs(first);
            }
            assertThat(calls).hasValue(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("concurrent callers share a failed fetch's error, which is then discarded")
    void sharedFailureIsDeliveredThenDiscarded() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        KeycardHttpTransport transport = request -> {
            if (calls.incrementAndGet() == 1) {
                entered.countDown();
                awaitUninterruptibly(release);
                return new TransportResponse(503, Map.of(), "");
            }
            return ok(METADATA);
        };
        AuthorizationServerMetadataCache cache = cache(transport, Duration.ofHours(1), Duration.ofMinutes(1));

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<AuthorizationServerMetadata> leader = pool.submit(() -> cache.get(ISSUER));
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            Future<AuthorizationServerMetadata> follower = pool.submit(() -> cache.get(ISSUER));
            Thread.sleep(200);
            release.countDown();

            assertThatThrownBy(() -> leader.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(HttpStatusException.class);
            assertThatThrownBy(() -> follower.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(HttpStatusException.class);
            assertThat(calls).hasValue(1);

            clock.advance(Duration.ofMillis(1200));
            assertThat(cache.get(ISSUER).issuer()).isEqualTo(ISSUER);
            assertThat(calls).hasValue(2);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("row 6: one caller's interruption does not poison the shared fetch for the others")
    void fetcherInterruptionDoesNotPoisonWaiters() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        KeycardHttpTransport transport = request -> {
            if (calls.incrementAndGet() == 1) {
                entered.countDown();
                try {
                    new CountDownLatch(1).await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new NetworkException("interrupted", e);
                }
            }
            return ok(METADATA);
        };
        AuthorizationServerMetadataCache cache = cache(transport, Duration.ofHours(1), Duration.ofMinutes(1));

        AtomicReference<Throwable> leaderOutcome = new AtomicReference<>();
        Thread leader = new Thread(() -> {
            try {
                cache.get(ISSUER);
            } catch (RuntimeException e) {
                leaderOutcome.set(e);
            }
        });
        leader.start();
        assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<AuthorizationServerMetadata> waiter = pool.submit(() -> cache.get(ISSUER));
            Thread.sleep(200);
            leader.interrupt();
            leader.join(5000);

            assertThat(leaderOutcome.get())
                    .isInstanceOf(NetworkException.class)
                    .hasCauseInstanceOf(InterruptedException.class);
            assertThat(waiter.get(5, TimeUnit.SECONDS).issuer()).isEqualTo(ISSUER);
            assertThat(calls).hasValue(2);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("invalidate and clear drop the cached outcome")
    void invalidateAndClear() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            AuthorizationServerMetadataCache cache = cache(Duration.ofHours(1), Duration.ofMinutes(1));

            cache.get(zone.issuer());
            cache.invalidate(zone.issuer());
            cache.get(zone.issuer());
            cache.clear();
            cache.get(zone.issuer());

            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(3);
        }
    }

    @Test
    @DisplayName("no global state: each cache instance holds its own entries")
    void cachesAreInstanceScoped() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            cache(Duration.ofHours(1), Duration.ofMinutes(1)).get(zone.issuer());
            cache(Duration.ofHours(1), Duration.ofMinutes(1)).get(zone.issuer());

            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
        }
    }

    private AuthorizationServerMetadataCache cache(Duration discoveryTtl, Duration negativeTtl) {
        return AuthorizationServerMetadataCache.builder()
                .clock(clock)
                .discoveryTtl(discoveryTtl)
                .negativeTtl(negativeTtl)
                .build();
    }

    private AuthorizationServerMetadataCache cache(
            KeycardHttpTransport transport, Duration discoveryTtl, Duration negativeTtl) {
        return AuthorizationServerMetadataCache.builder()
                .discovery(AuthorizationServerDiscovery.builder()
                        .transport(transport)
                        .build())
                .clock(clock)
                .discoveryTtl(discoveryTtl)
                .negativeTtl(negativeTtl)
                .build();
    }

    private static TransportResponse ok(String body) {
        return new TransportResponse(200, Map.of("content-type", List.of("application/json")), body);
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static RuntimeException catchThrown(Runnable call) {
        try {
            call.run();
        } catch (RuntimeException e) {
            return e;
        }
        throw new AssertionError("expected an exception");
    }
}
