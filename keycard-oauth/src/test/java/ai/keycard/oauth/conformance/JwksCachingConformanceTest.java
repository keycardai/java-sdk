package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.JwksException;
import ai.keycard.oauth.JwksKeyring;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.TransportResponse;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.TestClock;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.net.ConnectException;
import java.net.URI;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** jwks-caching.md (spec-version 4), Unit Tests table. */
class JwksCachingConformanceTest {

    private static RSAKey k1;
    private static RSAKey k2;
    private static RSAKey k9;

    private final TestClock clock = TestClock.start();

    @BeforeAll
    static void keys() throws Exception {
        k1 = new RSAKeyGenerator(2048).keyID("k1").generate();
        k2 = new RSAKeyGenerator(2048).keyID("k2").generate();
        k9 = new RSAKeyGenerator(2048).keyID("k9").generate();
    }

    @Test
    @DisplayName("row 1: a cold lookup discovers jwks_uri, fetches the JWKS and returns the matching key")
    void row1() throws Exception {
        try (StubZone zone = zone(k1, k2)) {
            PublicKey key = keyring(zone).resolve(zone.issuer(), "k1");

            assertThat(key).isEqualTo(k1.toRSAPublicKey());
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);
            assertThat(zone.requests(StubZone.JWKS_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 2: a second lookup within key_ttl is served from cache")
    void row2() {
        try (StubZone zone = zone(k1)) {
            JwksKeyring keyring = keyring(zone);
            keyring.resolve(zone.issuer(), "k1");
            clock.advance(Duration.ofMinutes(4));
            keyring.resolve(zone.issuer(), "k1");

            assertThat(zone.requests()).hasSize(2);
        }
    }

    @Test
    @DisplayName("row 3: a lookup after key_ttl fetches the JWKS again")
    void row3() {
        try (StubZone zone = zone(k1)) {
            JwksKeyring keyring = keyring(zone);
            keyring.resolve(zone.issuer(), "k1");
            clock.advance(Duration.ofMinutes(5));
            keyring.resolve(zone.issuer(), "k1");

            assertThat(zone.requests(StubZone.JWKS_PATH)).hasSize(2);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("rows 4 and 15: another kid in the cached set reuses jwks_uri and needs no network")
    void rows4And15() throws Exception {
        try (StubZone zone = zone(k1, k2)) {
            JwksKeyring keyring = keyring(zone);
            keyring.resolve(zone.issuer(), "k1");

            assertThat(keyring.resolve(zone.issuer(), "k2")).isEqualTo(k2.toRSAPublicKey());
            assertThat(zone.requests()).hasSize(2);
        }
    }

    @Test
    @DisplayName("row 5: a kid absent from the fetched JWKS is a key-not-found error")
    void row5() {
        try (StubZone zone = zone(k1)) {
            assertThatThrownBy(() -> keyring(zone).resolve(zone.issuer(), "k7"))
                    .isInstanceOfSatisfying(
                            JwksException.KeyNotFound.class,
                            e -> assertThat(e.retryable()).isFalse());
        }
    }

    @Test
    @DisplayName("row 6: discovery without jwks_uri is a discovery error")
    void row6() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 200, "{\"issuer\":\"" + zone.issuer() + "\"}");

            assertThatThrownBy(() -> keyring(zone).resolve(zone.issuer(), "k1"))
                    .isInstanceOf(JwksException.Discovery.class);
        }
    }

    @Test
    @DisplayName("row 7: a non-2xx JWKS response is a fetch error")
    void row7() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("GET", StubZone.JWKS_PATH, 503, "{}");
            assertThatThrownBy(() -> keyring(zone).resolve(zone.issuer(), "k1"))
                    .isInstanceOfSatisfying(
                            JwksException.Fetch.class,
                            e -> assertThat(e.retryable()).isTrue());

            zone.respond("GET", StubZone.JWKS_PATH, 404, "{}");
            assertThatThrownBy(() -> keyring(zone).resolve(zone.issuer(), "k1"))
                    .isInstanceOfSatisfying(
                            JwksException.Fetch.class,
                            e -> assertThat(e.retryable()).isFalse());

            zone.respond("GET", StubZone.JWKS_PATH, 200, "not a key set");
            assertThatThrownBy(() -> keyring(zone).resolve(zone.issuer(), "k1"))
                    .isInstanceOf(JwksException.Fetch.class);
        }
    }

    @Test
    @DisplayName("row 8: a cross-origin jwks_uri is rejected before any key fetch")
    void row8() {
        try (StubZone zone = StubZone.start()) {
            zone.respond(
                    "GET",
                    StubZone.DISCOVERY_PATH,
                    200,
                    "{\"issuer\":\"" + zone.issuer() + "\",\"jwks_uri\":\"https://evil.example/jwks.json\"}");

            assertThatThrownBy(() -> keyring(zone).resolve(zone.issuer(), "k1"))
                    .isInstanceOf(JwksException.UriValidation.class);
            assertThat(zone.requests()).hasSize(1);
        }
    }

    @Test
    @DisplayName("rows 9 and 17: concurrent cold lookups, same or different kids, share one JWKS fetch")
    void rows9And17() throws Exception {
        FakeZone fake = new FakeZone(k1, k2);
        CountDownLatch release = new CountDownLatch(1);
        fake.jwksGate = release;
        JwksKeyring keyring = fake.keyring(clock);

        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<PublicKey>> lookups = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                String kid = i % 2 == 0 ? "k1" : "k2";
                lookups.add(pool.submit(() -> keyring.resolve(FakeZone.ISSUER, kid)));
            }
            Thread.sleep(200);
            release.countDown();
            for (Future<PublicKey> lookup : lookups) {
                assertThat(lookup.get(5, TimeUnit.SECONDS)).isNotNull();
            }
            assertThat(fake.jwksFetches).hasValue(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("row 10: a JWKS network failure caches nothing; the next lookup fetches and succeeds")
    void row10() {
        FakeZone fake = new FakeZone(k1);
        fake.failJwksTimes.set(1);
        JwksKeyring keyring = fake.keyring(clock);

        assertThatThrownBy(() -> keyring.resolve(FakeZone.ISSUER, "k1"))
                .isInstanceOfSatisfying(
                        JwksException.Fetch.class,
                        e -> assertThat(e.retryable()).isTrue());
        assertThat(keyring.resolve(FakeZone.ISSUER, "k1")).isNotNull();
        assertThat(fake.jwksFetches).hasValue(2);
    }

    @Test
    @DisplayName("row 11: a transient discovery failure caches nothing; the next lookup discovers again")
    void row11() {
        FakeZone fake = new FakeZone(k1);
        fake.failDiscoveryTimes.set(1);
        JwksKeyring keyring = fake.keyring(clock);

        assertThatThrownBy(() -> keyring.resolve(FakeZone.ISSUER, "k1"))
                .isInstanceOfSatisfying(
                        JwksException.Discovery.class,
                        e -> assertThat(e.retryable()).isTrue());
        assertThat(keyring.resolve(FakeZone.ISSUER, "k1")).isNotNull();
        assertThat(fake.discoveries).hasValue(2);
    }

    @Test
    @DisplayName("row 12: a lookup cancelled mid-fetch doesn't stop a second lookup from succeeding")
    void row12() throws Exception {
        FakeZone fake = new FakeZone(k1);
        fake.blockFirstJwks = true;
        JwksKeyring keyring = fake.keyring(clock);

        AtomicReference<Throwable> cancelled = new AtomicReference<>();
        Thread first = new Thread(() -> {
            try {
                keyring.resolve(FakeZone.ISSUER, "k1");
            } catch (RuntimeException e) {
                cancelled.set(e);
            }
        });
        first.start();
        assertThat(fake.firstJwksEntered.await(5, TimeUnit.SECONDS)).isTrue();

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<PublicKey> second = pool.submit(() -> keyring.resolve(FakeZone.ISSUER, "k1"));
            Thread.sleep(200);
            first.interrupt();
            first.join(5000);

            assertThat(cancelled.get())
                    .isInstanceOf(JwksException.Fetch.class)
                    .cause()
                    .isInstanceOf(NetworkException.class);
            assertThat(second.get(5, TimeUnit.SECONDS)).isNotNull();
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("rows 13 and 14: unknown kids within the cooldown cost no fetch beyond the one that filled the set")
    void rows13And14() {
        try (StubZone zone = zone(k1)) {
            JwksKeyring keyring = keyring(zone);
            keyring.resolve(zone.issuer(), "k1");

            for (int i = 0; i < 20; i++) {
                String forged = "forged-" + i;
                assertThatThrownBy(() -> keyring.resolve(zone.issuer(), forged))
                        .isInstanceOf(JwksException.KeyNotFound.class);
                clock.advance(Duration.ofSeconds(1));
            }
            assertThat(zone.requests(StubZone.JWKS_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 16: a kid that rotates in is found after the cooldown with one more fetch")
    void row16() throws Exception {
        try (StubZone zone = zone(k1)) {
            JwksKeyring keyring = keyring(zone);
            keyring.resolve(zone.issuer(), "k1");
            serveJwks(zone, k1, k9);

            assertThatThrownBy(() -> keyring.resolve(zone.issuer(), "k9"))
                    .isInstanceOf(JwksException.KeyNotFound.class);
            clock.advance(Duration.ofSeconds(30));
            assertThat(keyring.resolve(zone.issuer(), "k9")).isEqualTo(k9.toRSAPublicKey());
            assertThat(zone.requests(StubZone.JWKS_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("row 18: after invalidate or clear, a lookup the old set lacked fetches regardless of the cooldown")
    void row18() {
        try (StubZone zone = zone(k1)) {
            JwksKeyring keyring = keyring(zone);
            keyring.resolve(zone.issuer(), "k1");
            serveJwks(zone, k1, k9);

            keyring.invalidate(zone.issuer());
            assertThat(keyring.resolve(zone.issuer(), "k9")).isNotNull();
            assertThat(zone.requests(StubZone.JWKS_PATH)).hasSize(2);

            serveJwks(zone, k1, k9, k2);
            keyring.clear();
            assertThat(keyring.resolve(zone.issuer(), "k2")).isNotNull();
            assertThat(zone.requests(StubZone.JWKS_PATH)).hasSize(3);
        }
    }

    @Test
    @DisplayName("row 19: a cooldown of 0 fetches on every unknown-kid lookup")
    void row19() {
        try (StubZone zone = zone(k1)) {
            JwksKeyring keyring = JwksKeyring.builder()
                    .clock(clock)
                    .jwksRefetchCooldown(Duration.ZERO)
                    .build();
            keyring.resolve(zone.issuer(), "k1");
            for (int i = 0; i < 3; i++) {
                assertThatThrownBy(() -> keyring.resolve(zone.issuer(), "unknown"))
                        .isInstanceOf(JwksException.KeyNotFound.class);
            }

            assertThat(zone.requests(StubZone.JWKS_PATH)).hasSize(4);
        }
    }

    @Test
    @DisplayName("defaults: key_ttl 5 minutes, cooldown 30 seconds, at most 256 keys")
    void defaults() {
        assertThat(JwksKeyring.DEFAULT_KEY_TTL).isEqualTo(Duration.ofMinutes(5));
        assertThat(JwksKeyring.DEFAULT_JWKS_REFETCH_COOLDOWN).isEqualTo(Duration.ofSeconds(30));
        assertThat(JwksKeyring.MAX_KEYS).isEqualTo(256);
    }

    private JwksKeyring keyring(StubZone zone) {
        return JwksKeyring.builder().clock(clock).build();
    }

    private static StubZone zone(RSAKey... keys) {
        StubZone zone = StubZone.start().serveDiscovery();
        serveJwks(zone, keys);
        return zone;
    }

    private static void serveJwks(StubZone zone, RSAKey... keys) {
        zone.respond("GET", StubZone.JWKS_PATH, 200, jwks(keys));
    }

    static String jwks(RSAKey... keys) {
        List<com.nimbusds.jose.jwk.JWK> publics = new ArrayList<>();
        for (RSAKey key : keys) {
            publics.add(key.toPublicJWK());
        }
        return new JWKSet(publics).toString();
    }

    /** A scripted zone behind a transport, for failure and concurrency rows. */
    private static final class FakeZone {

        static final URI ISSUER = URI.create("https://acme.keycard.cloud");

        final String jwks;
        final AtomicInteger discoveries = new AtomicInteger();
        final AtomicInteger jwksFetches = new AtomicInteger();
        final AtomicInteger failDiscoveryTimes = new AtomicInteger();
        final AtomicInteger failJwksTimes = new AtomicInteger();
        final CountDownLatch firstJwksEntered = new CountDownLatch(1);
        final List<String> log = new CopyOnWriteArrayList<>();
        volatile CountDownLatch jwksGate;
        volatile boolean blockFirstJwks;

        FakeZone(RSAKey... keys) {
            this.jwks = jwks(keys);
        }

        JwksKeyring keyring(TestClock clock) {
            KeycardHttpTransport transport = request -> {
                String path = request.uri().getPath();
                log.add(path);
                if (path.startsWith("/.well-known")) {
                    discoveries.incrementAndGet();
                    if (failDiscoveryTimes.getAndDecrement() > 0) {
                        throw new NetworkException("refused", new ConnectException("refused"));
                    }
                    return json("{\"issuer\":\"" + ISSUER + "\",\"jwks_uri\":\"" + ISSUER + "/jwks.json\"}");
                }
                int n = jwksFetches.incrementAndGet();
                if (failJwksTimes.getAndDecrement() > 0) {
                    throw new NetworkException("refused", new ConnectException("refused"));
                }
                if (blockFirstJwks && n == 1) {
                    firstJwksEntered.countDown();
                    try {
                        new CountDownLatch(1).await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new NetworkException("interrupted", e);
                    }
                }
                CountDownLatch gate = jwksGate;
                if (gate != null) {
                    try {
                        gate.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new NetworkException("interrupted", e);
                    }
                }
                return json(jwks);
            };
            return JwksKeyring.builder().transport(transport).clock(clock).build();
        }

        private static TransportResponse json(String body) {
            return new TransportResponse(200, Map.of("content-type", List.of("application/json")), body);
        }
    }
}
