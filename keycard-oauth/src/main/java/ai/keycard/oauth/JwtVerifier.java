package ai.keycard.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Verifies a compact JWT access token (jwt-signing-and-verification.md), failing closed.
 *
 * <p>The cheap checks run first, on the unverified token: structure, algorithm, a trusted issuer,
 * the RFC 9068 §2.2 claims ({@code iss}, {@code sub}, {@code aud}, {@code exp}, {@code iat},
 * {@code client_id}), expiry and {@code nbf}, audience, and {@code kid}. Only then is the key
 * resolved and the signature checked, so a token naming an untrusted issuer never causes a key
 * lookup or any network call.
 *
 * <pre>{@code
 * JwtVerifier verifier = JwtVerifier.builder(URI.create("https://acme.keycard.cloud"))
 *         .audiences("https://api.example.com")
 *         .build();
 * Map<String, Object> claims = verifier.verify(bearerToken);
 * }</pre>
 *
 * <p>Every rejection is an {@link InvalidTokenException}, including a {@code kid} the issuer's
 * JWKS doesn't hold. A JWKS that can't be reached or parsed is a {@link JwksException} instead, so
 * a server can answer 503 rather than 401.
 */
public final class JwtVerifier {

    /** The algorithms this verifier implements. */
    public static final Set<String> SUPPORTED_ALGORITHMS = Set.of("RS256", "ES256");

    private final Set<String> issuers;
    private final Set<String> audiences;
    private final Set<String> algorithms;
    private final Duration clockSkew;
    private final VerificationKeyring keyring;
    private final Clock clock;

    private JwtVerifier(Builder builder) {
        this.issuers = Set.copyOf(builder.issuers);
        this.audiences = Set.copyOf(builder.audiences);
        this.algorithms = Set.copyOf(builder.algorithms);
        this.clockSkew = builder.clockSkew;
        this.keyring = builder.keyring != null ? builder.keyring : JwksKeyring.create();
        this.clock = builder.clock;
    }

    /**
     * A builder trusting tokens from these issuers.
     *
     * @param issuers the trusted issuers; a token's {@code iss} must equal one exactly
     * @return a new builder
     * @throws ConfigurationException when no issuer is given
     */
    public static Builder builder(URI... issuers) {
        List<String> values = new ArrayList<>();
        for (URI issuer : issuers) {
            values.add(Objects.requireNonNull(issuer, "issuer").toString());
        }
        return new Builder(values);
    }

    /**
     * Verifies a token.
     *
     * @param token the compact JWT
     * @return the verified claims
     * @throws InvalidTokenException when any check fails
     * @throws JwksException when the issuer's keys can't be fetched (not when the {@code kid} is
     *     simply absent, which is an {@link InvalidTokenException})
     */
    public Map<String, Object> verify(String token) {
        Objects.requireNonNull(token, "token");
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()) {
            throw new InvalidTokenException("token is not a compact JWS");
        }
        Map<String, Object> header = decode(parts[0], "header");
        Map<String, Object> claims = decode(parts[1], "payload");

        Object alg = header.get("alg");
        if (!(alg instanceof String algorithm)
                || algorithm.equalsIgnoreCase("none")
                || !algorithms.contains(algorithm)) {
            throw new InvalidTokenException("algorithm " + alg + " is not allowed");
        }

        Object iss = claims.get("iss");
        if (!(iss instanceof String issuer) || !issuers.contains(issuer)) {
            throw new InvalidTokenException("issuer " + iss + " is not trusted");
        }

        requireString(claims, "sub");
        requireString(claims, "client_id");
        double exp = requireNumber(claims, "exp");
        requireNumber(claims, "iat");
        List<String> tokenAudiences = audiences(claims.get("aud"));

        double now = clock.millis() / 1000.0;
        double skew = clockSkew.toMillis() / 1000.0;
        if (now > exp + skew) {
            throw new InvalidTokenException("token expired");
        }
        Object nbf = claims.get("nbf");
        if (nbf != null) {
            if (!(nbf instanceof Number number) || !Double.isFinite(number.doubleValue())) {
                throw new InvalidTokenException("nbf is not a number");
            }
            if (now < number.doubleValue() - skew) {
                throw new InvalidTokenException("token is not valid yet");
            }
        }

        if (!audiences.isEmpty() && Collections.disjoint(audiences, tokenAudiences)) {
            throw new InvalidTokenException("audience " + tokenAudiences + " is not accepted");
        }

        Object kid = header.get("kid");
        if (!(kid instanceof String keyId) || keyId.isEmpty()) {
            throw new InvalidTokenException("token has no kid");
        }

        PublicKey key;
        try {
            key = keyring.resolve(URI.create(issuer), keyId);
        } catch (JwksException.KeyNotFound e) {
            throw new InvalidTokenException("no key " + keyId + " for issuer " + issuer, e);
        } catch (KeycardException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new JwksException.Fetch(
                    "the keyring failed to resolve key " + keyId + " for issuer " + issuer, e, false);
        }
        if (key == null) {
            throw new InvalidTokenException("no key " + keyId + " for issuer " + issuer);
        }

        try {
            if (!SignedJWT.parse(token).verify(verifierFor(algorithm, key))) {
                throw new InvalidTokenException("signature does not verify");
            }
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("signature does not verify: " + e.getMessage(), e);
        }
        return Collections.unmodifiableMap(claims);
    }

    private static JWSVerifier verifierFor(String algorithm, PublicKey key) throws JOSEException {
        if (algorithm.equals("RS256") && key instanceof RSAPublicKey rsa) {
            return new RSASSAVerifier(rsa);
        }
        if (algorithm.equals("ES256") && key instanceof ECPublicKey ec) {
            return new ECDSAVerifier(ec);
        }
        throw new InvalidTokenException("key type " + key.getAlgorithm() + " does not match algorithm " + algorithm);
    }

    private static Map<String, Object> decode(String part, String what) {
        try {
            return new LinkedHashMap<>(JSONObjectUtils.parse(new Base64URL(part).decodeToString()));
        } catch (ParseException | RuntimeException e) {
            throw new InvalidTokenException("token " + what + " does not decode", e);
        }
    }

    private static void requireString(Map<String, Object> claims, String name) {
        if (!(claims.get(name) instanceof String value) || value.isEmpty()) {
            throw new InvalidTokenException("token has no " + name);
        }
    }

    private static double requireNumber(Map<String, Object> claims, String name) {
        if (!(claims.get(name) instanceof Number number) || !Double.isFinite(number.doubleValue())) {
            throw new InvalidTokenException("token has no numeric " + name);
        }
        return number.doubleValue();
    }

    private static List<String> audiences(@Nullable Object aud) {
        List<String> values = new ArrayList<>();
        if (aud instanceof String single) {
            values.add(single);
        } else if (aud instanceof Collection<?> many) {
            for (Object value : many) {
                if (!(value instanceof String string)) {
                    throw new InvalidTokenException("token aud holds a value that is not a string");
                }
                values.add(string);
            }
        }
        values.removeIf(String::isEmpty);
        if (values.isEmpty()) {
            throw new InvalidTokenException("token has no aud");
        }
        return values;
    }

    /** Configures a {@link JwtVerifier}. */
    public static final class Builder {

        private final Set<String> issuers;
        private Set<String> audiences = Set.of();
        private Set<String> algorithms = Set.of("RS256");
        private Duration clockSkew = Duration.ZERO;
        private @Nullable VerificationKeyring keyring;
        private Clock clock = Clock.systemUTC();

        private Builder(List<String> issuers) {
            if (issuers.isEmpty()) {
                throw new ConfigurationException("a verifier needs at least one trusted issuer");
            }
            this.issuers = new LinkedHashSet<>(issuers);
        }

        /**
         * Accepted audiences; a token's {@code aud} must contain at least one. Unset, the audience
         * is not checked.
         *
         * @param audiences the accepted audiences
         * @return this builder
         */
        public Builder audiences(String... audiences) {
            this.audiences = Set.copyOf(new LinkedHashSet<>(List.of(audiences)));
            return this;
        }

        /**
         * Allowed {@code alg} values. Defaults to {@code RS256}; {@code none} is always rejected.
         *
         * @param algorithms values from {@link #SUPPORTED_ALGORITHMS}
         * @return this builder
         * @throws ConfigurationException for an algorithm this verifier doesn't implement
         */
        public Builder algorithms(String... algorithms) {
            Set<String> values = Set.copyOf(new LinkedHashSet<>(List.of(algorithms)));
            if (values.isEmpty()) {
                throw new ConfigurationException("at least one algorithm is required");
            }
            for (String value : values) {
                if (!SUPPORTED_ALGORITHMS.contains(value)) {
                    throw new ConfigurationException(
                            "algorithm " + value + " is not supported; use one of " + SUPPORTED_ALGORITHMS);
                }
            }
            this.algorithms = values;
            return this;
        }

        /**
         * Leeway on {@code exp} and {@code nbf}. Defaults to zero: comparisons are exact.
         *
         * @param clockSkew a duration of zero or more
         * @return this builder
         */
        public Builder clockSkew(Duration clockSkew) {
            if (clockSkew.isNegative()) {
                throw new ConfigurationException("clockSkew must not be negative");
            }
            this.clockSkew = clockSkew;
            return this;
        }

        /**
         * Where verification keys come from. Defaults to a new {@link JwksKeyring}.
         *
         * @param keyring the keyring
         * @return this builder
         */
        public Builder keyring(VerificationKeyring keyring) {
            this.keyring = Objects.requireNonNull(keyring, "keyring");
            return this;
        }

        /**
         * The clock for {@code exp} and {@code nbf}. Defaults to the system UTC clock.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Builds the verifier.
         *
         * @return the verifier
         */
        public JwtVerifier build() {
            return new JwtVerifier(this);
        }
    }
}
