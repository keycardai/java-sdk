package ai.keycard.oauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * A credential that authenticates with {@code private_key_jwt} client assertions (RFC 7523) signed
 * by a key it manages itself (web-identity.md, spec-version 2). On first use it generates an
 * RSA-2048 key and stores it; later uses load it. The private key never leaves the workload: the
 * zone verifies assertions against the public key set from {@link #publicJwks()}, which the
 * application publishes, typically at {@link #clientJwksUrl(URI)}.
 *
 * <pre>{@code
 * WebIdentity identity = WebIdentity.builder()
 *         .clientId("my-client")
 *         .serverName("Payments API")      // key id "payments-api"
 *         .storageDir(Path.of("/var/lib/payments/keys"))
 *         .build();
 * }</pre>
 *
 * <p>Each assertion has {@code iss} and {@code sub} set to the client id, {@code aud} set to the
 * URL the request goes to, a new {@code jti}, and a 300-second lifetime. Safe to share between
 * threads.
 */
public final class WebIdentity implements Credential, ClientAuthenticator {

    /** The {@code client_assertion_type} of a JWT client assertion. */
    public static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** How long an assertion is valid. */
    public static final Duration ASSERTION_LIFETIME = Duration.ofSeconds(300);

    private final String keyId;
    private final KeyStorage storage;
    private final @Nullable String clientId;
    private final Clock clock;
    private @Nullable RSAKey key;

    private WebIdentity(Builder builder) {
        this.keyId = builder.keyId != null
                ? builder.keyId
                : builder.serverName != null && !sanitize(builder.serverName).isEmpty()
                        ? sanitize(builder.serverName)
                        : UUID.randomUUID().toString();
        this.storage = builder.storage != null ? builder.storage : FileKeyStorage.of(builder.storageDir);
        this.clientId = builder.clientId;
        this.clock = builder.clock;
    }

    /**
     * A builder; every option is optional, but client authentication needs a client id.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The key id, the {@code kid} of every assertion and of the published key.
     *
     * @return the key id
     */
    public String keyId() {
        return keyId;
    }

    /**
     * The client id signed as {@code iss} and {@code sub}.
     *
     * @return the client id, or {@code null} when none was configured
     */
    public @Nullable String clientId() {
        return clientId;
    }

    /**
     * A token-exchange request authenticated by an assertion audienced to the token endpoint.
     *
     * @param context the subject token, resource, zone and token endpoint
     * @return the request, carrying {@code client_assertion} and no Basic credentials
     * @throws ConfigurationException when there is neither a resource client id nor a client id, or
     *     the token endpoint isn't known
     */
    @Override
    public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
        String subject = context.resourceClientId() != null ? context.resourceClientId() : clientId;
        if (subject == null || subject.isEmpty()) {
            throw new ConfigurationException(
                    "WebIdentity needs a client id: set clientId(...) or exchange with a resource client id");
        }
        if (context.tokenEndpoint() == null) {
            throw new ConfigurationException("WebIdentity needs the token endpoint as the assertion audience");
        }
        return TokenExchangeRequest.builder(context.subjectToken())
                .subjectTokenType(TokenTypes.ACCESS_TOKEN)
                .resource(context.resource())
                .clientAssertion(sign(subject, context.tokenEndpoint()), ASSERTION_TYPE)
                .build();
    }

    /**
     * A newly signed assertion for the endpoint the request goes to, as form fields.
     *
     * @param issuer the zone's issuer; unused, since the client id names the client
     * @param endpoint the URL the request goes to, signed as {@code aud}
     * @return {@code client_assertion} and {@code client_assertion_type}, and no headers
     * @throws ConfigurationException when no client id was configured
     */
    @Override
    public ClientAuthentication authenticate(URI issuer, URI endpoint) {
        if (clientId == null || clientId.isEmpty()) {
            throw new ConfigurationException("WebIdentity client authentication needs clientId(...)");
        }
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("client_assertion", sign(clientId, endpoint));
        fields.put("client_assertion_type", ASSERTION_TYPE);
        return ClientAuthentication.formFields(fields);
    }

    /**
     * The public key, for the zone to verify assertions against.
     *
     * @return a key set holding the RS256 signing key's public half
     * @throws ConfigurationException when the key can't be loaded or created
     */
    public JWKSet publicJwks() {
        return new JWKSet(key().toPublicJWK());
    }

    /**
     * Where an application conventionally publishes {@link #publicJwks()}.
     *
     * @param baseUrl the application's base URL
     * @return {@code <base>/.well-known/jwks.json}
     */
    public static URI clientJwksUrl(URI baseUrl) {
        String base = baseUrl.toString();
        return URI.create(
                (base.endsWith("/") ? base.substring(0, base.length() - 1) : base) + "/.well-known/jwks.json");
    }

    private String sign(String subject, URI audience) {
        long now = clock.instant().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", subject);
        claims.put("sub", subject);
        claims.put("aud", audience.toString());
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", now);
        claims.put("exp", now + ASSERTION_LIFETIME.toSeconds());
        try {
            return JwtSigner.of(new SigningKey(key().toRSAPrivateKey(), keyId, null))
                    .sign(claims);
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new ConfigurationException("the stored key for " + keyId + " is not a usable RSA key", e);
        }
    }

    private synchronized RSAKey key() {
        if (key == null) {
            String pem = storage.load(keyId);
            key = pem != null ? parse(pem) : generate();
        }
        return key;
    }

    private RSAKey generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            RSAPrivateCrtKey privateKey =
                    (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();
            storage.store(keyId, pem("PRIVATE KEY", privateKey.getEncoded()));
            return toJwk(privateKey);
        } catch (GeneralSecurityException e) {
            throw new ConfigurationException("cannot generate an RSA key", e);
        }
    }

    /** Reads PKCS#8 ({@code PRIVATE KEY}, Python) or PKCS#1 ({@code RSA PRIVATE KEY}, Ruby) PEM. */
    private RSAKey parse(String pem) {
        boolean pkcs1 = pem.contains("BEGIN RSA PRIVATE KEY");
        String body = pem.replaceAll("-----(BEGIN|END) [A-Z ]+-----", "").replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(body);
            byte[] pkcs8 = pkcs1 ? wrapPkcs1(der) : der;
            RSAPrivateCrtKey privateKey =
                    (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            return toJwk(privateKey);
        } catch (GeneralSecurityException | IllegalArgumentException | ClassCastException e) {
            throw new ConfigurationException("the stored key for " + keyId + " is not an RSA private key", e);
        }
    }

    private RSAKey toJwk(RSAPrivateCrtKey privateKey) throws GeneralSecurityException {
        java.security.interfaces.RSAPublicKey publicKey =
                (java.security.interfaces.RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }

    /** PKCS#8 PrivateKeyInfo around a PKCS#1 RSAPrivateKey: version 0, rsaEncryption, the key. */
    private static byte[] wrapPkcs1(byte[] pkcs1) {
        byte[] algorithm = {
            0x30,
            0x0d,
            0x06,
            0x09,
            0x2a,
            (byte) 0x86,
            0x48,
            (byte) 0x86,
            (byte) 0xf7,
            0x0d,
            0x01,
            0x01,
            0x01,
            0x05,
            0x00
        };
        byte[] version = {0x02, 0x01, 0x00};
        byte[] octets = der(0x04, pkcs1);
        byte[] content = new byte[version.length + algorithm.length + octets.length];
        System.arraycopy(version, 0, content, 0, version.length);
        System.arraycopy(algorithm, 0, content, version.length, algorithm.length);
        System.arraycopy(octets, 0, content, version.length + algorithm.length, octets.length);
        return der(0x30, content);
    }

    private static byte[] der(int tag, byte[] content) {
        byte[] length = BigInteger.valueOf(content.length).toByteArray();
        byte[] header;
        if (content.length < 0x80) {
            header = new byte[] {(byte) tag, (byte) content.length};
        } else {
            int start = length[0] == 0 ? 1 : 0;
            int size = length.length - start;
            header = new byte[2 + size];
            header[0] = (byte) tag;
            header[1] = (byte) (0x80 | size);
            System.arraycopy(length, start, header, 2, size);
        }
        byte[] out = new byte[header.length + content.length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(content, 0, out, header.length, content.length);
        return out;
    }

    private static String pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    /** Lowercase letters and digits, runs of anything else collapsed to one hyphen, no edge hyphens. */
    static String sanitize(String serverName) {
        return serverName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("^-+|-+$", "");
    }

    /**
     * Names the key and client, never key material.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "WebIdentity[keyId=" + keyId + ", clientId=" + clientId + ", storage=" + storage + "]";
    }

    /** Configures a {@link WebIdentity}. */
    public static final class Builder {

        private @Nullable String serverName;
        private @Nullable String keyId;
        private @Nullable KeyStorage storage;
        private java.nio.file.Path storageDir = FileKeyStorage.DEFAULT_DIR;
        private @Nullable String clientId;
        private Clock clock = Clock.systemUTC();

        private Builder() {}

        /**
         * A human-readable name; sanitized into the key id when no key id is given.
         *
         * @param serverName the name
         * @return this builder
         */
        public Builder serverName(String serverName) {
            this.serverName = Objects.requireNonNull(serverName, "serverName");
            return this;
        }

        /**
         * An explicit key id, which wins over the server name.
         *
         * @param keyId the key id
         * @return this builder
         */
        public Builder keyId(String keyId) {
            Objects.requireNonNull(keyId, "keyId");
            if (keyId.isEmpty()) {
                throw new ConfigurationException("keyId must not be empty");
            }
            this.keyId = keyId;
            return this;
        }

        /**
         * Where the key is kept; defaults to {@link FileKeyStorage} over {@link #storageDir(java.nio.file.Path)}.
         *
         * @param storage the storage
         * @return this builder
         */
        public Builder storage(KeyStorage storage) {
            this.storage = Objects.requireNonNull(storage, "storage");
            return this;
        }

        /**
         * The directory for the default file storage.
         *
         * @param storageDir the directory; defaults to {@link FileKeyStorage#DEFAULT_DIR}
         * @return this builder
         */
        public Builder storageDir(java.nio.file.Path storageDir) {
            this.storageDir = Objects.requireNonNull(storageDir, "storageDir");
            return this;
        }

        /**
         * The registered client id, signed as {@code iss} and {@code sub}. Required for client
         * authentication; a token exchange may instead carry a resource client id.
         *
         * @param clientId the client id
         * @return this builder
         */
        public Builder clientId(String clientId) {
            Objects.requireNonNull(clientId, "clientId");
            if (clientId.isEmpty()) {
                throw new ConfigurationException("clientId must not be empty");
            }
            this.clientId = clientId;
            return this;
        }

        /**
         * The clock for {@code iat} and {@code exp}.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Builds the credential. The key is loaded or generated on first use, not here.
         *
         * @return the credential
         */
        public WebIdentity build() {
            return new WebIdentity(this);
        }
    }
}
