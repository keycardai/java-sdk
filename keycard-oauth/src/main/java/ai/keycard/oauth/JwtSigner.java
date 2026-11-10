package ai.keycard.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Signs claims into a compact JWS (jwt-signing-and-verification.md). The header is {@code {alg,
 * kid}}, with {@code alg} from the key type: RS256 for RSA, ES256 for EC P-256. Claims, including
 * {@code exp}, {@code iat} and {@code nbf}, are signed exactly as given; the signer never invents
 * an expiry. When the claims omit {@code iss} and the key carries an issuer, that issuer is added.
 */
public final class JwtSigner {

    private final SigningKey key;
    private final JWSAlgorithm algorithm;
    private final JWSSigner signer;

    private JwtSigner(SigningKey key) {
        this.key = key;
        if (key.privateKey() instanceof RSAPrivateKey rsa) {
            this.algorithm = JWSAlgorithm.RS256;
            this.signer = new RSASSASigner(rsa);
        } else if (key.privateKey() instanceof ECPrivateKey ec) {
            this.algorithm = JWSAlgorithm.ES256;
            try {
                this.signer = new ECDSASigner(ec);
            } catch (JOSEException e) {
                throw new ConfigurationException("unsupported EC key: " + e.getMessage(), e);
            }
        } else {
            throw new ConfigurationException("signing keys must be RSA or EC P-256, got "
                    + key.privateKey().getAlgorithm());
        }
    }

    /**
     * A signer for one key.
     *
     * @param key the signing key, its id and an optional default issuer
     * @return the signer
     * @throws ConfigurationException when the key is neither RSA nor EC P-256
     */
    public static JwtSigner of(SigningKey key) {
        return new JwtSigner(Objects.requireNonNull(key, "key"));
    }

    /**
     * The algorithm this signer writes into the header.
     *
     * @return {@code RS256} or {@code ES256}
     */
    public String algorithm() {
        return algorithm.getName();
    }

    /**
     * Signs the claims.
     *
     * @param claims the payload, serialized as given
     * @return the compact JWS, {@code header.payload.signature}
     */
    public String sign(Map<String, Object> claims) {
        Map<String, Object> payload = new LinkedHashMap<>(claims);
        if (!payload.containsKey("iss") && key.issuer() != null) {
            payload.put("iss", key.issuer().toString());
        }
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(algorithm).keyID(key.keyId()).build(), new Payload(payload));
        try {
            jws.sign(signer);
        } catch (JOSEException e) {
            throw new KeycardException("signing failed: " + e.getMessage(), e);
        }
        return jws.serialize();
    }
}
