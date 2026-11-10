package ai.keycard.oauth;

import java.net.URI;
import java.security.PrivateKey;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The signer's input: a private key, its key id, and an optional default issuer.
 *
 * @param privateKey an RSA key (signs RS256) or an EC P-256 key (signs ES256)
 * @param keyId written to the JWT header as {@code kid}
 * @param issuer applied as {@code iss} when the claims omit it, or {@code null}
 */
public record SigningKey(
        PrivateKey privateKey, String keyId, @Nullable URI issuer) {

    /**
     * Validates the key id.
     *
     * @param privateKey the signing key
     * @param keyId the key id, non-empty
     * @param issuer the default issuer, or {@code null}
     */
    public SigningKey {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(keyId, "keyId");
        if (keyId.isEmpty()) {
            throw new ConfigurationException("keyId must not be empty");
        }
    }

    /**
     * Never prints the private key.
     *
     * @return the key id, algorithm and issuer
     */
    @Override
    public String toString() {
        return "SigningKey[keyId=" + keyId + ", algorithm=" + privateKey.getAlgorithm() + ", issuer=" + issuer + "]";
    }
}
