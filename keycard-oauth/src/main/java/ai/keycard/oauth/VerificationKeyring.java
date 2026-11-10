package ai.keycard.oauth;

import java.net.URI;
import java.security.PublicKey;

/**
 * Resolves the public key that verifies a token from {@code issuer} signed with {@code kid}.
 * {@link JwksKeyring} resolves from the issuer's published JWKS; a test or an offline deployment
 * can supply keys directly with a lambda.
 */
@FunctionalInterface
public interface VerificationKeyring {

    /**
     * The verification key for a token.
     *
     * @param issuer the token's (already trusted) issuer
     * @param kid the token header's key id
     * @return the public key
     * @throws JwksException when the key can't be resolved
     */
    PublicKey resolve(URI issuer, String kid);
}
