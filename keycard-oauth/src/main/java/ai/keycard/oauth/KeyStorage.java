package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * Where a {@link WebIdentity} keeps its private key, as PEM text keyed by key id. The default is
 * {@link FileKeyStorage}; implement this for a secret manager or a key/value store.
 */
public interface KeyStorage {

    /**
     * Loads a key.
     *
     * @param keyId the key id
     * @return the PEM text, or {@code null} when no key is stored under the id
     * @throws ConfigurationException when the storage can't be read
     */
    @Nullable
    String load(String keyId);

    /**
     * Stores a newly generated key.
     *
     * @param keyId the key id
     * @param pem the PKCS#8 PEM text of the private key
     * @throws ConfigurationException when the storage can't be written
     */
    void store(String keyId, String pem);
}
