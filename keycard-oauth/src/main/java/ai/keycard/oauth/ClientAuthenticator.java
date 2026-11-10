package ai.keycard.oauth;

import java.net.URI;

/**
 * The client-authentication capability of a {@link Credential} (base.md credential operations,
 * spec-version 5).
 *
 * <p>It is a separate interface rather than a member of {@link Credential} so a credential
 * implemented outside the SDK keeps compiling without it. {@link ClientSecret}, {@code
 * WebIdentity} and {@code WorkloadIdentity} implement it. An operation that needs client
 * authentication rejects a credential without it with a {@link ConfigurationException} before
 * sending anything.
 */
@FunctionalInterface
public interface ClientAuthenticator {

    /**
     * The headers and form fields that authenticate the client on one request.
     *
     * @param issuer the zone's issuer, which picks the zone for a multi-zone credential
     * @param endpoint the URL the request goes to, the audience of an assertion
     * @return what to merge into the request
     * @throws ConfigurationException when the credential has nothing for this zone
     */
    ClientAuthentication authenticate(URI issuer, URI endpoint);
}
