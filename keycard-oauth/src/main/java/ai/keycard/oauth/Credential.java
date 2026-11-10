package ai.keycard.oauth;

/**
 * How a client authenticates to a Keycard zone: {@link ClientSecret}, {@code WebIdentity} or
 * {@code WorkloadIdentity}.
 *
 * <p>Every credential prepares token-exchange requests. Credentials that can also authenticate
 * the client on other requests (client credentials, refresh, the device grant) implement {@link
 * ClientAuthenticator} as well.
 */
@FunctionalInterface
public interface Credential {

    /**
     * Builds the token-exchange request for a subject token, carrying whatever body-level client
     * authentication this credential uses (an assertion, a {@code client_id}). A credential that
     * authenticates with a header, such as {@link ClientSecret}, leaves the body free of client
     * credentials and supplies the header through {@link ClientAuthenticator}.
     *
     * @param context the subject token, target resource and zone
     * @return the request to send
     */
    TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context);
}
