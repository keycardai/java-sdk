package ai.keycard.oauth;

/** The URNs OAuth token requests carry: grant types, token types and assertion types. */
public final class TokenTypes {

    /** RFC 8693 token exchange grant type. */
    public static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

    /** RFC 8693 access token type, the default {@code subject_token_type}. */
    public static final String ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";

    /** RFC 8693 JWT token type, for actor tokens such as a JWT-SVID. */
    public static final String JWT = "urn:ietf:params:oauth:token-type:jwt";

    /** RFC 7523 JWT bearer client assertion type. */
    public static final String JWT_BEARER_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** Keycard's substitute-user subject token type, for impersonation. */
    public static final String SUBSTITUTE_USER = "urn:keycard:params:oauth:token-type:substitute-user";

    /** The {@code client_credentials} grant type (RFC 6749 §4.4). */
    public static final String CLIENT_CREDENTIALS_GRANT = "client_credentials";

    private TokenTypes() {}
}
