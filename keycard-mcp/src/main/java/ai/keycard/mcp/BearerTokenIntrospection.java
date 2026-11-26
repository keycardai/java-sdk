package ai.keycard.mcp;

import ai.keycard.oauth.ClientAuthenticator;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.OAuthErrorCodes;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.TokenIntrospectionClient;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/** The per-request introspection check shared by the servlet filter and Spring starter. */
public final class BearerTokenIntrospection {

    private static final System.Logger LOG = System.getLogger(BearerTokenIntrospection.class.getName());
    private static final Pattern SAFE_RESPONSE_DETAIL = Pattern.compile(
            "is not a JSON object|has no boolean active|has an aud that is not a string or list of strings"
                    + "|has a (token_type|iss|sub|client_id|scope|sid|jti) that is not a string"
                    + "|has an? (iat|exp|nbf) that is not an integer|has an out-of-range (iat|exp|nbf)");
    private static final Pattern SAFE_METADATA_DETAIL = Pattern.compile("is not a JSON object|has no issuer"
            + "|has an invalid (issuer|jwks_uri|(token|authorization|registration|userinfo|end_session"
            + "|device_authorization|revocation|introspection)_endpoint)"
            + "|has a (grant_types_supported|response_types_supported"
            + "|(token|revocation|introspection)_endpoint_auth_methods_supported)"
            + " that is not a list of strings");

    /** The outcome of checking the current status of a locally verified token. */
    public enum Result {
        /** The endpoint reports that the token is active. */
        ACTIVE,
        /** The endpoint reports that the token is inactive. */
        INACTIVE,
        /** The check cannot determine the token's status. */
        UNAVAILABLE
    }

    private final List<URI> issuers;
    private final Credential credential;
    private final KeycardHttpTransport transport;
    private final Duration timeout;
    private final Clock clock;
    private final ConcurrentMap<URI, TokenIntrospectionClient> clients = new ConcurrentHashMap<>();
    private final Set<String> loggedFailures = ConcurrentHashMap.newKeySet();

    BearerTokenIntrospection(
            List<URI> issuers,
            @Nullable Credential credential,
            KeycardHttpTransport transport,
            Duration timeout,
            Clock clock) {
        if (!(credential instanceof ClientAuthenticator)) {
            throw new ConfigurationException("introspection requires a credential with client authentication");
        }
        if (issuers.size() > 1 && !(credential instanceof ClientSecret secret && secret.isMultiZone())) {
            throw new ConfigurationException(
                    "introspection of tokens from multiple zones requires a zone-keyed credential");
        }
        if (timeout.isZero() || timeout.isNegative()) {
            throw new ConfigurationException("introspection timeout must be positive");
        }
        transport.requireRedirectsDisabled();
        this.issuers = issuers;
        this.credential = credential;
        this.transport = transport;
        this.timeout = timeout;
        this.clock = clock;
    }

    /**
     * Checks a token after local verification and scope enforcement, without caching its status.
     *
     * @param issuer the verified issuer claim
     * @param token the original bearer token
     * @return the status check outcome
     */
    public Result check(@Nullable String issuer, String token) {
        if (issuer == null) {
            logFailure("<unconfigured>", "the verified issuer is missing");
            return Result.UNAVAILABLE;
        }
        URI zone;
        try {
            zone = URI.create(issuer);
        } catch (IllegalArgumentException invalid) {
            logFailure("<unconfigured>", "the verified issuer is not a URI");
            return Result.UNAVAILABLE;
        }
        if (!issuers.contains(zone)) {
            logFailure("<unconfigured>", "the verified issuer is not configured for introspection");
            return Result.UNAVAILABLE;
        }
        String issuerLabel = issuerLabel(zone);
        try {
            if (credential instanceof ClientSecret secret && secret.isMultiZone()) {
                try {
                    secret.clientId(zone);
                } catch (ConfigurationException missing) {
                    logFailure(issuerLabel, "no client credential is configured for the verified issuer");
                    return Result.UNAVAILABLE;
                }
            }
            TokenIntrospectionClient client = clients.computeIfAbsent(
                    zone,
                    key -> TokenIntrospectionClient.builder(key)
                            .credential(credential)
                            .transport(transport)
                            .fetchTimeout(timeout)
                            .clock(clock)
                            .build());
            return client.introspectToken(token).active() ? Result.ACTIVE : Result.INACTIVE;
        } catch (RuntimeException failure) {
            logFailure(issuerLabel, describe(zone, failure));
            return Result.UNAVAILABLE;
        }
    }

    /**
     * Writes the infrastructure-failure response without an authentication challenge.
     *
     * @param response the response to write
     * @throws IOException if writing the response fails
     */
    public static void unavailable(HttpServletResponse response) throws IOException {
        BearerChallenge.unavailable(response);
    }

    private void logFailure(String issuer, String cause) {
        String detail = "issuer=" + issuer + ": " + cause;
        if (loggedFailures.add(detail)) {
            LOG.log(System.Logger.Level.WARNING, "Bearer token introspection failed: " + detail);
        }
    }

    private static String issuerLabel(URI zone) {
        String host = zone.getHost();
        return host == null
                ? "<invalid>"
                : zone.getScheme() + "://" + host + (zone.getPort() == -1 ? "" : ":" + zone.getPort())
                        + zone.getRawPath();
    }

    private static String describe(URI zone, RuntimeException failure) {
        String description = failure.getClass().getName();
        if (failure instanceof HttpStatusException http) {
            description += " HTTP " + http.status();
        }
        if (failure instanceof OAuthErrorException oauth
                && (OAuthErrorCodes.isPermanent(oauth.error())
                        || Set.of("server_error", "invalid_request", "temporarily_unavailable")
                                .contains(oauth.error()))) {
            description += " " + oauth.error();
        }
        if (failure.getCause() != null) {
            description += " caused by " + failure.getCause().getClass().getName();
        }
        String message = safeMessage(zone, failure);
        return message == null ? description : description + ": " + message;
    }

    private static @Nullable String safeMessage(URI zone, RuntimeException failure) {
        String message = failure.getMessage();
        if (message == null) {
            return null;
        }
        String response = "token introspection response ";
        String metadata = "metadata for " + zone + " ";
        if (message.startsWith(response)
                && SAFE_RESPONSE_DETAIL
                        .matcher(message.substring(response.length()))
                        .matches()) {
            return message;
        }
        if (message.startsWith(metadata)
                && SAFE_METADATA_DETAIL
                        .matcher(message.substring(metadata.length()))
                        .matches()) {
            return "metadata " + message.substring(metadata.length());
        }
        if (message.equals("the zone " + zone + " advertises no introspection_endpoint")) {
            return "the zone advertises no introspection_endpoint";
        }
        if (message.equals("introspection_endpoint must be an HTTPS URL")) {
            return message;
        }
        if (failure instanceof OAuthProtocolException protocol
                && OAuthProtocolException.ISSUER_MISMATCH.equals(protocol.code())) {
            return "discovered issuer does not match the requested issuer";
        }
        if (failure instanceof HttpStatusException http) {
            if (message.equals("discovery for " + zone + " returned HTTP " + http.status())) {
                return "discovery request failed";
            }
            if (message.equals("token introspection request returned HTTP " + http.status())) {
                return "token introspection request failed";
            }
        }
        return null;
    }
}
