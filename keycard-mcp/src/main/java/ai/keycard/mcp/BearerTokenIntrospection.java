package ai.keycard.mcp;

import ai.keycard.oauth.ClientAuthenticator;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.OAuthErrorCodes;
import ai.keycard.oauth.OAuthErrorException;
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
import org.jspecify.annotations.Nullable;

/** The per-request introspection check shared by the servlet filter and Spring starter. */
public final class BearerTokenIntrospection {

    private static final System.Logger LOG = System.getLogger(BearerTokenIntrospection.class.getName());

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
    public Result check(String issuer, String token) {
        try {
            URI zone = URI.create(issuer);
            if (!issuers.contains(zone)) {
                logFailure("the verified issuer is not configured for introspection");
                return Result.UNAVAILABLE;
            }
            if (credential instanceof ClientSecret secret && secret.isMultiZone()) {
                try {
                    secret.clientId(zone);
                } catch (ConfigurationException missing) {
                    logFailure("no client credential is configured for the verified issuer");
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
            logFailure(describe(failure));
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

    private void logFailure(String cause) {
        if (loggedFailures.add(cause)) {
            LOG.log(System.Logger.Level.WARNING, "Bearer token introspection failed: " + cause);
        }
    }

    private static String describe(RuntimeException failure) {
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
        return description;
    }
}
