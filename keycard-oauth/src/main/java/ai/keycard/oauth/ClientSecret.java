package ai.keycard.oauth;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A static {@code client_id} and {@code client_secret}, sent as HTTP Basic ({@code
 * client_secret_basic}, RFC 6749 §2.3.1). One credential can hold a pair per zone.
 *
 * <pre>{@code
 * ClientSecret single = ClientSecret.of("my-client", secret);
 * ClientSecret perZone = ClientSecret.perZone(Map.of(
 *         URI.create("https://acme.keycard.cloud"), ClientSecret.of("acme-client", acmeSecret),
 *         URI.create("https://beta.keycard.cloud"), ClientSecret.of("beta-client", betaSecret)));
 * }</pre>
 *
 * <p>A multi-zone credential picks the pair by the zone's issuer and fails closed for a zone it
 * doesn't hold, never falling back to another zone's secret. {@link #toString()} never prints a
 * secret.
 */
public final class ClientSecret implements Credential, ClientAuthenticator {

    private final @Nullable String clientId;
    private final @Nullable String clientSecret;
    private final Map<String, ClientSecret> zones;

    private ClientSecret(@Nullable String clientId, @Nullable String clientSecret, Map<String, ClientSecret> zones) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.zones = zones;
    }

    /**
     * A single-zone credential.
     *
     * @param clientId the registered client id
     * @param clientSecret the registered client secret
     * @return the credential
     * @throws ConfigurationException when either value is empty
     */
    public static ClientSecret of(String clientId, String clientSecret) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(clientSecret, "clientSecret");
        if (clientId.isEmpty() || clientSecret.isEmpty()) {
            throw new ConfigurationException("clientId and clientSecret must not be empty");
        }
        return new ClientSecret(clientId, clientSecret, Map.of());
    }

    /**
     * A multi-zone credential holding one pair per zone issuer.
     *
     * @param zones single-zone credentials keyed by each zone's issuer
     * @return the credential
     * @throws ConfigurationException when the map is empty or a value is itself multi-zone
     */
    public static ClientSecret perZone(Map<URI, ClientSecret> zones) {
        if (zones.isEmpty()) {
            throw new ConfigurationException("a multi-zone ClientSecret needs at least one zone");
        }
        Map<String, ClientSecret> byIssuer = new LinkedHashMap<>();
        zones.forEach((issuer, pair) -> {
            Objects.requireNonNull(issuer, "issuer");
            Objects.requireNonNull(pair, "credential for " + issuer);
            if (pair.isMultiZone()) {
                throw new ConfigurationException("the credential for " + issuer + " must be single-zone");
            }
            byIssuer.put(key(issuer), pair);
        });
        return new ClientSecret(null, null, Collections.unmodifiableMap(byIssuer));
    }

    /**
     * Whether this credential holds a pair per zone.
     *
     * @return {@code true} for a credential built with {@link #perZone(Map)}
     */
    public boolean isMultiZone() {
        return !zones.isEmpty();
    }

    /**
     * The client id this credential authenticates as in a zone.
     *
     * @param issuer the zone's issuer; ignored by a single-zone credential
     * @return the client id
     * @throws ConfigurationException when a multi-zone credential holds nothing for the zone
     */
    public String clientId(URI issuer) {
        return pairFor(issuer).clientId();
    }

    /**
     * The Basic header for the zone, and no form fields.
     *
     * @param issuer the zone's issuer
     * @param endpoint the URL the request goes to; unused, since Basic carries no audience
     * @return the authentication
     * @throws ConfigurationException when a multi-zone credential holds nothing for the zone
     */
    @Override
    public ClientAuthentication authenticate(URI issuer, URI endpoint) {
        Pair pair = pairFor(issuer);
        return ClientAuthentication.basic(pair.clientId(), pair.clientSecret());
    }

    /**
     * A token-exchange request with the access-token subject type and no client credentials in the
     * body. The Basic header comes from {@link #authenticate(URI, URI)}.
     *
     * @param context the subject token, resource and zone
     * @return the request
     * @throws ConfigurationException when a multi-zone credential holds nothing for the zone
     */
    @Override
    public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
        pairFor(context.issuer());
        return TokenExchangeRequest.builder(context.subjectToken())
                .subjectTokenType(TokenTypes.ACCESS_TOKEN)
                .resource(context.resource())
                .build();
    }

    /**
     * Names the client ids and zones, never the secrets.
     *
     * @return a description without secrets
     */
    @Override
    public String toString() {
        if (isMultiZone()) {
            StringBuilder s = new StringBuilder("ClientSecret[zones={");
            zones.forEach((issuer, pair) ->
                    s.append(issuer).append("=").append(pair.clientId).append(", "));
            s.setLength(s.length() - 2);
            return s.append("}]").toString();
        }
        return "ClientSecret[clientId=" + clientId + "]";
    }

    private Pair pairFor(URI issuer) {
        if (!isMultiZone()) {
            return new Pair(Objects.requireNonNull(clientId), Objects.requireNonNull(clientSecret));
        }
        ClientSecret zone = zones.get(key(issuer));
        if (zone == null) {
            throw new ConfigurationException("no client credentials are configured for zone " + issuer);
        }
        return zone.pairFor(issuer);
    }

    private static String key(URI issuer) {
        String value = issuer.toString();
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private record Pair(String clientId, String clientSecret) {}
}
