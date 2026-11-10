package ai.keycard.spring.boot;

import java.net.URI;
import java.util.List;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code keycard.*} configuration. Spring's relaxed binding lets {@code KEYCARD_ZONE_URL} set
 * {@code keycard.zone-url}; that's the application's configuration system, not the SDK reading the
 * environment.
 *
 * <pre>
 * keycard.zone-url=https://acme.keycard.cloud
 * keycard.audiences=https://mcp.example.com/mcp
 * keycard.client-id=...        # only for @KeycardGrant, unless a Credential bean is defined
 * keycard.client-secret=...
 * </pre>
 *
 * @param zoneUrl the zone's issuer; the starter configures nothing without it
 * @param audiences audiences inbound tokens must carry, normally this server's resource identifier
 * @param clientId the application's client id, for {@code @KeycardGrant} exchanges
 * @param clientSecret the application's client secret
 * @param resourceName the human-readable name published in protected-resource metadata
 * @param scopesSupported the scopes published in protected-resource metadata
 */
@ConfigurationProperties("keycard")
public record KeycardProperties(
        @Nullable URI zoneUrl,
        @Nullable List<String> audiences,
        @Nullable String clientId,
        @Nullable String clientSecret,
        @Nullable String resourceName,
        @Nullable List<String> scopesSupported) {

    /**
     * Names the zone and client, never the secret.
     *
     * @return a description without the secret
     */
    @Override
    public String toString() {
        return "KeycardProperties[zoneUrl=" + zoneUrl + ", audiences=" + audiences + ", clientId=" + clientId
                + ", resourceName=" + resourceName + ", scopesSupported=" + scopesSupported + "]";
    }
}
