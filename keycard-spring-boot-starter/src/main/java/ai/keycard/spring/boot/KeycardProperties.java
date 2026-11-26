package ai.keycard.spring.boot;

import java.net.URI;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * {@code keycard.*} configuration. Spring's relaxed binding lets {@code KEYCARD_ZONE_URL} set
 * {@code keycard.zone-url}; that's the application's configuration system, not the SDK reading the
 * environment.
 *
 * <pre>
 * keycard.zone-url=https://acme.keycard.cloud
 * keycard.resource-identifier=https://mcp.example.com/mcp
 * keycard.introspect=true
 * keycard.client-id=...        # for introspection or @KeycardGrant, unless a Credential bean is defined
 * keycard.client-secret=...
 * </pre>
 *
 * @param zoneUrl the zone's issuer; the starter configures nothing without it
 * @param audiences audiences inbound tokens must carry, normally this server's resource identifier
 * @param clientId the application's client id, for introspection or {@code @KeycardGrant} exchanges
 * @param clientSecret the application's client secret
 * @param resourceName the human-readable name published in protected-resource metadata
 * @param scopesSupported the scopes published in protected-resource metadata
 * @param resourceIdentifier the exact HTTP(S) resource URL or URN
 * @param resourceIdentifiersByZone the resource identifiers by zone ID
 * @param multiResource enables explicit audience list or shared discovery mode
 * @param allowAnyAudience skips audience checking without enabling protected-resource discovery
 * @param metadataForwarded the public host-root metadata URL is forwarded into the servlet context
 * @param introspect checks current bearer token status with the Resource owner's application credential
 */
@ConfigurationProperties("keycard")
public record KeycardProperties(
        @Nullable URI zoneUrl,
        @Nullable List<String> audiences,
        @Nullable String clientId,
        @Nullable String clientSecret,
        @Nullable String resourceName,
        @Nullable List<String> scopesSupported,
        @Nullable String resourceIdentifier,
        @Nullable Map<String, String> resourceIdentifiersByZone,
        boolean multiResource,
        boolean allowAnyAudience,
        boolean metadataForwarded,
        boolean introspect) {

    /**
     * Creates the Spring resource server configuration.
     *
     * @param zoneUrl the configured zone or base issuer
     * @param audiences the optional audience list
     * @param clientId the optional client ID
     * @param clientSecret the optional client secret
     * @param resourceName the optional resource name
     * @param scopesSupported the optional resource scopes
     * @param resourceIdentifier the optional exact resource identifier
     * @param resourceIdentifiersByZone the optional zone resource identifiers
     * @param multiResource whether to enable list-based verification
     * @param allowAnyAudience whether to skip audience checking
     * @param metadataForwarded whether metadata requests are forwarded into the context
     * @param introspect whether to check verified bearer tokens with the introspection endpoint
     */
    @ConstructorBinding
    public KeycardProperties {}

    /**
     * Creates the Spring resource server configuration with introspection disabled.
     *
     * @param zoneUrl the configured zone or base issuer
     * @param audiences the optional audience list
     * @param clientId the optional client ID
     * @param clientSecret the optional client secret
     * @param resourceName the optional resource name
     * @param scopesSupported the optional resource scopes
     * @param resourceIdentifier the optional exact resource identifier
     * @param resourceIdentifiersByZone the optional zone resource identifiers
     * @param multiResource whether to enable list-based verification
     * @param allowAnyAudience whether to skip audience checking
     * @param metadataForwarded whether metadata requests are forwarded into the context
     */
    public KeycardProperties(
            @Nullable URI zoneUrl,
            @Nullable List<String> audiences,
            @Nullable String clientId,
            @Nullable String clientSecret,
            @Nullable String resourceName,
            @Nullable List<String> scopesSupported,
            @Nullable String resourceIdentifier,
            @Nullable Map<String, String> resourceIdentifiersByZone,
            boolean multiResource,
            boolean allowAnyAudience,
            boolean metadataForwarded) {
        this(
                zoneUrl,
                audiences,
                clientId,
                clientSecret,
                resourceName,
                scopesSupported,
                resourceIdentifier,
                resourceIdentifiersByZone,
                multiResource,
                allowAnyAudience,
                metadataForwarded,
                false);
    }

    /**
     * Creates an implicit resource binding configuration.
     *
     * @param zoneUrl the configured zone issuer
     * @param audiences the optional audience list
     * @param clientId the optional client ID
     * @param clientSecret the optional client secret
     * @param resourceName the optional resource name
     * @param scopesSupported the optional resource scopes
     */
    public KeycardProperties(
            @Nullable URI zoneUrl,
            @Nullable List<String> audiences,
            @Nullable String clientId,
            @Nullable String clientSecret,
            @Nullable String resourceName,
            @Nullable List<String> scopesSupported) {
        this(
                zoneUrl,
                audiences,
                clientId,
                clientSecret,
                resourceName,
                scopesSupported,
                null,
                null,
                false,
                false,
                false);
    }

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
