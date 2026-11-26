package ai.keycard.mcp;

import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.TokenVerifier;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;

/** The audience and discovery policy shared by a resource server's HTTP components. */
public final class ResourceBinding implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final System.Logger LOG = System.getLogger(ResourceBinding.class.getName());
    private static final String LEGACY_WARNING =
            "Implicit resource binding is deprecated; configure resource_identifier.";

    /** The exact identifier in single-resource mode. */
    private final @Nullable URI identifier;

    /** The zone bindings keyed by zone ID, backed by a serializable map and entries. */
    @SuppressWarnings("serial")
    private final Map<String, Zone> zones;

    /** Whether explicit list or shared discovery mode is enabled. */
    private final boolean multiResource;

    /** Whether the verifier skips audience checking. */
    private final boolean allowAnyAudience;

    /** The configured global audiences in a serializable immutable list. */
    @SuppressWarnings("serial")
    private final List<String> audiences;

    /** The published protected-resource documents in a serializable immutable list. */
    @SuppressWarnings("serial")
    private final List<Document> documents;

    private ResourceBinding(@Nullable URI issuer, Options options, List<String> audiences, boolean metadataOnly) {
        this.identifier = options.identifier;
        this.multiResource = options.multiResource;
        this.allowAnyAudience = options.allowAnyAudience;
        this.audiences = List.copyOf(audiences);
        if ((multiResource && allowAnyAudience)
                || (identifier != null && (options.identifiersByZone != null || multiResource || allowAnyAudience))
                || (options.identifiersByZone != null && allowAnyAudience)
                || (!audiences.isEmpty()
                        && (identifier != null
                                || allowAnyAudience
                                || (options.identifiersByZone != null && !multiResource)))) {
            throw new ConfigurationException("conflicting resource binding modes");
        }
        if (!metadataOnly && multiResource && audiences.isEmpty()) {
            throw new ConfigurationException("multiResource requires a nonempty audience list");
        }
        Map<String, Zone> configured = new LinkedHashMap<>();
        if (options.identifiersByZone != null) {
            if (options.identifiersByZone.isEmpty()) {
                throw new ConfigurationException("resourceIdentifiersByZone must not be empty");
            }
            for (var entry : options.identifiersByZone.entrySet()) {
                URI resource = parseIdentifier(entry.getValue());
                if (issuer == null && isHttp(resource)) {
                    throw new ConfigurationException("HTTP(S) per-zone resources require a base issuer");
                }
                configured.put(
                        entry.getKey(), new Zone(resource, issuer == null ? null : zoneIssuer(issuer, entry.getKey())));
            }
        }
        this.zones = Collections.unmodifiableMap(configured);
        List<Document> published = new ArrayList<>();
        if (identifier != null && isHttp(identifier)) {
            published.add(new Document(identifier, issuer == null ? List.of() : List.of(issuer)));
        } else if (!zones.isEmpty() && multiResource) {
            URI shared = zones.values().iterator().next().identifier();
            if (!isHttp(shared)
                    || zones.values().stream()
                            .anyMatch(zone -> !zone.identifier().toString().equals(shared.toString()))
                    || (!metadataOnly && !audiences.equals(List.of(shared.toString())))) {
                throw new ConfigurationException(
                        "shared discovery requires one identical HTTP(S) identifier and singleton audience");
            }
            published.add(new Document(
                    shared, zones.values().stream().map(Zone::issuer).toList()));
        } else {
            for (Zone zone : zones.values()) {
                URI zonalIssuer = zone.issuer();
                if (isHttp(zone.identifier()) && zonalIssuer != null) {
                    Document document = new Document(zone.identifier(), List.of(zonalIssuer));
                    if (published.stream()
                            .anyMatch(other -> other.path().equals(document.path())
                                    && Objects.equals(
                                            other.resource().getRawQuery(),
                                            document.resource().getRawQuery()))) {
                        throw new ConfigurationException("per-zone resources have ambiguous protected metadata routes");
                    }
                    published.add(document);
                }
            }
        }
        this.documents = List.copyOf(published);
    }

    static ResourceBinding forVerifier(URI issuer, Options options, List<String> audiences) {
        return new ResourceBinding(issuer, options, audiences, false);
    }

    static ResourceBinding forPrebuiltVerifier(URI issuer, Options options, TokenVerifier verifier) {
        List<String> audiences = options.multiResource
                        || (options.identifier == null
                                && options.identifiersByZone == null
                                && !options.allowAnyAudience)
                ? verifier.audiences()
                : List.of();
        return forVerifier(issuer, options, audiences);
    }

    static ResourceBinding forMetadata(@Nullable URI issuer, Options options) {
        return new ResourceBinding(issuer, options, List.of(), true);
    }

    static void warnLegacy() {
        LOG.log(System.Logger.Level.WARNING, LEGACY_WARNING);
    }

    /**
     * Whether request-derived legacy metadata and challenges are in use.
     *
     * @return true for legacy configurations
     */
    public boolean isLegacy() {
        return identifier == null && zones.isEmpty() && !allowAnyAudience && !multiResource;
    }

    /**
     * Whether requests must select a trusted zone independently of the token.
     *
     * @return true for request-selected per-zone binding
     */
    public boolean requiresZone() {
        return !zones.isEmpty() && !multiResource;
    }

    boolean sharedDiscovery() {
        return !zones.isEmpty() && multiResource;
    }

    /**
     * The configured public protected-resource metadata URLs.
     *
     * @return URLs to register at the public host root
     */
    public List<URI> metadataUrls() {
        return documents.stream().map(Document::url).toList();
    }

    /**
     * The configured metadata URL to include in a challenge, if any.
     *
     * @param request the servlet request
     * @param zone the resolved issuer, or null when no zone has been selected
     * @return the configured URL when the original path and query match a published resource
     */
    public Optional<URI> challengeUrl(HttpServletRequest request, @Nullable URI zone) {
        Object originalPath = request.getAttribute(RequestDispatcher.FORWARD_REQUEST_URI);
        String path = originalPath instanceof String value ? value : request.getRequestURI();
        String query = originalPath instanceof String
                ? (String) request.getAttribute(RequestDispatcher.FORWARD_QUERY_STRING)
                : request.getQueryString();
        return documents.stream()
                .filter(document ->
                        !requiresZone() || (zone != null && document.issuers().contains(zone)))
                .filter(document -> path.equals(requestPath(document.resource()))
                        && Objects.equals(query, document.resource().getRawQuery()))
                .map(Document::url)
                .findFirst();
    }

    Optional<Document> document(String path, @Nullable String query) {
        return documents.stream()
                .filter(document -> document.path().equals(path)
                        && Objects.equals(query, document.resource().getRawQuery()))
                .findFirst();
    }

    Map<URI, String> zonalAudiences() {
        Map<URI, String> result = new LinkedHashMap<>();
        for (Zone zone : zones.values()) {
            if (zone.issuer() != null) {
                result.put(zone.issuer(), zone.identifier().toString());
            }
        }
        return result;
    }

    Optional<URI> issuer(String zoneId) {
        return Optional.ofNullable(zones.get(zoneId)).map(Zone::issuer);
    }

    List<String> expectedAudiences() {
        return identifier == null ? audiences : List.of(identifier.toString());
    }

    void validate(TokenVerifier verifier) {
        if (isLegacy()) {
            return;
        }
        Map<URI, String> perIssuer = requiresZone() ? zonalAudiences() : Map.of();
        if (!perIssuer.equals(verifier.audiencesByIssuer())
                || !Set.copyOf(expectedAudiences()).equals(Set.copyOf(verifier.audiences()))
                || (!zones.isEmpty()
                        && !issuerNames(zonalAudiences().keySet()).equals(issuerNames(verifier.issuers())))) {
            throw new ConfigurationException("the token verifier does not enforce the configured resource binding");
        }
    }

    private static Set<String> issuerNames(Collection<URI> issuers) {
        return issuers.stream().map(URI::toString).collect(Collectors.toUnmodifiableSet());
    }

    private static URI parseIdentifier(String identifier) {
        try {
            URI uri = URI.create(identifier);
            if ((isHttp(uri) && uri.getHost() != null && uri.getRawUserInfo() == null && uri.getRawFragment() == null)
                    || ("urn".equalsIgnoreCase(uri.getScheme())
                            && uri.isOpaque()
                            && uri.getRawFragment() == null
                            && uri.getRawSchemeSpecificPart().matches("[A-Za-z0-9][A-Za-z0-9-]{0,31}:.+"))) {
                return uri;
            }
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException("invalid resource_identifier", e);
        }
        throw new ConfigurationException("resource_identifier must be an absolute HTTP(S) URL or URN");
    }

    private static boolean isHttp(URI uri) {
        return "https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme());
    }

    private static URI zoneIssuer(URI base, String id) {
        if (!id.matches("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
                || !isHttp(base)
                || base.getHost() == null
                || base.getRawUserInfo() != null
                || base.getRawQuery() != null
                || base.getRawFragment() != null
                || !(base.getRawPath().isEmpty() || base.getRawPath().equals("/"))) {
            throw new ConfigurationException(
                    "per-zone resource binding requires a DNS zone ID and an HTTP(S) base issuer");
        }
        int port = base.getPort();
        boolean keepPort = port != -1
                && !("https".equalsIgnoreCase(base.getScheme()) && port == 443)
                && !("http".equalsIgnoreCase(base.getScheme()) && port == 80);
        return URI.create(base.getScheme() + "://" + id + "." + base.getHost() + (keepPort ? ":" + port : ""));
    }

    private static String requestPath(URI resource) {
        return resource.getRawPath().isEmpty() ? "/" : resource.getRawPath();
    }

    record Document(URI resource, List<URI> issuers) implements Serializable {
        Document {
            issuers = List.copyOf(issuers);
        }

        String path() {
            String suffix = resource.getRawPath();
            return BearerChallenge.PROTECTED_RESOURCE_PATH + (suffix.equals("/") ? "" : suffix);
        }

        URI url() {
            String query = resource.getRawQuery();
            return URI.create(resource.getScheme() + "://" + resource.getRawAuthority() + path()
                    + (query == null ? "" : "?" + query));
        }
    }

    private record Zone(URI identifier, @Nullable URI issuer) implements Serializable {}

    static final class Options {
        private @Nullable URI identifier;
        private @Nullable Map<String, String> identifiersByZone;
        private boolean multiResource;
        private boolean allowAnyAudience;

        void identifier(String resourceIdentifier) {
            this.identifier = parseIdentifier(resourceIdentifier);
        }

        void identifiersByZone(Map<String, String> resourceIdentifiersByZone) {
            this.identifiersByZone = new LinkedHashMap<>(resourceIdentifiersByZone);
        }

        void multiResource(boolean enabled) {
            this.multiResource = enabled;
        }

        void allowAnyAudience(boolean enabled) {
            this.allowAnyAudience = enabled;
        }
    }
}
