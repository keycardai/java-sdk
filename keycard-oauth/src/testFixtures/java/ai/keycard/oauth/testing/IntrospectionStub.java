package ai.keycard.oauth.testing;

import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.TransportRequest;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

/** Advertises HTTPS introspection metadata backed by a loopback stub. */
public final class IntrospectionStub {

    /** The endpoint advertised by introspection metadata. */
    public static final String PATH = "/oauth/introspect";

    private IntrospectionStub() {}

    /**
     * The HTTPS issuer presented to the SDK.
     *
     * @param zone the loopback stub
     * @return its issuer with HTTPS scheme
     */
    public static URI issuer(StubZone zone) {
        return URI.create("https://" + zone.issuer().getRawAuthority());
    }

    /**
     * Serves the metadata pointing to the stub's JWKS and, optionally, introspection.
     *
     * @param zone the loopback stub
     * @param introspection whether the metadata advertises introspection
     */
    public static void discovery(StubZone zone, boolean introspection) {
        URI issuer = issuer(zone);
        Map<String, String> metadata = new LinkedHashMap<>();
        metadata.put("issuer", issuer.toString());
        metadata.put("jwks_uri", issuer.resolve(StubZone.JWKS_PATH).toString());
        if (introspection) {
            metadata.put("introspection_endpoint", issuer.resolve(PATH).toString());
        }
        zone.respond("GET", StubZone.DISCOVERY_PATH, 200, JSONObjectUtils.toJSONString(metadata));
    }

    /**
     * Routes only configured HTTPS issuers to loopback stub servers.
     *
     * @param zones the configured stubs
     * @return a transport that preserves the original method, body and timeout
     */
    public static KeycardHttpTransport transport(StubZone... zones) {
        KeycardHttpTransport http = KeycardHttpTransport.create();
        return request -> {
            for (StubZone zone : zones) {
                URI path = issuer(zone).relativize(request.uri());
                if (!path.isAbsolute()) {
                    return http.send(new TransportRequest(
                            request.method(),
                            zone.issuer().resolve(path),
                            request.headers(),
                            request.body(),
                            request.timeout()));
                }
            }
            throw new AssertionError("unexpected request URI " + request.uri());
        };
    }
}
