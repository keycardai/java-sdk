package ai.keycard.mcp;

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Serves this resource server's own public keys at {@code /.well-known/jwks.json}, for a server
 * that signs its own assertions. Private key material is stripped before serving.
 */
public final class JwksServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** The public key set as JSON. */
    private final String body;

    private JwksServlet(JWKSet keys) {
        this.body = keys.toPublicJWKSet().toString();
    }

    /**
     * A servlet serving the public half of {@code keys}.
     *
     * @param keys the key set; private parts are never served
     * @return the servlet
     */
    public static JwksServlet of(JWKSet keys) {
        return new JwksServlet(keys);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cors.allow(response);
        BearerChallenge.json(response, 200, body);
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        Cors.preflight(response);
    }
}
