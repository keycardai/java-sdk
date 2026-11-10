package ai.keycard.mcp;

import jakarta.servlet.http.HttpServletResponse;

/** Permissive CORS for the discovery documents, so browser clients can read them. */
final class Cors {

    private Cors() {}

    static void allow(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
    }

    static void preflight(HttpServletResponse response) {
        allow(response);
        response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "*");
        response.setStatus(204);
    }
}
