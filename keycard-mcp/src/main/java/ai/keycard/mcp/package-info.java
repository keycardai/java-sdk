/**
 * Keycard auth for MCP servers on Jakarta Servlet.
 *
 * <p>A bearer enforcement filter (RFC 6750), OAuth metadata servlets (RFC 9728 and RFC 8414),
 * and a grant filter that exchanges the caller's token for the resources a tool needs. The
 * module wraps no MCP SDK: it attaches at the servlet seam, so it works under the official MCP
 * Java SDK's servlet transport or any other servlet-based server.
 */
@NullMarked
package ai.keycard.mcp;

import org.jspecify.annotations.NullMarked;
