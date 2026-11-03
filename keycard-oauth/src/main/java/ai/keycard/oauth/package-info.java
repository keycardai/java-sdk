/**
 * OAuth 2.0 primitives for Keycard.
 *
 * <p>Token exchange (RFC 8693) with actor tokens and impersonation, the client credentials
 * grant, workload identity, authorization code with PKCE, dynamic client registration (RFC
 * 7591), authorization server discovery (RFC 8414), JWT and JWKS verification, and the
 * non-throwing {@code AccessContext}. Every other Keycard module builds on this one.
 */
@NullMarked
package ai.keycard.oauth;

import org.jspecify.annotations.NullMarked;
