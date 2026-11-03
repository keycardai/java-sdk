/**
 * Keycard agent-to-agent delegation.
 *
 * <p>Discovers a target agent's card, exchanges the caller's token for one scoped to the target
 * (the user stays the subject and the calling agent is recorded in the {@code act} claim), and
 * invokes the target over JSON-RPC.
 */
@NullMarked
package ai.keycard.a2a;

import org.jspecify.annotations.NullMarked;
