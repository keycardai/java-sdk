/**
 * A workload identity token source backed by the SPIFFE Workload API.
 *
 * <p>Fetches JWT-SVIDs for use as client assertions and actor tokens. It lives apart from
 * {@code keycard-oauth} because the SPIFFE client library pulls in gRPC at runtime. Workloads
 * that run spiffe-helper can read the SVID from a file through {@code keycard-oauth} alone.
 */
@NullMarked
package ai.keycard.spiffe;

import org.jspecify.annotations.NullMarked;
