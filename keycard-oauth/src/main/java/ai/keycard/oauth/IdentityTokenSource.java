package ai.keycard.oauth;

/**
 * Supplies the platform-signed OIDC token a {@link WorkloadIdentity} presents as its client
 * assertion. Called on every request, because platforms rotate these tokens.
 *
 * <p>A lambda works anywhere a source does:
 *
 * <pre>{@code
 * WorkloadIdentity credential = WorkloadIdentity.builder(() -> vault.read("oidc-token")).build();
 * }</pre>
 *
 * <p>A source may throw {@link WorkloadIdentityConfigurationException} or {@link
 * WorkloadIdentityRuntimeException} with its own source identifier; the credential passes those
 * through. Any other exception is wrapped in a {@link WorkloadIdentityRuntimeException} with the
 * identifier {@value WorkloadIdentityRuntimeException#SOURCE_CUSTOM}.
 */
@FunctionalInterface
public interface IdentityTokenSource {

    /**
     * The current platform-signed OIDC token.
     *
     * @return the token, as the platform issued it
     */
    String identityToken();
}
