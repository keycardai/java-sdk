package ai.keycard.oauth;

import java.net.URI;
import java.util.List;
import java.util.Objects;

/**
 * The begin step of a web app's sign-in: the URL to redirect the browser to, and what the app keeps
 * until its callback route runs. Store {@code state} and {@code codeVerifier} server side (the
 * session, a signed cookie), one pending flow per user session; the SDK keeps nothing between the
 * two calls.
 *
 * @param url the authorize URL to redirect to
 * @param state the CSRF value embedded in the URL
 * @param codeVerifier the PKCE verifier; never send it to the browser
 * @param resources the RFC 8707 resources requested
 */
public record WebAppFlow(URI url, String state, String codeVerifier, List<URI> resources) {

    /**
     * Freezes the resources.
     *
     * @param url the authorize URL
     * @param state the CSRF value
     * @param codeVerifier the PKCE verifier
     * @param resources the requested resources
     */
    public WebAppFlow {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(codeVerifier, "codeVerifier");
        resources = List.copyOf(resources);
    }

    /**
     * Never prints the verifier.
     *
     * @return the URL and resources
     */
    @Override
    public String toString() {
        return "WebAppFlow[url=" + url + ", resources=" + resources + "]";
    }
}
