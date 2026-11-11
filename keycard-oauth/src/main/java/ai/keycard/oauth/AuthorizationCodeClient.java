package ai.keycard.oauth;

import com.sun.net.httpserver.HttpServer;
import java.awt.Desktop;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.jspecify.annotations.Nullable;

/**
 * The authorization code grant with PKCE (RFC 6749 §4.1, RFC 7636) against one Keycard zone: the
 * authorize URL, code exchange, a two-step flow for web apps, a loopback flow for CLIs and desktop
 * apps, and refresh.
 *
 * <pre>{@code
 * AuthorizationCodeClient client = AuthorizationCodeClient.builder(URI.create("https://acme.keycard.cloud"))
 *         .clientId("my-cli")
 *         .build();
 * TokenResponse token = client.authenticate(AuthorizationCodeClient.Loopback.builder()
 *         .resources(URI.create("https://api.example.com"))
 *         .build());
 * }</pre>
 *
 * <p>The client authenticates as configured: a public client sends {@code client_id} in the body,
 * a confidential client sends HTTP Basic, and a client built with a {@link Credential} sends that
 * credential's client authentication. The client keeps no state between calls.
 */
public final class AuthorizationCodeClient {

    /** Opens the authorize URL for the user. */
    @FunctionalInterface
    public interface BrowserOpener {

        /**
         * Shows the user the URL to sign in at.
         *
         * @param url the authorize URL
         */
        void open(URI url);

        /**
         * Opens the system browser when one is available, otherwise prints the URL to standard
         * error for the user to open.
         *
         * @return the opener
         */
        static BrowserOpener system() {
            return url -> {
                if (!GraphicsEnvironment.isHeadless()
                        && Desktop.isDesktopSupported()
                        && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    try {
                        Desktop.getDesktop().browse(url);
                        return;
                    } catch (IOException | UnsupportedOperationException e) {
                        // fall through to printing the URL
                    }
                }
                System.err.println("Open this URL to sign in: " + url);
            };
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final URI issuer;
    private final @Nullable String clientId;
    private final @Nullable String clientSecret;
    private final @Nullable ClientAuthenticator credential;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final AuthorizationServerMetadataCache metadata;

    private AuthorizationCodeClient(Builder builder) {
        this.issuer = builder.issuer;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.credential = builder.credential;
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
        this.metadata = builder.metadataCache != null
                ? builder.metadataCache
                : AuthorizationServerMetadataCache.builder()
                        .discovery(AuthorizationServerDiscovery.builder()
                                .transport(builder.transport)
                                .fetchTimeout(builder.fetchTimeout)
                                .build())
                        .clock(builder.clock)
                        .discoveryTtl(builder.discoveryTtl)
                        .negativeTtl(builder.negativeTtl)
                        .build();
    }

    /**
     * A builder for a client against one zone.
     *
     * @param issuer the zone's issuer
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        return new Builder(issuer);
    }

    /**
     * Builds an authorize URL from its parts, with no discovery.
     *
     * @param authorizationEndpoint the zone's authorization endpoint
     * @param clientId the client id
     * @param redirectUri where the zone sends the browser back
     * @param pkce the PKCE pair
     * @param state the CSRF value, or {@code null}
     * @param scopes requested scopes, joined with spaces; empty sends none
     * @param resources RFC 8707 resources, one {@code resource} parameter each
     * @return the URL
     */
    public static URI buildAuthorizeUrl(
            URI authorizationEndpoint,
            String clientId,
            URI redirectUri,
            Pkce pkce,
            @Nullable String state,
            List<String> scopes,
            List<URI> resources) {
        List<String[]> params = new ArrayList<>();
        params.add(new String[] {"response_type", "code"});
        params.add(new String[] {"client_id", clientId});
        params.add(new String[] {"redirect_uri", redirectUri.toString()});
        params.add(new String[] {"code_challenge", pkce.codeChallenge()});
        params.add(new String[] {"code_challenge_method", pkce.codeChallengeMethod()});
        if (!scopes.isEmpty()) {
            params.add(new String[] {"scope", String.join(" ", scopes)});
        }
        if (state != null) {
            params.add(new String[] {"state", state});
        }
        for (URI resource : resources) {
            params.add(new String[] {"resource", resource.toString()});
        }
        StringBuilder query = new StringBuilder();
        for (String[] param : params) {
            query.append(query.length() == 0 ? "" : "&")
                    .append(URLEncoder.encode(param[0], StandardCharsets.UTF_8))
                    .append('=')
                    .append(URLEncoder.encode(param[1], StandardCharsets.UTF_8));
        }
        String base = authorizationEndpoint.toString();
        return URI.create(base + (authorizationEndpoint.getRawQuery() == null ? "?" : "&") + query);
    }

    /**
     * The authorize URL for this client, with the endpoint from discovery.
     *
     * @param redirectUri where the zone sends the browser back
     * @param pkce the PKCE pair
     * @param state the CSRF value, or {@code null}
     * @param scopes requested scopes
     * @param resources RFC 8707 resources
     * @return the URL
     * @throws ConfigurationException when the client id can't be determined
     * @throws KeycardException when discovery fails or advertises no authorization endpoint
     */
    public URI authorizeUrl(
            URI redirectUri, Pkce pkce, @Nullable String state, List<String> scopes, List<URI> resources) {
        URI endpoint = metadata.requireEndpoint(
                issuer, "authorization_endpoint", AuthorizationServerMetadata::authorizationEndpoint);
        return buildAuthorizeUrl(endpoint, requireClientId(), redirectUri, pkce, state, scopes, resources);
    }

    /**
     * Exchanges an authorization code for tokens.
     *
     * @param code the code from the redirect
     * @param codeVerifier the PKCE verifier sent as the challenge
     * @param redirectUri the redirect URI used in the authorization request
     * @return the tokens
     * @throws OAuthErrorException when the zone refuses the code, such as {@code invalid_grant}
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse exchangeCode(String code, String codeVerifier, URI redirectUri) {
        Map<String, List<String>> form = new LinkedHashMap<>();
        form.put("grant_type", List.of("authorization_code"));
        form.put("code", List.of(Objects.requireNonNull(code, "code")));
        form.put("code_verifier", List.of(Objects.requireNonNull(codeVerifier, "codeVerifier")));
        form.put(
                "redirect_uri",
                List.of(Objects.requireNonNull(redirectUri, "redirectUri").toString()));
        URI endpoint = metadata.tokenEndpoint(issuer);
        return TokenEndpoint.post(
                transport, endpoint, form, clientAuthentication(endpoint), fetchTimeout, "code exchange");
    }

    /**
     * The begin step of a web app's sign-in: a fresh PKCE pair and CSRF {@code state}, and the
     * authorize URL carrying them.
     *
     * @param redirectUri the app's registered callback URL
     * @param scopes requested scopes
     * @param resources RFC 8707 resources, bound into the code at authorize time
     * @return the URL to redirect to and what to store until the callback
     */
    public WebAppFlow begin(URI redirectUri, List<String> scopes, List<URI> resources) {
        Pkce pkce = Pkce.generate();
        String state = randomState();
        URI url = authorizeUrl(redirectUri, pkce, state, scopes, resources);
        return new WebAppFlow(url, state, pkce.codeVerifier(), resources);
    }

    /**
     * The complete step of a web app's sign-in, called from its callback route.
     *
     * @param callbackParams the query parameters the callback received
     * @param state the {@code state} stored at begin
     * @param codeVerifier the verifier stored at begin
     * @param redirectUri the same callback URL as at begin
     * @return the tokens
     * @throws OAuthErrorException when the callback carries an {@code error} (status 0, since it
     *     arrived on the redirect), or the zone refuses the code
     * @throws OAuthProtocolException with code {@code state_mismatch} or {@code invalid_callback}
     *     before any token request, when {@code state} doesn't match or {@code code} is missing
     */
    public TokenResponse complete(
            Map<String, String> callbackParams, String state, String codeVerifier, URI redirectUri) {
        // State first: an error redirect without our state could come from anyone, and reporting
        // it would let a forged redirect end the sign-in.
        if (!stateMatches(callbackParams, state)) {
            throw new OAuthProtocolException("the callback's state does not match the stored value", "state_mismatch");
        }
        String error = callbackParams.get("error");
        if (error != null && !error.isEmpty()) {
            String description = callbackParams.get("error_description");
            throw new OAuthErrorException(
                    "sign-in failed with " + error + (description == null ? "" : ": " + description),
                    0,
                    "",
                    error,
                    description,
                    callbackParams.get("error_uri"));
        }
        String code = callbackParams.get("code");
        if (code == null || code.isEmpty()) {
            throw new OAuthProtocolException("the callback carries no code", "invalid_callback");
        }
        return exchangeCode(code, codeVerifier, redirectUri);
    }

    /**
     * Renews a grant with its refresh token. When the response carries a new refresh token, the
     * zone rotated it: store it in place of the old one.
     *
     * @param refreshToken the refresh token
     * @param resources RFC 8707 resources to narrow to, or empty
     * @param scopes scopes to narrow to, or empty for the original grant
     * @return the renewed tokens
     * @throws OAuthErrorException with {@code invalid_grant}, never retryable here, when the refresh
     *     token is expired, revoked or another client's; sign in again
     * @throws KeycardException for discovery, HTTP, network and response-format failures, which
     *     leave the refresh token usable
     */
    public TokenResponse refresh(String refreshToken, List<URI> resources, List<String> scopes) {
        Map<String, List<String>> form = new LinkedHashMap<>();
        form.put("grant_type", List.of("refresh_token"));
        form.put("refresh_token", List.of(Objects.requireNonNull(refreshToken, "refreshToken")));
        if (!scopes.isEmpty()) {
            form.put("scope", List.of(String.join(" ", scopes)));
        }
        if (!resources.isEmpty()) {
            List<String> values = new ArrayList<>();
            resources.forEach(resource -> values.add(resource.toString()));
            form.put("resource", values);
        }
        URI endpoint = metadata.tokenEndpoint(issuer);
        return TokenEndpoint.post(
                transport,
                endpoint,
                form,
                clientAuthentication(endpoint),
                fetchTimeout,
                "refresh",
                Set.of("invalid_grant"));
    }

    /**
     * Signs the user in through the browser: opens the authorize URL, receives the redirect on a
     * loopback server at {@code 127.0.0.1}, and exchanges the code.
     *
     * @param options scopes, resources, port, timeout and how to open the browser
     * @return the tokens
     * @throws InteractionTimeoutException when the user doesn't finish within the timeout
     * @throws OAuthErrorException when the user denies access or the zone refuses the code
     */
    public TokenResponse authenticate(Loopback options) {
        HttpServer server;
        try {
            // The redirect URI names 127.0.0.1, so bind exactly that; getLoopbackAddress() can be ::1.
            server = HttpServer.create(
                    new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), options.port), 0);
        } catch (IOException e) {
            throw new ConfigurationException("could not listen on 127.0.0.1:" + options.port, e);
        }
        URI redirectUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + options.callbackPath);
        WebAppFlow flow;
        try {
            flow = begin(redirectUri, options.scopes, options.resources);
        } catch (RuntimeException e) {
            server.stop(0);
            throw e;
        }
        CompletableFuture<Map<String, String>> callback = new CompletableFuture<>();
        server.createContext(options.callbackPath, exchange -> {
            try (exchange) {
                Map<String, String> params =
                        queryParams(exchange.getRequestURI().getRawQuery());
                // The context matches by prefix; only the exact path with our state ends the wait,
                // so a stray or forged request can't cancel or hijack the sign-in.
                boolean ours = "GET".equals(exchange.getRequestMethod())
                        && options.callbackPath.equals(exchange.getRequestURI().getRawPath())
                        && stateMatches(params, flow.state());
                if (!ours) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
                callback.complete(params);
                byte[] page = ("<!doctype html><title>Signed in</title>"
                                + "<p>You can close this window and return to the application.</p>")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                exchange.sendResponseHeaders(200, page.length);
                exchange.getResponseBody().write(page);
            }
        });
        server.start();
        try {
            options.browser.open(flow.url());
            Map<String, String> params;
            try {
                params = callback.get(options.timeout.toMillis(), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                throw new InteractionTimeoutException("sign-in was not completed within " + options.timeout);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new KeycardException("interrupted while waiting for sign-in", e);
            } catch (ExecutionException e) {
                throw new KeycardException("the loopback callback failed", e.getCause());
            }
            return complete(params, flow.state(), flow.codeVerifier(), redirectUri);
        } finally {
            // A one-second grace lets the browser finish reading the page instead of seeing a reset.
            server.stop(1);
        }
    }

    private static boolean stateMatches(Map<String, String> callbackParams, String state) {
        String received = callbackParams.get("state");
        return received != null
                && MessageDigest.isEqual(
                        received.getBytes(StandardCharsets.UTF_8), state.getBytes(StandardCharsets.UTF_8));
    }

    private ClientAuthentication clientAuthentication(URI endpoint) {
        if (credential != null) {
            return credential.authenticate(issuer, endpoint);
        }
        String id = Objects.requireNonNull(clientId);
        if (clientSecret != null) {
            return ClientAuthentication.basic(id, clientSecret);
        }
        return ClientAuthentication.formFields(Map.of("client_id", id));
    }

    private String requireClientId() {
        if (clientId != null) {
            return clientId;
        }
        if (credential instanceof ClientSecret secret) {
            return secret.clientId(issuer);
        }
        if (credential instanceof WorkloadIdentity workload && workload.clientId() != null) {
            return workload.clientId();
        }
        if (credential instanceof WebIdentity web && web.clientId() != null) {
            return web.clientId();
        }
        throw new ConfigurationException("the authorize URL needs a client id; this credential doesn't name one");
    }

    private static String randomState() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static Map<String, String> queryParams(@Nullable String rawQuery) {
        Map<String, String> params = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return params;
        }
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            String name = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            params.putIfAbsent(name, value);
        }
        return params;
    }

    /** Options for {@link #authenticate(Loopback)}. */
    public static final class Loopback {

        private final List<String> scopes;
        private final List<URI> resources;
        private final int port;
        private final String callbackPath;
        private final Duration timeout;
        private final BrowserOpener browser;

        private Loopback(Loopback.Builder builder) {
            this.scopes = List.copyOf(builder.scopes);
            this.resources = List.copyOf(builder.resources);
            this.port = builder.port;
            this.callbackPath = builder.callbackPath;
            this.timeout = builder.timeout;
            this.browser = builder.browser;
        }

        /**
         * A builder with an ephemeral port, {@code /callback}, a 5 minute timeout and the system
         * browser.
         *
         * @return a new builder
         */
        public static Loopback.Builder builder() {
            return new Loopback.Builder();
        }

        /** Configures {@link Loopback}. */
        public static final class Builder {

            private List<String> scopes = List.of();
            private List<URI> resources = List.of();
            private int port;
            private String callbackPath = "/callback";
            private Duration timeout = Duration.ofMinutes(5);
            private BrowserOpener browser = BrowserOpener.system();

            private Builder() {}

            /**
             * Requested scopes.
             *
             * @param scopes the scopes
             * @return this builder
             */
            public Loopback.Builder scopes(String... scopes) {
                this.scopes = List.of(scopes);
                return this;
            }

            /**
             * RFC 8707 resources to bind into the code.
             *
             * @param resources the resources
             * @return this builder
             */
            public Loopback.Builder resources(URI... resources) {
                this.resources = List.of(resources);
                return this;
            }

            /**
             * The loopback port; 0 picks a free one. The zone must accept the resulting
             * {@code http://127.0.0.1:<port><path>} as a redirect URI.
             *
             * @param port the port
             * @return this builder
             */
            public Loopback.Builder port(int port) {
                if (port < 0 || port > 65535) {
                    throw new ConfigurationException("port must be 0 to 65535, got " + port);
                }
                this.port = port;
                return this;
            }

            /**
             * The callback path. Defaults to {@code /callback}.
             *
             * @param callbackPath a path starting with {@code /}
             * @return this builder
             */
            public Loopback.Builder callbackPath(String callbackPath) {
                if (!callbackPath.startsWith("/")) {
                    throw new ConfigurationException("callbackPath must start with /");
                }
                this.callbackPath = callbackPath;
                return this;
            }

            /**
             * How long to wait for the user. Defaults to 5 minutes.
             *
             * @param timeout a positive duration
             * @return this builder
             */
            public Loopback.Builder timeout(Duration timeout) {
                if (timeout.isNegative() || timeout.isZero()) {
                    throw new ConfigurationException("timeout must be positive");
                }
                this.timeout = timeout;
                return this;
            }

            /**
             * How to show the user the authorize URL. Defaults to {@link BrowserOpener#system()}.
             *
             * @param browser the opener
             * @return this builder
             */
            public Loopback.Builder browser(BrowserOpener browser) {
                this.browser = Objects.requireNonNull(browser, "browser");
                return this;
            }

            /**
             * Builds the options.
             *
             * @return the options
             */
            public Loopback build() {
                return new Loopback(this);
            }
        }
    }

    /** Configures an {@link AuthorizationCodeClient}. */
    public static final class Builder {

        private final URI issuer;
        private @Nullable String clientId;
        private @Nullable String clientSecret;
        private @Nullable ClientAuthenticator credential;
        private KeycardHttpTransport transport;
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration discoveryTtl = AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL;
        private Duration negativeTtl = AuthorizationServerMetadataCache.DEFAULT_NEGATIVE_TTL;
        private Clock clock = Clock.systemUTC();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder(URI issuer) {
            AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
            this.issuer = issuer;
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * The client id. Alone, the client is public and sends it in the body.
         *
         * @param clientId the registered client id
         * @return this builder
         */
        public Builder clientId(String clientId) {
            this.clientId = Objects.requireNonNull(clientId, "clientId");
            return this;
        }

        /**
         * A client secret, making the client confidential (HTTP Basic). Needs {@link #clientId}.
         *
         * @param clientSecret the secret
         * @return this builder
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = Objects.requireNonNull(clientSecret, "clientSecret");
            return this;
        }

        /**
         * A credential that authenticates the client instead of a client id and secret. It must
         * provide client authentication.
         *
         * @param credential the credential
         * @return this builder
         * @throws ConfigurationException when the credential can't authenticate the client
         */
        public Builder credential(Credential credential) {
            if (!(Objects.requireNonNull(credential, "credential") instanceof ClientAuthenticator authenticator)) {
                throw new ConfigurationException(
                        credential.getClass().getName() + " does not provide client authentication");
            }
            this.credential = authenticator;
            return this;
        }

        /**
         * The transport for discovery and token requests.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(KeycardHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Sends requests through a caller-configured JDK client.
         *
         * @param client the client
         * @return this builder
         */
        public Builder httpClient(HttpClient client) {
            return transport(KeycardHttpTransport.of(client));
        }

        /**
         * The bound on each discovery and token request. Defaults to 10 seconds.
         *
         * @param fetchTimeout a positive duration
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            if (fetchTimeout.isNegative() || fetchTimeout.isZero()) {
                throw new ConfigurationException("fetchTimeout must be positive, got " + fetchTimeout);
            }
            this.fetchTimeout = fetchTimeout;
            return this;
        }

        /**
         * How long discovered endpoints are reused. Defaults to 1 hour.
         *
         * @param discoveryTtl a positive duration
         * @return this builder
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            this.discoveryTtl = Objects.requireNonNull(discoveryTtl, "discoveryTtl");
            return this;
        }

        /**
         * How long a deterministic discovery failure is remembered. Defaults to 1 minute.
         *
         * @param negativeTtl a duration of zero or more
         * @return this builder
         */
        public Builder negativeTtl(Duration negativeTtl) {
            this.negativeTtl = Objects.requireNonNull(negativeTtl, "negativeTtl");
            return this;
        }

        /**
         * The clock for discovery TTLs.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * A metadata cache to share with other clients.
         *
         * @param metadataCache the shared cache
         * @return this builder
         */
        public Builder metadataCache(AuthorizationServerMetadataCache metadataCache) {
            this.metadataCache = Objects.requireNonNull(metadataCache, "metadataCache");
            return this;
        }

        /**
         * Builds the client.
         *
         * @return the client
         * @throws ConfigurationException when neither a client id nor a credential is set, a secret
         *     has no client id, or a credential is combined with a client id or secret
         */
        public AuthorizationCodeClient build() {
            if (credential != null && (clientId != null || clientSecret != null)) {
                throw new ConfigurationException("set a credential or a client id and secret, not both");
            }
            if (credential == null && clientId == null) {
                throw new ConfigurationException("an authorization code client needs a client id or a credential");
            }
            if (clientSecret != null && clientId == null) {
                throw new ConfigurationException("a client secret needs a client id");
            }
            return new AuthorizationCodeClient(this);
        }
    }
}
