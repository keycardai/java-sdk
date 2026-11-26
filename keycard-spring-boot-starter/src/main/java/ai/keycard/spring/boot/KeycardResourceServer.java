package ai.keycard.spring.boot;

import ai.keycard.mcp.AuthProvider;
import ai.keycard.mcp.AuthorizationServerMetadataServlet;
import ai.keycard.mcp.ProtectedResourceMetadataServlet;
import ai.keycard.mcp.RequireBearerAuthFilter.ZoneResolver;
import ai.keycard.mcp.ResourceBinding;
import ai.keycard.oauth.ConfigurationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Configures Spring Security's own OAuth2 resource server for a Keycard zone: Keycard's verifier
 * as the {@link JwtDecoder}, RFC 6750 challenges with {@code resource_metadata}, RFC 9728
 * protected-resource metadata naming the zone, the zone's RFC 8414 metadata proxied at {@code
 * /.well-known/oauth-authorization-server}, and 503 {@code temporarily_unavailable} with no
 * challenge when the zone's keys can't be fetched.
 *
 * <pre>{@code
 * @Bean
 * SecurityFilterChain api(HttpSecurity http, KeycardResourceServer keycard) {
 *     return http
 *             .authorizeHttpRequests(auth -> auth
 *                     .requestMatchers("/admin/**").hasAuthority("SCOPE_admin")
 *                     .anyRequest().authenticated())
 *             .csrf(csrf -> csrf.disable())
 *             .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
 *             .with(keycard, Customizer.withDefaults())
 *             .build();
 * }
 * }</pre>
 *
 * <p>The configurer leaves CSRF as the chain sets it. A chain that only accepts bearer tokens
 * should disable CSRF and sessions, as above and as the starter's default chain does: a bearer
 * token is never sent by the browser on its own, so there is nothing to forge, and with CSRF on,
 * an unauthenticated POST gets a CSRF 403 instead of the 401 challenge an MCP client needs. A
 * chain that also signs people in with cookies, Basic or a sign-in form must keep CSRF on.
 *
 * <p>Protected-resource metadata is written by Spring Security's filter, which needs a JSON
 * library on the classpath (Jackson, which Spring Boot's web starter brings, Gson or JSON-B).
 *
 * <p>Scope checks are Spring's: a token's {@code scope} claim becomes {@code SCOPE_*} authorities,
 * and a denied rule answers 403 {@code insufficient_scope}. The starter registers one of these as
 * a bean and applies it to a default chain when the application defines none.
 */
public final class KeycardResourceServer extends AbstractHttpConfigurer<KeycardResourceServer, HttpSecurity> {

    private final String zoneUrl;
    private final JwtDecoder decoder;
    private final List<String> scopesSupported;
    private final String resourceName;
    private final AuthorizationServerMetadataFilter authorizationServerMetadata;
    private final @Nullable ResourceBinding binding;
    private final @Nullable ProtectedResourceMetadataServlet protectedResourceMetadata;
    private final @Nullable ZoneResolver zoneResolver;
    private static final String PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";

    /**
     * A configurer for one zone.
     *
     * @param zoneUrl the zone's issuer, published as the authorization server
     * @param decoder the decoder, normally a {@link KeycardJwtDecoder}
     * @param resourceName the name published in protected-resource metadata, or empty for none
     * @param scopesSupported the scopes published in protected-resource metadata
     */
    public KeycardResourceServer(
            String zoneUrl, JwtDecoder decoder, String resourceName, List<String> scopesSupported) {
        this.zoneUrl = Objects.requireNonNull(zoneUrl, "zoneUrl");
        this.decoder = Objects.requireNonNull(decoder, "decoder");
        this.resourceName = Objects.requireNonNull(resourceName, "resourceName");
        this.scopesSupported = List.copyOf(scopesSupported);
        this.authorizationServerMetadata = new AuthorizationServerMetadataFilter(
                AuthorizationServerMetadataServlet.of(URI.create(zoneUrl)), false);
        this.binding = null;
        this.protectedResourceMetadata = null;
        this.zoneResolver = null;
        System.getLogger(KeycardResourceServer.class.getName())
                .log(
                        System.Logger.Level.WARNING,
                        "Implicit resource binding is deprecated; configure resource_identifier.");
    }

    KeycardResourceServer(
            String zoneUrl,
            JwtDecoder decoder,
            String resourceName,
            List<String> scopesSupported,
            AuthProvider provider,
            @Nullable ZoneResolver zoneResolver,
            String contextPath,
            boolean metadataForwarded) {
        this.zoneUrl = zoneUrl;
        this.decoder = decoder;
        this.resourceName = resourceName;
        this.scopesSupported = List.copyOf(scopesSupported);
        this.binding = provider.resourceBinding();
        this.zoneResolver = binding.requiresZone() ? zoneResolver : null;
        if (binding.requiresZone() && (zoneResolver == null || !(decoder instanceof KeycardJwtDecoder))) {
            throw new ConfigurationException(
                    "per-zone resource binding requires a request zone resolver and KeycardJwtDecoder");
        }
        if (!binding.metadataUrls().isEmpty()
                && !contextPath.isEmpty()
                && !contextPath.equals("/")
                && !metadataForwarded) {
            throw new ConfigurationException(
                    "publish resource metadata at the public host root or configure metadata forwarding");
        }
        this.authorizationServerMetadata =
                new AuthorizationServerMetadataFilter(provider.authorizationServerMetadata(), !binding.isLegacy());
        ProtectedResourceMetadataServlet.Builder metadata = provider.protectedResourceMetadata()
                .scopesSupported(scopesSupported.toArray(String[]::new))
                .metadataForwarded(metadataForwarded);
        if (!resourceName.isEmpty()) {
            metadata.resourceName(resourceName);
        }
        this.protectedResourceMetadata = binding.metadataUrls().isEmpty() ? null : metadata.build();
    }

    @Override
    public void init(HttpSecurity http) {
        AuthenticationEntryPoint challenge = challenge(binding, zoneResolver);
        BearerTokenAccessDeniedHandler denied = new BearerTokenAccessDeniedHandler();
        http.oauth2ResourceServer(resourceServer -> {
            resourceServer
                    .bearerTokenResolver(new StrictBearerTokenResolver())
                    .authenticationEntryPoint(challenge)
                    .accessDeniedHandler(
                            binding == null || binding.isLegacy()
                                    ? denied
                                    : (request, response, exception) -> {
                                        denied.handle(request, response, exception);
                                        appendMetadata(binding, zoneResolver, request, response);
                                    })
                    .withObjectPostProcessor(new ObjectPostProcessor<BearerTokenAuthenticationFilter>() {
                        @Override
                        public <O extends BearerTokenAuthenticationFilter> O postProcess(O filter) {
                            filter.setAuthenticationFailureHandler(new ZoneAwareFailureHandler(challenge));
                            return filter;
                        }
                    });
            ZoneResolver resolver = zoneResolver;
            if (resolver == null) {
                resourceServer.jwt(jwt -> jwt.decoder(decoder));
            } else {
                JwtAuthenticationConverter converter = http.getSharedObject(ApplicationContext.class)
                        .getBeanProvider(JwtAuthenticationConverter.class)
                        .getIfAvailable(JwtAuthenticationConverter::new);
                resourceServer.authenticationManagerResolver(request -> authentication -> {
                    URI zone = resolveZone(resolver, request);
                    if (zone == null) {
                        throw new OAuth2AuthenticationException(
                                BearerTokenErrors.invalidToken("the request's zone is not configured"));
                    }
                    JwtAuthenticationProvider provider =
                            new JwtAuthenticationProvider(((KeycardJwtDecoder) decoder).forZone(zone));
                    provider.setJwtAuthenticationConverter(converter);
                    return provider.authenticate(authentication);
                });
            }
            if (binding == null || binding.isLegacy()) {
                resourceServer.protectedResourceMetadata(
                        metadata -> metadata.protectedResourceMetadataCustomizer(builder -> {
                            builder.authorizationServer(zoneUrl);
                            if (!resourceName.isEmpty()) {
                                builder.resourceName(resourceName);
                            }
                            scopesSupported.forEach(builder::scope);
                        }));
            }
        });
        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(challenge));
        http.addFilterBefore(authorizationServerMetadata, BearerTokenAuthenticationFilter.class);
        ProtectedResourceMetadataServlet metadata = protectedResourceMetadata;
        if (binding != null && !binding.isLegacy()) {
            http.addFilterBefore(
                    new OncePerRequestFilter() {
                        @Override
                        protected boolean shouldNotFilter(HttpServletRequest request) {
                            String path = request.getRequestURI()
                                    .substring(request.getContextPath().length());
                            return !path.equals(PROTECTED_RESOURCE_PATH)
                                    && !path.startsWith(PROTECTED_RESOURCE_PATH + "/");
                        }

                        @Override
                        protected void doFilterInternal(
                                HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                                throws ServletException, IOException {
                            if (metadata != null && metadata.matches(request)) {
                                metadata.service(request, response);
                            } else {
                                response.setStatus(404);
                            }
                        }
                    },
                    X509AuthenticationFilter.class);
        }
    }

    static AuthenticationEntryPoint challenge(@Nullable ResourceBinding binding, @Nullable ZoneResolver zoneResolver) {
        if (binding == null || binding.isLegacy()) {
            return new SchemeAwareEntryPoint(new BearerTokenAuthenticationEntryPoint());
        }
        return new SchemeAwareEntryPoint((request, response, exception) -> {
            String header = "Bearer";
            if (exception instanceof OAuth2AuthenticationException failure) {
                var error = failure.getError();
                if (error instanceof BearerTokenError bearer
                        && bearer.getHttpStatus().value() != 401) {
                    response.setStatus(bearer.getHttpStatus().value());
                    return;
                }
                header += " error=\"" + error.getErrorCode() + "\"";
                if (error.getDescription() != null) {
                    header += ", error_description=\""
                            + error.getDescription()
                                    .replace("\\", "\\\\")
                                    .replace("\"", "\\\"")
                                    .replaceAll("[\\p{Cntrl}]", "")
                            + "\"";
                }
            }
            response.setStatus(401);
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, header);
            appendMetadata(binding, zoneResolver, request, response);
        });
    }

    private static void appendMetadata(
            @Nullable ResourceBinding binding,
            @Nullable ZoneResolver zoneResolver,
            HttpServletRequest request,
            HttpServletResponse response) {
        if (binding == null || binding.isLegacy() || (response.getStatus() != 401 && response.getStatus() != 403)) {
            return;
        }
        String header = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);
        if (header != null && header.startsWith("Bearer")) {
            URI zone = zoneResolver == null ? null : resolveZone(zoneResolver, request);
            binding.challengeUrl(request, zone)
                    .ifPresent(url -> response.setHeader(
                            HttpHeaders.WWW_AUTHENTICATE,
                            header + (header.equals("Bearer") ? " " : ", ") + "resource_metadata=\"" + url + '"'));
        }
    }

    private static @Nullable URI resolveZone(ZoneResolver resolver, HttpServletRequest request) {
        String key = KeycardResourceServer.class.getName() + ".zone";
        Object cached = request.getAttribute(key);
        if (cached instanceof Optional<?> value) {
            return (URI) value.orElse(null);
        }
        URI zone = resolver.resolve(request);
        request.setAttribute(key, Optional.ofNullable(zone));
        return zone;
    }

    /**
     * The RFC 6750 challenge, with {@code invalid_token} when the request carried an {@code
     * Authorization} header in some other scheme, as the servlet filter answers.
     *
     * <p>This lives in the challenge rather than the token resolver on purpose: Spring runs the
     * resolver on every request, so rejecting other schemes there would also refuse {@code
     * permitAll()} paths and break a chain that signs people in with Basic. The challenge is only
     * written for a protected path with no authenticated caller, where a Basic header that
     * authenticated never arrives.
     */
    static final class SchemeAwareEntryPoint implements AuthenticationEntryPoint {

        private final AuthenticationEntryPoint delegate;

        SchemeAwareEntryPoint(AuthenticationEntryPoint delegate) {
            this.delegate = delegate;
        }

        @Override
        public void commence(
                jakarta.servlet.http.HttpServletRequest request,
                jakarta.servlet.http.HttpServletResponse response,
                AuthenticationException exception)
                throws IOException, jakarta.servlet.ServletException {
            AuthenticationException reported = exception;
            if (!(exception instanceof OAuth2AuthenticationException) && otherScheme(request)) {
                reported = new OAuth2AuthenticationException(
                        BearerTokenErrors.invalidToken("unsupported authorization scheme"));
            }
            delegate.commence(request, response, reported);
        }

        private static boolean otherScheme(jakarta.servlet.http.HttpServletRequest request) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header == null || header.isBlank()) {
                return false;
            }
            String scheme = header.trim().split("\\s+", 2)[0];
            return !scheme.equalsIgnoreCase("bearer");
        }
    }

    /** Answers zone failures with 503 and no challenge; everything else gets the RFC 6750 challenge. */
    static final class ZoneAwareFailureHandler implements AuthenticationFailureHandler {

        private final AuthenticationEntryPoint challenge;

        ZoneAwareFailureHandler(AuthenticationEntryPoint challenge) {
            this.challenge = challenge;
        }

        @Override
        public void onAuthenticationFailure(
                jakarta.servlet.http.HttpServletRequest request,
                jakarta.servlet.http.HttpServletResponse response,
                AuthenticationException exception)
                throws IOException, jakarta.servlet.ServletException {
            if (exception instanceof AuthenticationServiceException
                    && exception.getCause() instanceof KeycardJwtDecoder.ZoneUnavailableException) {
                response.setStatus(503);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"temporarily_unavailable\"}");
                return;
            }
            challenge.commence(request, response, exception);
        }
    }
}
