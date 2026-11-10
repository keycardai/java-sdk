package ai.keycard.spring.boot;

import ai.keycard.mcp.AuthProvider;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.Credential;
import java.util.List;
import java.util.Objects;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Wires Keycard into a Spring Boot servlet application once {@code keycard.zone-url} is set:
 *
 * <ol>
 *   <li>an {@link AuthProvider} for the zone, with a {@link Credential} bean or {@code
 *       keycard.client-id} / {@code keycard.client-secret} for exchanges;
 *   <li>a {@link KeycardJwtDecoder} as Spring Security's {@link JwtDecoder};
 *   <li>a {@link KeycardResourceServer} to apply to a {@link SecurityFilterChain}, and a default
 *       chain requiring a verified token on every request when the application defines none;
 *   <li>{@link KeycardGrant} and {@code AccessContext} handler parameters in Spring MVC.
 * </ol>
 *
 * <p>Each bean backs off when the application defines its own.
 */
@AutoConfiguration(
        beforeName = {
            "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerAutoConfiguration",
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.OAuth2ResourceServerWebSecurityAutoConfiguration"
        })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "keycard", name = "zone-url")
@EnableConfigurationProperties(KeycardProperties.class)
public class KeycardAutoConfiguration {

    /** Created by Spring. */
    public KeycardAutoConfiguration() {}

    /**
     * The provider for the configured zone.
     *
     * @param properties the {@code keycard.*} settings
     * @param credential an application-defined credential, preferred over the properties
     * @return the provider
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthProvider keycardAuthProvider(KeycardProperties properties, ObjectProvider<Credential> credential) {
        AuthProvider.Builder builder = AuthProvider.builder(Objects.requireNonNull(properties.zoneUrl()));
        if (properties.audiences() != null && !properties.audiences().isEmpty()) {
            builder.audiences(properties.audiences().toArray(String[]::new));
        }
        Credential configured = credential.getIfAvailable();
        if (configured != null) {
            builder.credential(configured);
        } else if (properties.clientId() != null && properties.clientSecret() != null) {
            builder.credential(ClientSecret.of(properties.clientId(), properties.clientSecret()));
        }
        return builder.build();
    }

    /**
     * Spring Security's decoder, backed by the provider's verifier.
     *
     * @param provider the provider
     * @return the decoder
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder keycardJwtDecoder(AuthProvider provider) {
        return new KeycardJwtDecoder(provider.tokenVerifier());
    }

    /**
     * The configurer to apply to a {@link SecurityFilterChain}.
     *
     * @param properties the {@code keycard.*} settings
     * @param decoder the decoder
     * @return the configurer
     */
    @Bean
    @ConditionalOnMissingBean
    public KeycardResourceServer keycardResourceServer(KeycardProperties properties, JwtDecoder decoder) {
        return new KeycardResourceServer(
                String.valueOf(properties.zoneUrl()),
                decoder,
                properties.resourceName() == null ? "" : properties.resourceName(),
                properties.scopesSupported() == null ? List.of() : properties.scopesSupported());
    }

    /**
     * The default chain when the application defines none: every request needs a verified token.
     *
     * @param http Spring's builder
     * @param keycard the configurer
     * @return the chain
     * @throws Exception from Spring's builder
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain keycardSecurityFilterChain(HttpSecurity http, KeycardResourceServer keycard)
            throws Exception {
        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .with(keycard, Customizer.withDefaults())
                .build();
    }

    /** {@link KeycardGrant} and {@code AccessContext} parameters for Spring MVC. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(WebMvcConfigurer.class)
    static class Mvc {

        @Bean
        WebMvcConfigurer keycardWebMvcConfigurer(AuthProvider provider) {
            KeycardGrantInterceptor interceptor =
                    new KeycardGrantInterceptor(provider, new BearerTokenAuthenticationEntryPoint());
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    registry.addInterceptor(interceptor);
                }

                @Override
                public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                    resolvers.add(new AccessContextArgumentResolver());
                }
            };
        }
    }
}
