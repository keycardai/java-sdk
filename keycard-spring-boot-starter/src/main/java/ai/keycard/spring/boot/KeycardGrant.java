package ai.keycard.spring.boot;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares the downstream resources a Spring MVC handler needs (grant-decorator.md). Before the
 * handler runs, the caller's verified token is exchanged (RFC 8693) for one token per resource,
 * and the results land in an {@link ai.keycard.oauth.AccessContext} the handler takes as a
 * parameter.
 *
 * <pre>{@code
 * @GetMapping("/events")
 * @KeycardGrant(resources = "https://calendar.example", scopes = "calendar.read")
 * List<Event> events(AccessContext access) {
 *     if (access.hasResourceError("https://calendar.example")) {
 *         return List.of();
 *     }
 *     String token = access.access("https://calendar.example").accessToken();
 *     ...
 * }
 * }</pre>
 *
 * <p>On a class it applies to every handler; with one on the method too, the resources union into
 * one context. A failed exchange never stops the request: it is recorded against its resource. A
 * request with no verified token is answered 401 with an RFC 6750 challenge.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface KeycardGrant {

    /**
     * The downstream resources, as absolute URIs.
     *
     * @return the resources
     */
    String[] resources();

    /**
     * Scopes to request for every resource in this annotation, sent space-separated.
     *
     * @return the scopes; empty for the server's defaults
     */
    String[] scopes() default {};
}
