plugins {
    id("keycard.java-library")
}

description = "Spring Boot auto-configuration for Keycard: a Keycard-backed JwtDecoder for Spring " +
    "Security's resource server, RFC 9728 metadata, and @KeycardGrant with AccessContext injection."

dependencies {
    api(project(":keycard-mcp"))
    // Spring Security's own resource server does the verification plumbing; the starter plugs
    // Keycard's verifier and challenges into it.
    api(libs.spring.boot.starter.oauth2.resource.server)
    api(libs.spring.boot.autoconfigure)
    // @KeycardGrant and the AccessContext argument resolver attach to Spring MVC when present.
    compileOnly(libs.spring.webmvc)
    compileOnly(libs.jakarta.servlet.api.x61)

    testImplementation(testFixtures(project(":keycard-oauth")))
    testImplementation(libs.spring.webmvc)
    testImplementation(libs.spring.test)
    testImplementation(libs.spring.boot.test)
    testImplementation(libs.spring.security.test)
    testImplementation(libs.jakarta.servlet.api.x61)
    // Spring's metadata filter writes JSON through Jackson, which web apps already have.
    testImplementation(libs.jackson.databind)
}
