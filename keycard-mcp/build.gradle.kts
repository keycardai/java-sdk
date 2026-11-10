plugins {
    id("keycard.java-library")
}

description = "Keycard auth for MCP servers on Jakarta Servlet: bearer enforcement (RFC 6750), " +
    "OAuth metadata endpoints (RFC 9728 and RFC 8414), and delegated token exchange."

// The servlet container supplies the Servlet API, so it is compile-only here
// and for consumers (Jakarta Servlet 6.0: Tomcat 10.1+, Jetty 12 ee10,
// Spring Boot 3 and 4).
dependencies {
    api(project(":keycard-oauth"))
    compileOnlyApi(libs.jakarta.servlet.api)

    testImplementation(testFixtures(project(":keycard-oauth")))
    testImplementation(libs.jetty.ee10.servlet)
}
