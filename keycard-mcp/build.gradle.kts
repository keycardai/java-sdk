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

// Gradle publishes compileOnlyApi dependencies at compile scope, which would make Maven bundle
// the Servlet API into an application's WAR. The container supplies it, so the POM says
// `provided`: Maven users still see which Servlet version is needed, without getting a copy.
mavenPublishing {
    pom {
        withXml {
            val dependencies = asElement().getElementsByTagName("dependency")
            for (i in 0 until dependencies.length) {
                val dependency = dependencies.item(i) as org.w3c.dom.Element
                val artifactId = dependency.getElementsByTagName("artifactId").item(0)?.textContent
                if (artifactId == "jakarta.servlet-api") {
                    dependency.getElementsByTagName("scope").item(0)?.textContent = "provided"
                }
            }
        }
    }
}
