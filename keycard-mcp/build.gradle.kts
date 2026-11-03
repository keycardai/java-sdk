plugins {
    id("keycard.java-library")
}

description = "Keycard auth for MCP servers on Jakarta Servlet: bearer enforcement (RFC 6750), " +
    "OAuth metadata endpoints (RFC 9728 and RFC 8414), and delegated token exchange."

dependencies {
    api(project(":keycard-oauth"))
    testImplementation(testFixtures(project(":keycard-oauth")))
}
