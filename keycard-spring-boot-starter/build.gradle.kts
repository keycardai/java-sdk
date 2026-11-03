plugins {
    id("keycard.java-library")
}

description = "Spring Boot auto-configuration for Keycard: a Keycard-backed JwtDecoder, protected " +
    "resource metadata, and AccessContext injection."

dependencies {
    api(project(":keycard-oauth"))
    testImplementation(testFixtures(project(":keycard-oauth")))
}
