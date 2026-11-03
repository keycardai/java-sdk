plugins {
    id("keycard.java-library")
}

description = "Keycard agent-to-agent delegation: agent card discovery, per-hop token exchange, " +
    "and JSON-RPC invocation."

dependencies {
    api(project(":keycard-oauth"))
    testImplementation(testFixtures(project(":keycard-oauth")))
}
