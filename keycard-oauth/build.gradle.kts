plugins {
    id("keycard.java-library")
    `java-test-fixtures`
}

description = "OAuth 2.0 primitives for Keycard: token exchange, client credentials, workload identity, " +
    "authorization code with PKCE, DCR, discovery, JWT and JWKS verification, and AccessContext."

// Nimbus is the only runtime dependency: JWK/JWT handling plus its JSON
// utilities, so the core takes no position on Jackson 2 versus Jackson 3.
// Other modules' tests share the stub zone in src/testFixtures through
// testImplementation(testFixtures(project(":keycard-oauth"))).
dependencies {
    api(libs.nimbus.jose.jwt)
}

// The stub zone is for this repo's tests only; keep it out of the published
// artifacts.
val javaComponent = components["java"] as AdhocComponentWithVariants
// afterEvaluate because the publishing plugin adds the sources variant late.
afterEvaluate {
    listOf("testFixturesApiElements", "testFixturesRuntimeElements", "testFixturesSourcesElements")
        .mapNotNull { configurations.findByName(it) }
        .forEach { javaComponent.withVariantsFromConfiguration(it) { skip() } }
}
