plugins {
    java
    application
}

dependencies {
    implementation("ai.keycard:keycard-mcp:0.1.0-SNAPSHOT")
    implementation("ai.keycard:keycard-oauth:0.1.0-SNAPSHOT")
    // The official MCP Java SDK and its Streamable HTTP servlet transport.
    implementation("io.modelcontextprotocol.sdk:mcp:2.1.0")
    implementation("org.eclipse.jetty.ee10:jetty-ee10-servlet:12.1.14")
    runtimeOnly("org.slf4j:slf4j-simple:2.0.17")
}

application {
    mainClass.set("example.Server")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
    options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Werror"))
}

// The hermetic selftest: a stub zone from keycard-oauth's test fixtures plus the
// MCP SDK's own client, so it needs no network and no live zone.
val selftest: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets["main"].output
    runtimeClasspath += sourceSets["main"].output
}
configurations[selftest.implementationConfigurationName].extendsFrom(configurations.implementation.get())
configurations[selftest.runtimeOnlyConfigurationName].extendsFrom(configurations.runtimeOnly.get())
dependencies {
    "selftestImplementation"(testFixtures("ai.keycard:keycard-oauth:0.1.0-SNAPSHOT"))
}

tasks.register<JavaExec>("selftest") {
    description = "Runs the server against a stub zone and drives it with the MCP client."
    classpath = selftest.runtimeClasspath
    mainClass.set("example.SelfTest")
}

tasks.register<JavaExec>("liveE2e") {
    description = "Runs the server against a live zone and drives it with a real user token."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("example.LiveE2e")
}
