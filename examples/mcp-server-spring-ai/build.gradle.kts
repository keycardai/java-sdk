plugins {
    java
    application
}

dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.2"))
    implementation(platform("org.springframework.ai:spring-ai-bom:2.0.2"))
    // Spring AI 2.0's WebMVC MCP server, behind Keycard's starter on Spring Security.
    implementation("org.springframework.ai:spring-ai-starter-mcp-server-webmvc")
    implementation("ai.keycard:keycard-spring-boot-starter:0.1.0-SNAPSHOT")
}

application {
    mainClass.set("example.Application")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
    options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-parameters"))
}

// The hermetic selftest: a stub zone from keycard-oauth's test fixtures plus the MCP SDK client.
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
    description = "Runs the server against a live zone with a real user token."
    classpath = selftest.runtimeClasspath
    mainClass.set("example.LiveE2e")
}
