plugins {
    java
    application
}

val a2aJava = "1.5.1.Final"

dependencies {
    implementation("ai.keycard:keycard-a2a:0.1.0-SNAPSHOT")
    implementation("ai.keycard:keycard-mcp:0.1.0-SNAPSHOT")
    implementation("org.eclipse.jetty.ee10:jetty-ee10-servlet:12.1.14")
    // Agent B speaks A2A through the official a2a-java SDK: its spec types and its
    // JSON-RPC codec parse what agent A sends and serialize the reply.
    implementation("org.a2aproject.sdk:a2a-java-sdk-spec-grpc:$a2aJava")
    implementation("com.google.protobuf:protobuf-java-util:4.36.2")
    runtimeOnly("org.slf4j:slf4j-simple:2.0.17")
}

application {
    mainClass.set("example.Agents")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
    options.compilerArgs.addAll(listOf("-Xlint:deprecation"))
}

// The hermetic selftest: a stub zone that performs a real RFC 8693 exchange.
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
    description = "Runs both agents against a stub zone and checks identity flow-through."
    classpath = selftest.runtimeClasspath
    mainClass.set("example.SelfTest")
}

tasks.register<JavaExec>("liveE2e") {
    description = "Runs both agents against a live zone with a real user token."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("example.LiveE2e")
}
