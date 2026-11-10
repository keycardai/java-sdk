plugins {
    java
    application
}

dependencies {
    implementation("ai.keycard:keycard-oauth:0.1.0-SNAPSHOT")
    implementation("ai.keycard:keycard-spiffe:0.1.0-SNAPSHOT")
    // The Workload API path runs in a Linux container; java-spiffe needs a
    // native gRPC transport for the agent's Unix socket.
    runtimeOnly("io.spiffe:grpc-netty-linux:0.8.17")
}

// installDist lays out build/install/engine-obo/lib for the container run.
application {
    mainClass.set("example.LiveE2e")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

// Each task reads its configuration from the environment that bin/ scripts set.
tasks.register<JavaExec>("signIn") {
    description = "Signs a user in through the browser and stores the access token."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("example.SignIn")
    standardInput = System.`in`
}

tasks.register<JavaExec>("liveE2e") {
    description = "Runs BNY's engine flow against a live zone."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("example.LiveE2e")
}

tasks.register<JavaExec>("deviceE2e") {
    description = "Runs the device authorization grant against a live zone; pass the mode with --args."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("example.DeviceE2e")
    standardInput = System.`in`
}

tasks.register<JavaExec>("onboardingE2e") {
    description = "Runs credential discovery and client registration against a live zone."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("example.OnboardingE2e")
}
