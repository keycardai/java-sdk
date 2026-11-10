plugins {
    java
}

dependencies {
    implementation("ai.keycard:keycard-oauth:0.1.0-SNAPSHOT")
    implementation("ai.keycard:keycard-spiffe:0.1.0-SNAPSHOT")
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
