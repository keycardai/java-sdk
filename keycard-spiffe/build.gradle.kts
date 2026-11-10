plugins {
    id("keycard.java-library")
}

description = "SPIFFE JWT-SVID identity token source for Keycard workload identity. " +
    "A separate module so keycard-oauth never pulls in gRPC."

// java-spiffe-core reaches the Workload API over gRPC and needs a native
// transport at runtime, which the application picks for its platform:
// io.spiffe:grpc-netty-linux, grpc-netty-macos or grpc-netty-macos-aarch64.
dependencies {
    api(project(":keycard-oauth"))
    api(libs.java.spiffe.core)

    testImplementation(testFixtures(project(":keycard-oauth")))
}
