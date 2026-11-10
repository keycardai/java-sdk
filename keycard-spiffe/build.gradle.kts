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
    // gRPC brings Guava 33.5.0, inside the range of GHSA-xxph-c9ww-hj94 (CompactHashMap
    // deserialization, fixed in 33.7.2). A direct dependency, not a
    // constraint, so Maven consumers resolve the patched version too.
    runtimeOnly(libs.guava)

    testImplementation(testFixtures(project(":keycard-oauth")))
}
