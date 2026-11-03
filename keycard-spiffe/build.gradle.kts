plugins {
    id("keycard.java-library")
}

description = "SPIFFE JWT-SVID identity token source for Keycard workload identity. " +
    "A separate module so keycard-oauth never pulls in gRPC."

dependencies {
    api(project(":keycard-oauth"))
}
