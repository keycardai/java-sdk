// A separate build that consumes the SDK from source through a composite build.
rootProject.name = "mcp-server-servlet"

includeBuild("../..")

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}
