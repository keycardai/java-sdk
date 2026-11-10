// A separate build that consumes the SDK from source through a composite build.
rootProject.name = "a2a-delegation"

includeBuild("../..")

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}
