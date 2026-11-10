// A separate build that consumes the SDK from source through a composite build,
// the Gradle analog of Bundler's path: gem.
rootProject.name = "engine-obo"

includeBuild("../..")

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}
