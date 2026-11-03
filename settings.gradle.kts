pluginManagement {
    includeBuild("build-logic")
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "java-sdk"

include(
    "keycard-oauth",
    "keycard-spiffe",
    "keycard-mcp",
    "keycard-spring-boot-starter",
    "keycard-a2a",
    "keycard-bom",
)
