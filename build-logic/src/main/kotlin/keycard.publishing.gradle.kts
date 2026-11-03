// Maven Central publishing for library and BOM modules. The plugin adds the
// sources and javadoc jars Central requires and uploads through the Central
// Portal. Signing turns on only when a key is configured, so local builds and
// publishToMavenLocal work without one.

plugins {
    id("com.vanniktech.maven.publish")
}

mavenPublishing {
    publishToMavenCentral()

    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    coordinates(project.group.toString(), project.name, project.version.toString())

    pom {
        name.set(project.name)
        description.set(provider { project.description ?: project.name })
        url.set("https://github.com/keycardai/java-sdk")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/license/mit")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("keycardai")
                name.set("Keycard Labs, Inc.")
                url.set("https://keycard.ai")
            }
        }
        scm {
            url.set("https://github.com/keycardai/java-sdk")
            connection.set("scm:git:https://github.com/keycardai/java-sdk.git")
            developerConnection.set("scm:git:ssh://git@github.com/keycardai/java-sdk.git")
        }
    }
}
