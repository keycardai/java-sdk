// Conventions for every published Keycard library module: Java 17 bytecode,
// strict compiler and Javadoc checks, JUnit, formatting, and Maven Central
// publishing.

plugins {
    `java-library`
    id("com.diffplug.spotless")
    id("keycard.publishing")
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

fun lib(alias: String) = libs.findLibrary(alias).get()

// The build compiles on whatever JDK runs Gradle; --release pins the API
// surface and bytecode to Java 17. CI runs the build on 17, 21 and 25.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror", "-parameters"))
}

tasks.withType<Javadoc>().configureEach {
    // javadoc errors on a module holding only package-info.java, which is every
    // module until its first ticket lands. The javadoc jar is then empty.
    onlyIf("module has classes to document") {
        (it as Javadoc).source.any { file -> file.name != "package-info.java" }
    }
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        addBooleanOption("Xdoclint:all", true)
        addBooleanOption("Werror", true)
        addStringOption("-release", "17")
    }
}

dependencies {
    api(lib("jspecify"))

    testImplementation(platform(lib("junit-bom")))
    testImplementation(lib("junit-jupiter"))
    testImplementation(lib("assertj-core"))
    testRuntimeOnly(lib("junit-platform-launcher"))
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.jar {
    manifest {
        // ai.keycard.<module>, matching the module's root package
        // (keycard-spring-boot-starter -> ai.keycard.spring.boot).
        val moduleName = "ai.keycard." +
            project.name.removePrefix("keycard-").removeSuffix("-starter").replace('-', '.')
        attributes("Automatic-Module-Name" to moduleName)
    }
}

// The MIT notice has to travel with every copy, and the POM only names the
// license, so each jar (classes, sources, Javadoc) carries the text itself.
// The base Jar type, because the publishing plugin's Javadoc jar isn't the
// java plugin's bundling Jar.
val licenseFile = rootProject.layout.projectDirectory.file("LICENSE")
tasks.withType<org.gradle.jvm.tasks.Jar>().configureEach {
    from(licenseFile) { into("META-INF") }
}

spotless {
    java {
        palantirJavaFormat(libs.findVersion("palantir-java-format").get().requiredVersion)
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
}
