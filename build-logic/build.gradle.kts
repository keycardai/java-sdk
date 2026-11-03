plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.spotless.gradle.plugin)
    implementation(libs.vanniktech.maven.publish.plugin)
}
