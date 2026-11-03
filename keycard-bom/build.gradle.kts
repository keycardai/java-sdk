plugins {
    `java-platform`
    id("keycard.publishing")
}

description = "Bill of materials that pins every Keycard Java module to one version."

dependencies {
    constraints {
        api(project(":keycard-oauth"))
        api(project(":keycard-spiffe"))
        api(project(":keycard-mcp"))
        api(project(":keycard-spring-boot-starter"))
        api(project(":keycard-a2a"))
    }
}
