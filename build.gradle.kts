import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.3.20-eap-52"
    maven
}

group = "dev.castive"
version = "2.1"

repositories {
    maven { setUrl("https://dl.bintray.com/kotlin/kotlin-eap") }
    maven(url = "https://jitpack.io")
    jcenter()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))

    implementation("com.github.djcass44:log2:3.2")

    implementation("io.javalin:javalin:2.8.0")
    implementation("org.slf4j:slf4j-simple:1.7.25")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.9.8")
    implementation("com.auth0:java-jwt:3.7.0")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.2.0")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.2.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.2.0")
}

tasks.withType<KotlinCompile>().all {
    kotlinOptions.jvmTarget = "1.8"
}
tasks.withType<Test> {
    useJUnitPlatform()
}