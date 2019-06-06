import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
	kotlin("jvm") version "1.3.30"
	maven
}

group = "dev.castive"
version = "0.3.3"

repositories {
	mavenCentral()
	jcenter()
	maven(url = "https://jitpack.io")
}

dependencies {
	implementation(kotlin("stdlib-jdk8"))

	implementation("com.github.djcass44:log2:3.3")

	implementation("io.javalin:javalin:2.8.0")
	implementation("org.slf4j:slf4j-simple:1.7.25")
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.9.8")
	
	implementation("com.auth0:java-jwt:3.7.0")
	implementation("com.auth0:jwks-rsa:0.8.1")

	implementation("com.microsoft.graph:microsoft-graph:1.3.0")

	// Networking
	implementation("com.github.kittinunf.fuel:fuel:2.1.0")
	implementation("com.github.kittinunf.fuel:fuel-coroutines:2.1.0")
	implementation("com.github.kittinunf.fuel:fuel-gson:2.1.0")

	testImplementation("org.junit.jupiter:junit-jupiter-api:5.2.0")
	testImplementation("org.junit.jupiter:junit-jupiter-params:5.2.0")
	testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.2.0")
}

tasks.withType<KotlinCompile>().all {
	kotlinOptions.jvmTarget = "11"
}
tasks.withType<Test> {
	useJUnitPlatform()
}