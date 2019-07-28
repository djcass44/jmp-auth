import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
	kotlin("jvm") version "1.3.30"
	maven
//	jacoco
//	id("org.sonarqube") version "2.7.1"
}

group = "dev.castive"
version = "0.4.0"

repositories {
	mavenCentral()
	jcenter()
	maven(url = "https://jitpack.io")
	maven(url = "https://dl.bintray.com/nitram509/jbrotli/")
}

dependencies {
	implementation(kotlin("stdlib-jdk8"))

	implementation("com.github.djcass44:log2:3.3")

	implementation("io.javalin:javalin:3.2.0")
	implementation("org.slf4j:slf4j-simple:1.7.25")
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.9.8")
	
	implementation("com.auth0:java-jwt:3.7.0")
	implementation("com.auth0:jwks-rsa:0.8.1")

	implementation("com.microsoft.graph:microsoft-graph:1.3.0")
	implementation("com.github.scribejava:scribejava-apis:6.7.0")

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
//tasks.jacocoTestReport {
//	reports {
//		xml.isEnabled = true
//	}
//}
//sonarqube {
//	properties{
//		property("sonar.projectKey", "djcass44:jmp-auth")
//		property("sonar.projectName", "djcass44/jmp-auth")
//	}
//}