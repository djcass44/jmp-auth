import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
	kotlin("jvm") version "1.3.60"
	maven
}

group = "dev.castive"
version = "0.6.6"

repositories {
	mavenCentral()
	jcenter()
	maven(url = "https://jitpack.io")
}

val junitVersion: String by project

dependencies {
	implementation(kotlin("stdlib-jdk8"))

	implementation("com.github.djcass44:log2:3.4")
	implementation("com.github.djcass44:castive-utilities:v3")

	api("io.javalin:javalin:3.6.0")
	implementation("org.slf4j:slf4j-simple:1.7.26")
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.10.0")
	implementation("com.google.code.gson:gson:2.8.5")
	
	implementation("com.auth0:java-jwt:3.7.0")
	implementation("com.auth0:jwks-rsa:0.8.1")
	// cant be opened by consumers
	implementation("com.github.scribejava:scribejava-apis:6.8.1")

	// Networking
	val fuelVersion = "2.1.0"
	implementation("com.github.kittinunf.fuel:fuel:$fuelVersion")
	implementation("com.github.kittinunf.fuel:fuel-coroutines:$fuelVersion")
	implementation("com.github.kittinunf.fuel:fuel-gson:$fuelVersion")

	testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
	testImplementation("org.junit.jupiter:junit-jupiter-params:$junitVersion")
	testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")

	testImplementation("org.hamcrest:hamcrest:2.2")
	testImplementation("org.mockito:mockito-core:3.0.0")
	testImplementation("org.jetbrains.kotlin:kotlin-test")
}
tasks {
	wrapper {
		gradleVersion = "5.6.4"
		distributionType = Wrapper.DistributionType.ALL
	}
	withType<KotlinCompile>().all {
		kotlinOptions.jvmTarget = "11"
	}
	withType<Test> {
		useJUnitPlatform()
	}
}