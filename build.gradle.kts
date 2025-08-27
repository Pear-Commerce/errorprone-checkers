plugins {
  `java-library`
  `maven-publish`
}

java.sourceCompatibility = JavaVersion.VERSION_21
java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
}

repositories {
  mavenCentral()
}

dependencies {
    compileOnly("com.google.errorprone:error_prone_annotations:2.27.1")
    compileOnly("com.google.errorprone:error_prone_core:2.27.1")
    // provide com.sun.tools.javac.* at compile time:
    compileOnly("com.google.errorprone:javac:9+181-r4173-1")
    compileOnly("com.google.auto.service:auto-service-annotations:1.1.1")
    annotationProcessor("com.google.auto.service:auto-service:1.1.1")

    // (optional) tests
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.errorprone:error_prone_test_helpers:2.27.1")
}

tasks.withType<JavaCompile>().configureEach {
  options.encoding = "UTF-8"
}

publishing {
  publications {
    create<MavenPublication>("mavenJava") {
      from(components["java"])
      // JitPack will publish as com.github.<user>:errorprone-checkers:<tag>
      groupId = "com.pearcommerce"
      artifactId = "errorprone-checkers"
      version = "0.0.0"
    }
  }
}
