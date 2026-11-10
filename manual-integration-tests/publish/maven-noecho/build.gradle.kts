plugins {
    `java-library`
    `maven-publish`
}

group = "example.lib"
version = "1.0"

java {
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }

    repositories {
        maven {
            name = "localServer"
            url = uri(System.getProperty("REPO_URL"))
            isAllowInsecureProtocol = true

            credentials(PasswordCredentials::class) {
                username = providers.environmentVariable("PUBLISH_USER").orNull
                password = providers.environmentVariable("PUBLISH_PASSWORD").orNull
            }
        }
    }
}
