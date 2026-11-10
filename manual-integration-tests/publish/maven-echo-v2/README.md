# Maven Echo

Start the local Nexus server, load its publishing credentials, then publish:

```sh
set -a
. ../../setup/nexus/.env
set +a
gradle publish
```

The Gradle publication uploads only to `http://localhost:8081/repository/maven-a`.
