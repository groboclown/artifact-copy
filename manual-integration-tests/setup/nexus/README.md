# Setup Details

The `docker-compose.yml` file will start up Nexus and its dependent services, then run another container to configure the server to add raw, NPM, Python, Maven, and Cargo repositories.

```
../sctl.sh start nexus
../sctl.sh logs nexus
```

Nexus takes one to three minutes to become ready on a first run; the configure container waits for it and then reports what it did.  It is safe to re-run: every step checks before it creates, so a second run changes nothing.

It also creates the two non-admin accounts (`am-reader` and `am-publisher`) with roles to match.

When the server first starts up, you need to accept the EULA in order to use the server.  You can accept it with the [accept-eula.sh](accept-eula.sh) script.

## Configured Repositories

This creates three hosted repositories per format at startup time, named `{format}-a`, `{format}-b`, and `{format}-c`:

* `raw-*` - raw repositories.
* `npm-*` - NPM repositories.
* `pypi-*` - PyPI repositories.
* `maven-*` - Maven2 compatible repositories.
* `cargo-*` - Cargo repositories.  Added for future testing purposes.

## Anonymous Access

Anonymous access is **on** for every `-a` repository.  The `-b` and `-c` repositories need a user.  Publishing (general repository write access) requires using the publish user for all repositories.

This allows for testing out anonymous-capable reads vs. authenticated reads.

The configuration does this by creating one privilege per `-a` repository, putting them in a role of their own, and moving the built-in `anonymous` user onto that role - away from Nexus's stock `nx-anonymous`, which carries wildcard read over every repository.  A re-run does not update an existing role, so a changed `NEXUS_FORMATS` needs a fresh server (`docker compose down -v`).

The [`configure.sh`](configure.sh) script reads these from the `.env` file:

* `NEXUS_VERSION` pins the image, which is unpinned by default.  Cargo needs a recent Nexus release; if the configure container reports that the format is unsupported, set this to a newer tag.
* `NEXUS_FORMATS` chooses which repositories to create.  It defaults to `raw npm pypi maven cargo`.
