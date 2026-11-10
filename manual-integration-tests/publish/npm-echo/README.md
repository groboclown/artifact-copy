# Node.js Echo

**FOR EXAMPLE ONLY** DO NOT PUBLISH PUBLICLY.

This example only populates the local integration artifact servers with sample data.  Its `dependencies` and `engines` exist so a copy can be checked for keeping the published manifest; nothing installs it.

Publish with the scripts, which write a temporary `.npmrc` holding the publish user's credentials:

```sh
../../tests/030-publish-npm-nexus.sh
../../tests/031-publish-npm-ak.sh
```
