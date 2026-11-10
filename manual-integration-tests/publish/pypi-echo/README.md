# Python Echo

**FOR EXAMPLE ONLY** DO NOT PUBLISH PUBLICLY.

This example is only for populating the local, integration artifact servers with sample data.

## Using

Build and upload only to the local Nexus PyPI repository:

```sh
python3 -m pip install '.[publish]'
make publish
```

The upload command prompts for the Nexus publishing credentials from [`manual-integration-tests/setup/nexus/.env`](../../setup/nexus/.env).

You can swap out the server to the Artifact Keeper host by running:

```sh
make publish PYPI_UPLOAD_URL=http://localhost:8083/pypi/pypi-a/
```

and pointing to the credentials under [`manual-integration-tests/setup/artifact-keeper/.env`](../../setup/artifact-keeper/.env).
