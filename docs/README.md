# artifact-copy User Guide

The main [readme](../README.md) file contains the primary source for how to use this tool.

You can find detailed information about building your artifact server configurations in the guides:

- [General settings](configuration-general.md) for server agnostic settings.  This includes items important to security.
- For each server kind, we have specific guides to help you configure it:
    - [Artifact Keeper](configuration-artifact-keeper.md)
    - [Artifactory](configuration-artifactory.md)
    - [Nexus](configuration-nexus.md)
    - [Local directory](configuration-local-directory.md)
    - [Public repositories](configuration-public.md)
- The common repository types (regardless of the hosting server) have their own specific settings:
    - [Maven 2 style](configuration-maven2.md)
    - [NPM style](configuration-npm.md)
    - [PyPI style](configuration-pypi.md)
    - [Raw and generic](configuration-raw.md)
- Servers have [shared settings](configuration-server.md).
- Servers generate [low-level hosts, sources, targets, and enumerators](configuration-low-level.md), which advanced configurations can tune or write directly.

If you plan on using artifact-copy for more than a one-off run, you may be interested in:

- [Working with the progress database](progress-db.md)
- [Report output](reports.md)
- [Security assumptions](security.md): what the tool guards against, and what it leaves to you
- [References](references.md): the external specifications and APIs this tool implements

To add to the functionality that artifact-copy provides:

- [Write new server helpers](custom-server-kinds.md)
- [Writing custom extensions](extensions.md)

For information on using the code here as a library, see the documentation on [how to embed it in your own project](embedding-guide.md).
