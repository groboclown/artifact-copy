# Writing Your Own Server Kind

Out of the box, `artifact-copy` provides built-in server support for several popular sources.  The settings for each one come from experimentation with how they work, along with following their documentation for best practice or requirements on usage.

You can instead directly construct the low-level mechanics that these server definitions turn into, or you can craft your own server definition.

To create your own, you need to:

- Define a directory for your custom definitions to live.  You'll set this value in your configuration `setup.server-kinds-dir` value.
- Add a directory under that base directory for the server kind.  When using a `server:` definition in your configuration, the `kind` value will map to this directory name.
- Add a `kind.yaml` file in that server kind directory.  This says the supported repository types and how they relate to the server.
- Add the template files that `kind.yaml` names: one for the server, and one or more for its repository kinds.

The built-in kinds live in [server-kinds/](../server-kinds/) and make good starting points.  A directory in `setup.server-kinds-dir` with the same name as a built-in kind replaces that built-in kind as a whole.

The rest of this file shows an example of building up an imaginary server technology named "gitea" into a new server kind.

## Layout

```text
my-kinds/                  <- setup.server-kinds-dir
  gitea/                   <- servers.*.kind: gitea
    kind.yaml              manifest; not rendered
    server.yaml.hbs        rendered once per server
    maven.yaml.hbs         rendered once per repository of kind "maven"
    npm.yaml.hbs           rendered once per repository of kind "npm"
```

A relative `setup.server-kinds-dir` is taken against the configuration file that declares it.

## How a server becomes configuration

Each server generates one host, named for the server's alias.  Each of its repositories generates a source, a target, and an enumerator, all named for the repository's alias.  The alias is what you pass on the command line.

```yaml
servers:
  gitea:                       # host "gitea"
    kind: gitea
    url: https://gitea.example.com/
    repositories:
      libs:                    # source, target, and enumerator "libs"
        kind: maven
```

The generated entries are ordinary `hosts`, `sources`, `targets`, and `enumerators` entries.  If one has the same name as an entry you wrote yourself, loading fails, unless your entry sets `override-template: true`, in which case yours is used instead.

## The manifest: `kind.yaml`

```yaml
description: Gitea package registry
server:
  file: server.yaml.hbs
  values:                      # optional: JSON Schema for servers.*.values
    type: object
    additionalProperties: false
    properties:
      owner:
        type: string
repositories:
  maven:                       # the repository kind users write
    file: maven.yaml.hbs
    roles: [source, target]
  npm:
    file: npm.yaml.hbs
    roles: [source, target]
    values:                    # optional: JSON Schema for repositories.*.values
      type: object
      additionalProperties: false
      properties:
        scope:
          type: string
          default: "@internal"
```

| Field | Required | Meaning |
| --- | --- | --- |
| `description` | no | What the kind is, for people reading the file. |
| `server.file` | yes | The server template. |
| `server.values` | no | A JSON Schema for the server's `values`. |
| `repositories` | no | The repository kinds this server kind supports, keyed by the name users write in a repository's `kind`. |
| `repositories.*.file` | yes | The repository template.  Several repository kinds may name the same file, for example `maven` and `maven2`. |
| `repositories.*.roles` | yes | Which of `source`, `target`, and `enumerator` the template renders.  At least one. |
| `repositories.*.values` | no | A JSON Schema for the repository's `values`. |

Every file named must sit beside `kind.yaml` and end in `.yaml.hbs`.  Any other field is an error.

### Values

`values` lets a user hand your templates settings that the configuration does not otherwise have, such as a raw repository's path mapping.

- Absent `values` in the manifest means the scope accepts none, and a user who gives some gets an error.
- A top-level property's `default` fills in a value the user left out.  Defaults apply before validation.
- A server's values are checked against `server.values`, and a repository's own values against its repository kind's `values`.

## The server template

Rendered once per server.  It may render only these keys:

| Key | Meaning |
| --- | --- |
| `host` | Host settings, the same fields as a `hosts` entry.  Optional. |
| `access` | What the kind permits: a list of `read`, `write`, or `read-write`.  Absent means both.  A public registry lists `[read]`. |
| `default-repository` | A repository used when the server declares none, named for the server.  For a server with exactly one repository, such as Maven Central. |

The generated host combines the template's `host` with the user's server:

- The user's `url` replaces any url the template gives.  One of the two must supply it.
- The user's `authentication` is added.  A template must never declare `authentication`; credentials belong to the user.
- The server's `insecure-transport` replaces the template's.  A kind you write may set it on its host for a server it knows serves plain `http://`; the server entry's own value, `true` or `false`, wins.  No built-in kind sets it.
- The user's `retry` merges over the template's: a user `on-status` rule adds a status code, or replaces the template's rule for the same code.

```yaml
# server.yaml.hbs
access: [read, write]
host:
  retry:
    on-status:
      429:
        honor-retry-after: true
```

## Repository templates

Rendered once per repository of a kind that names the file.  The template renders `source`, `target`, and `enumerator` blocks, each holding the fields of the matching low-level entry.  The blocks it renders must be exactly the manifest's `roles`.

```yaml
# maven.yaml.hbs
source:
  kind: maven
  host-path: {{yaml (concat "api/packages/" values.owner "/maven")}}
target:
  kind: maven
  host-path: {{yaml (concat "api/packages/" values.owner "/maven")}}
```

When the repository is lowered:

- `host` defaults to the server's alias; leave it out.
- The repository's `access` picks the blocks used: `read` keeps `source` and `enumerator`, `write` keeps `target`.  Absent access means everything the server template's `access` permits.
- The user's `source`, `target`, and `enumerator` blocks on the repository deep-merge over yours, the user winning.  Mappings merge by key; anything else is replaced whole.

## What a template can read

| Name | Server template | Repository template |
| --- | --- | --- |
| `server.alias` | yes | yes |
| `server.url`, `server.kind`, `server.retry` | yes, when the user set them | yes, when the user set them |
| `values.*` | the server's values | the server's values, overlaid by the repository's |
| `repository.alias` | no | yes |
| `repository.name` | no | yes; the user's `name`, or the alias |
| `repository.kind` | no | yes |
| `repository.access` | no | yes: `read`, `write`, or `read-write` |

The server's `authentication` is never visible to a template.

## Template syntax

Templates use [Handlebars](https://handlebarsjs.com/guide/).  Keeping to the Mustache subset (variables, `{{#section}}`, and `{{^inverted}}`) keeps them readable by Mustache tooling.

- **Strict**: naming a variable that does not exist is an error, which catches typos.  Guard an optional value with `{{#if values.x}}...{{/if}}`, or give it a `default` in the manifest.
- **No escaping**: output is YAML, so nothing is HTML-escaped; `&` stays `&`.
- **`yaml`** writes a value as a quoted YAML scalar.  Use it for anything the user supplied, so a value holding `:` or `#` stays text instead of changing the document's structure: `name: {{yaml repository.name}}`.
- **`concat`** joins its arguments into one string: `{{yaml (concat "repository/" repository.name)}}`.

## File paths

A relative path in a template's output, such as a host's `license-policy`, is taken against the configuration file that declared the server (for the host) or the repository (for its entries), not against the template's directory.

## When something is wrong

Loading reports every problem at once, naming the server or repository and the template file.  Among them:

- an unknown server kind, or a repository kind the server kind does not support, with the supported choices;
- a manifest with an unknown field, a missing file, or a file outside its directory;
- values that fail the manifest's schema;
- a template that fails to render, renders YAML that does not parse, renders a key it may not, or renders roles other than the manifest's;
- a generated entry that is not a valid host, source, target, or enumerator;
- a repository asking for access the server kind does not permit.
