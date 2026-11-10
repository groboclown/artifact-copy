# Version Handling

Version parsing, ordering, pre-release classification, and range matching are `version::VersionHandler`, its own trait over `model` alone, with four named handlers behind `version::open(kind)`:

| Kind | What it is | Was |
| --- | --- | --- |
| `semver` | node-semver, npm's dialect and not Cargo's | `ecosystem::Npm` |
| `maven` | `ComparableVersion` plus bracketed ranges | `ecosystem::Maven` |
| `pep440` | Python's scheme | `ecosystem::PyPi` |
| `tags` | names with no order; refuses every range | `ecosystem::GitHub`, since removed |

Each ecosystem **delegates** to its handler rather than implementing one, and `Ecosystem` requires `VersionHandler` so no call site changed. A test asserts each ecosystem and its named handler give the same answers, so the delegation cannot rot into two implementations.

A source may name one with `version-handler`, a closed set the schema enumerates and `validate-config` resolves. Absent means *the ecosystem's own*, which is what every configuration written before the key existed says -- so saying nothing behaves exactly as it did.

## Only a repository whose contents decide may declare one

`repo::version_scheme(kind)` answers `Fixed` or `Declared`, and `validate-config` **refuses** `version-handler` on a `Fixed` kind.

Every registry adapter is `Fixed`. npm *is* semver, Maven *is* `ComparableVersion`, PyPI *is* PEP 440 -- each is decided by the ecosystem the adapter speaks, so a configuration disagreeing is not expressing a preference, it is being wrong. Ignoring the setting would be worse than refusing it: the run would resolve a plausible-looking wrong artifact instead of failing where somebody can see it.

`github` is `Declared`, because a tag is text its publisher chose. `nexus`, `artifactory`, and `artifact-keeper` with `ecosystem: raw` and `mapping: name-version-file` are the same case and more so. Under `directory` or `as-is` they are `Fixed`: those mappings read no version, so a handler would order nothing, and accepting one would be a setting silently ignored.

An **unknown kind answers `Fixed`**, so an extension's source cannot be handed a handler this tool would then not apply -- a refused setting is visible and a silently ignored one is not. That is the conservative direction. An extension instead declares its scheme in its `describe` answer (`version-scheme`), and `ExtensionSource::version_handler` answers with it.

## The fallback, and where it bites

`Source::version_handler(id)` answers *how do this repository's versions order*: the artifact's ecosystem by default, and the declared handler when `repo::Bound` carries one. `Source::resolve` consults it, which is what makes the key take effect rather than merely validate -- selection is the only thing resolution needs from either, and selection is exactly what a version convention decides. `session::ConfiguredSource::versions` asks the same method, so the accessor and resolution cannot disagree.

Every `Ecosystem` is a `VersionHandler`, which is what makes the fallback a substitution rather than a special case.

**`Bound` forwards `resolve` only without a handler, and the reason is worth keeping.** An earlier version always delegated it to the inner source, which was a bug with no symptom until a handler was configured: the default body asks `self` how versions order, so delegating meant the *inner* source answered and the declared handler was resolved, validated, and ignored. The next version never delegated, assuming a direct source has no `resolve` of its own -- false for `github`, whose override then never ran in a configured run. So with a handler the default body runs against `self`, and without one the inner source decides, which for a source with no override is the same body against the same handler. A source that overrides `resolve` gets the standard step-down loop under a handler; its `versions` and `metadata` still answer, so only the selection algorithm changes.

**An exact request is re-read under the handler.** The ecosystem parsed the request, and raw reads every `@x` as exact, so the shared resolution loop passes an exact spec back through `version_spec`: under `semver`, `tool@24` becomes a range for the newest `24.x.y`, and `tool@24.1.0` stays exact. It lives in the shared loop, not a source's `resolve`, because a wrapper such as `InventorySource` runs that loop itself. A registry ecosystem parsed with the same handler's rules, so the re-read changes nothing there.

**Per artifact, not per source**, which was not obvious until the fallback had somewhere to live: a repository manager serves Maven, npm, and PyPI from one host, and those three order versions differently, so *which* convention applies is a question about the artifact. A source speaking one ecosystem answers the same every time, which is the common case and costs nothing.

One consequence worth knowing: an artifact whose ecosystem the source does not speak is an **error** under the fallback and is **answered** under a declared handler. That is right in both directions -- the ecosystem path is asking the source a question it can refuse, and the declared path is the user having said which convention this repository follows, which is not an ecosystem question.

## What it buys

- A raw repository under `mapping: name-version-file` configures `version-handler: semver` and gets ordering without pretending to be npm.
- A GitHub repository whose tags happen to be semver says so, instead of `GitHubSource` refusing every range because *tags in general* have no order.
- The ecosystem keeps the part that is genuinely ecosystem-shaped: coordinate syntax and identity.

Not an extension point: the built-in handlers are expected to cover a wide range of conventions, and the added flexibility would not outweigh the complexity. An embedder that needs its own supplies an `Ecosystem`, which is one.

**One coupling is worth knowing**, since it shaped the split: npm's and PyPI's `parse_req` need version-spec parsing, because `lodash@^4.17.0` and `requests>=2` cannot be split without it. They call their handler rather than the parser being duplicated on both sides.
