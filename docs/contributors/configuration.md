# Configuration Shape

Where a rule lives, and how a path in a configuration file resolves. Both were patterns already in the code before anyone named them; writing them down is what makes the next rule land in the right place.

## Globals, Per Repository, and Per Artifact

The tool has three general scopes of configuration that overlap:

* Globals - define the general defaults for operation.  These summarize common rules that everything follows.
* Repository - settings on a repository that may differ depending on how reliable the configurator considers the environment.  Some public repositories may have a wide publish window because it has a history of malware publications, while internal ones may be trusted right away.
* Per-artifact - settings on an artifact + version range to allow explicit overrides.

The first two - globals + repository - live in the user configuration files.  The last one - per-artifact - always lives is their own override policy file, though their shape depends upon the kind of evaluation.  Overriding CVE score limitations may be allowed based on VEX (Vulnerability Exploitability eXchange) documents.

## Where a rule lives

> **Configuration says what the rules are. Separate policy files say which artifacts are exceptions to them.**

The configuration holds nothing keyed by an artifact -- today, literally nothing: there is not one purl-shaped key anywhere in `config::model`. Broad settings live there (`unknown-publish-time`, `minimum-publish-time`, the malware and vulnerability stances, and the `problem-policy` table of per-code defaults), and the configuration also says *where the policy files are*.

Per-artifact rules live in those files, and all three have the same shape. The security policy holds none: it keeps only the organization-wide `malware` and `vulnerabilities` stances, and a VEX statement about specific artifacts arrives with the request, as a `--lock` document. See [advisories.md](advisories.md#vex-documents-belong-with-the-lock-files).

| File | Per-artifact rule | Keyed by |
| --- | --- | --- |
| license policy | `ArtifactRule` | `purl` |
| quarantine policy | override, either direction | `purl` + code |
| signing policy | which keys may vouch | `purl` |

Three properties fall out, and they are the reason the split is worth keeping rather than a coincidence worth tidying away:

- **An exception is reviewable on its own.** A file of nothing but "these specific artifacts are excused, and why" reads in a pull request; the same entries buried among host definitions and timeouts do not.
- **An exception carries a justification.** Every existing rule has a `ref` or reference field and comment fields, because an exception without a reason is one nobody can later re-evaluate. Anything new here should keep that.
- **The two have different lifetimes.** A configuration is edited when the setup changes. An exception list is edited when a specific artifact is reviewed, which is far more often and usually by a different person.

It also decides questions directly. `license-forbidden` is classified as a failure rather than a quarantine precisely because license exceptions already have a home: the license policy file. Adding a second way to excuse the same artifact would mean two places to look and two that can disagree.

License, security, quarantine, and signing policies are meant to sit in the `setup` section, but all four can have `host` overrides. A specific host override should be rare, yet a user may have a condition like "this is a name-confusion attack" that applies to a public server and not to an internal one.

## Explicit path rules

When a configuration file references another filesystem path, the user can select two different options - either load the file relative to the invocation working directory (`working-dir-path`) or relative to the current configuration file (`config-relative-path`).  Both have their uses, and this distinction gives the user full control over the selection (though, regrettably, verbose).  The configuration also allows for a third path, `command`, that uses the operating system command discovery resolution.

| What | Relative to |
| --- | --- |
| `working-dir-path` | the working directory |
| `config-relative-path` | the file that declared it |
| `extensions.*.command` | neither; the operating system resolves it |
| `host-path` | relative to a URI scheme + host + optional port |

### How the second rule is implemented

In the loader, per document, **before** `merge_first_wins`. That is the only moment it is possible: afterwards the merged document is one object with no record of which file any key came from, which is exactly what `Config.base_dir`'s doc said when it argued for a single base. The premise was right and the conclusion did not follow -- acting earlier makes the better rule reachable.

`Config::base_dir`, `set_base_dir`, and `resolve_path` were then deleted. Every path reaching `Config` is already absolute, so keeping them would have left a second, contradictory rule in the code.

`SecretValue::resolve_in` was deleted too. Secrets resolve against the working directory by design, so an API for resolving them against some other base is a trap: the next reader wires it up and silently changes where credentials are read from.

### The command is not a file path

`extensions.*.command` uses `Command`, not `ConfigRelativePath`: anchoring `command: python3` would make it mean `<config-dir>/python3` and stop installed interpreter lookup.

### The guard, and why the first version of it was useless

The anchored routes form a hand-written list. A test walks `schema/config.schema.json`, resolves each `$ref: ConfigRelativePath` to the document route a user writes, and asserts agreement.

The first attempt compared only the **last segment** of each route. That missed duplicate `path` keys. Path-bearing objects accept either explicit key, but schema `oneOf` rules reject both together. Whole-route comparison remains the anchoring guard.
