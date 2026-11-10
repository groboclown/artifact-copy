# Contributor Documentation

Why the code is shaped the way it is. [TODO.md](../../TODO.md) holds what is *left to do*; these files hold what was *settled*, so a decision that looks arbitrary a year from now can be checked rather than re-litigated.

| File | Subject |
| --- | --- |
| [../references.md](../references.md) | The external specifications and APIs the code implements, and [`external/`](../../external/README.md) for their machine-readable definitions |
| [exit-codes.md](exit-codes.md) | The exit-code rule with its worked examples |
| [extensions.md](extensions.md) | Extension points and the extension mechanism architecture |
| [trade-offs.md](trade-offs.md) | Maven work-arounds, and why the project has a boring name |
| [run-outcomes.md](run-outcomes.md) | What makes a run succeed or fail: reachability and severity, and the three meanings of `pom-property-unresolved` |
| [configuration.md](configuration.md) | Where a rule lives -- configuration versus policy file -- and how a relative path resolves |
| [module-layout.md](module-layout.md) | Why modules sit where they do, what must not be merged, and the `core` / `internal` split |
| [adding-a-kind.md](adding-a-kind.md) | Where to edit when adding a server, corpus, ecosystem, format, or other named choice, and the test that guards each step |
| [wiring.md](wiring.md) | Sessions, hosts, capabilities, and the credential leak that decided when binding happens |
| [sources-and-targets.md](sources-and-targets.md) | Repository managers, proxies, GitHub releases, raw repositories |
| [resolution.md](resolution.md) | Turning a request into one exact version, and the publish window |
| [versions.md](versions.md) | `VersionHandler`, and which repositories may declare one |
| [verification.md](verification.md) | Checksums, signatures, keys, expiry, and revocation |
| [advisories.md](advisories.md) | Vulnerability and malware screening: the record shape, the index, and the corpora |
| [licensing.md](licensing.md) | Where the license policy is evaluated and where the verdict lives |
| [quarantine.md](quarantine.md) | Soft versus hard, the four classes, and the per-code defaults |
| [write-path.md](write-path.md) | Upload capabilities, the npm and Maven targets, `copy`, and `dist-tags` |
| [several-targets.md](several-targets.md) | Plan: one `copy` publishing to several targets, fetching each payload once |
| [user-limits.md](user-limits.md) | Decisions that limit what a user can do, where each lives in code, and what an option would look like |
| [reporting.md](reporting.md) | How problems reach a report as they occur |
| [logging.md](logging.md) | The log versus the report, the tee between them, levels and flags, and progress bars |
| [server-behaviors.md](server-behaviors.md) | What Nexus, Artifactory, and public services did when probed |
| [artifact-keeper-api.md](artifact-keeper-api.md) | REST reference behind the Artifact Keeper enumerator, source, and target |

User-facing documentation lives one directory up: [reports.md](../reports.md), [extensions.md](../extensions.md), and [embedding-guide.md](../embedding-guide.md).
