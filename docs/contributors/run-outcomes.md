# What a Successful Run Means

Reasoning behind the exit-code rule and the problem classification that feeds it. The rule itself, with its worked examples, is in [exit-codes.md](exit-codes.md); this file holds what was settled while implementing it.

## The principle

> **A run succeeded if everything the user named was copied. What the tool reached on its own is reported, not failed.**

A user who asks for `pkg:npm/app@1.2.3` and gets a zero exit is entitled to assume it copied. A user who asks for the same thing and gets a non-zero exit because a dev dependency thirty levels down carries a license the policy dislikes has been told their request failed, when it did not -- and the reliable consequence of that is a pipeline that stops reading exit codes.

## Two axes, not one

Every `Problem` carries a `Provenance`, and its immediate `Cause` says how that artifact was reached:

| `Cause` | The user | Counts toward failure |
| --- | --- | --- |
| `Requested` | named it on the command line | yes |
| `LockFile` | named it in a file they supplied | yes |
| `Enumerated` | pointed at a repository and said "this lot" | yes |
| `Dependency` | did not name it; the spider found it | **it depends** |

It is the **immediate** cause, not the root: a chain always roots at something the user named, so the root would call everything a failure.

### Provenance is necessary and not sufficient

A first cut made `Dependency` simply never fail, and that is wrong. From [exit-codes.md](exit-codes.md), the cases side by side:

| What happened | Failure? |
| --- | --- |
| the *requested* artifact was not found | yes |
| a **test** dependency ten layers down was not found | no |
| a **direct runtime** dependency has an unreadable POM | no |
| a **direct runtime** dependency is known **malware** | yes |

So a problem on a dependency can still fail the run, and *how it was reached* is not the whole answer.

**The second axis is severity, not necessity, and the examples settle it.** Rows three and four hold reachability, kind, and depth constant and vary only the code. One fails and one does not, so the discriminator is the code. Nothing in the example set separates a runtime dependency from a test one: both of those rows come out reported.

That was not the first reading. An earlier draft argued for **necessity** -- that `DepKind::Runtime` is part of the artifact in a way `Dev` and `Test` are not, so a runtime dependency that cannot be copied leaves the request broken. The architecture document rejects that outright, and for a better reason than tidiness: *what is actually required cannot be determined without the runtime environment.* Maven `provided`, npm `peerDependencies`, and Python extras all mean "required, in a situation this tool cannot see". Guessing would be wrong in both directions, so the tool reports and leaves the judgement to the user.

The two axes, then:

- **Reachability** -- `Dependency` versus everything else, from the immediate `Cause`.
- **Severity** -- a property of the `Code`, saying *this one fails however the artifact was reached*. `malware-known` carries it. So do the integrity codes, by the same argument: a checksum mismatch is not a missing artifact but a wrong answer, and depth does not make it less so.

`DepKind` stays in `Cause::Dependency` because a report is more useful for carrying it, but it does not decide the exit code.

**So `Action::is_failure()` is not the exit rule and never quite was.** `worst()` answers "how bad was the worst thing", which is not the same question as "did we do what was asked". The exit code is a function of both the action and the provenance, and `cli::subcmd::run` has to return enough to compute it.

## `pom-property-unresolved` means three different things

One Maven failure, three consequences, decided by **where** the unresolved reference sits:

| Where | Consequence | Code | Action |
| --- | --- | --- | --- |
| the POM's own coordinates | the artifact is refused | `pom-property-unresolved` | `skip-artifact` |
| a dependency's coordinates | that dependency is dropped | `dependency-unresolved` | `warn` |
| a parent that would not load | reported, nothing held back | `dependency-unresolved` | `warn` |

The first is the artifact failing to say what it is -- `<version>${revision}</version>` with nothing defining `revision`. Nothing read out of such a POM is worth having: not the dependency list, not the licenses, and not any `${project.version}` below it. It is refused in `effective_pom` rather than in each caller, so `metadata` and `deps` cannot disagree.

The third is only ever a means to an end. If the missing parent cost something, that something is reported at its own site and its own severity; reporting the cause as well would grade the same loss twice. So the parent failure is always a warning and the run carries on, which is what `unreachable_parent_that_cost_nothing_is_only_reported` pins.

Two real bugs fell out on the way, both worth knowing because the shape recurs:

- **The POM's own coordinates were never interpolated.** `effective` took `group_id`, `artifact_id`, and `version` raw from the chain, so `${revision}` became the version verbatim and was never recorded as unresolved -- and `Coords`, built from those same values, then expanded `${project.version}` to the literal `${revision}` everywhere below.
- **An unresolved dependency version was descended on.** The resolver leaves `${spring.version}` verbatim by design so a caller can refuse, and `deps` did not: `Some("${spring.version}")` passed the versionless check and was pushed as a real dependency, sending the spider to ask a repository for that version by name.
