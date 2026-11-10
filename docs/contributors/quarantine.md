# Quarantine

A **quarantine** marks an artifact a rule has a reservation about, where the reservation is reviewable. It is what lets a user read a report, look at what was flagged or held back, decide that a given case is a false positive, and re-run with that one acknowledged.

Whether the reservation actually stops the artifact is the **soft/hard** distinction, and by default only hard does. A soft quarantine takes the artifact and flags it; a user who wants soft ones to stop things too *hardens* them.

## The governing rule

> **Quarantine means "we chose not to take this", never "we could not take this."**

That single line settles most of the per-code questions below, and the two are easy to blur. A publish window is a rule we applied, and the rule might be wrong about this artifact -- reviewable. A checksum mismatch is not a rule, it is evidence that the bytes are not what was claimed -- there is nothing to review and no acknowledgement that should let it through. A signature that does not verify is the same kind of fact.

So integrity failures are fatal by default and carry no quarantine class, however tempting the symmetry looks: `checksum-mismatch`, `size-mismatch`, and `signature-invalid` abort the run, and `Code::quarantine` answers `None` for each.

**That is a default, not a lock.** These codes concern an artifact, so a `problem-policy` entry or a quarantine rule may name them and set any class, `allowed` included, and `Class::Allowed` turns any code into a warning. Such an entry is a written statement to accept bytes that did not verify; the defaults never make it, and a reviewer should read one as exactly that.

**Being reviewable is necessary and not sufficient.** A forbidden license is reviewable too, and is still not a quarantine, because its review already has a home in the license policy file and a second one would mean two places to look. [configuration.md](configuration.md) is what decides that; this rule only decides what is eligible.

## Decisions taken

1. **Quarantine is an orthogonal field, not an `Action` variant.** `Action` keeps its five ordered levels and `Problem` gains a separate marker, so `worst()`, `is_failure()`, and the exit code keep working unchanged. The two really are different axes: `host-unreachable` skips and is *not* reviewable, `publish-too-recent` skips and *is*.

2. **Soft flags, hard stops.** A soft quarantine takes the artifact and records the reservation; a hard one holds the artifact back. That is the whole of the distinction, and it keeps a repository full of routine unknown-key signatures from interfering with every run until someone tunes it.

   **Neither is necessarily a failure.** Whether stopping an artifact fails the *run* is not the quarantine class's business -- it is [run-outcomes.md](run-outcomes.md): a hard quarantine on something the user named fails the run, and the same hard quarantine on a dependency thirty levels down does not.

3. **Per-artifact overrides live in their own quarantine policy file**, named from config or the command line, parallel to the license and security policy files. A separate file is reviewable in a pull request, which is the point: an acknowledgement that something unsafe is being done deliberately should be visible to someone other than the person who made it. The file overrides the `problem-policy` table; the table defines defaults per code, the file defines overrides per artifact per code.

   **It tightens as well as loosens.** An entry may name any of the four classes, so `failure` or `hard` on a specific artifact is as expressible as `allowed`. That is why it is not called an *allow* file: the loosening direction is the common one and is not the only one. Tightening one artifact is the natural way to say "this package in particular, we do not accept on the usual terms".

4. **Expiry is judged on the signature's own creation time, falling back to the repository's publish time** when the signature carries none.

## How the four classes map onto the two fields

A soft quarantine does not skip by default; it flags. That makes the whole mapping fall out, and it means `Action`, `is_failure()`, and the exit code really do keep working unchanged, as decision 1 claimed.

| User writes | `Action` | Quarantine | Stops the artifact |
| --- | --- | --- | --- |
| `allowed` | `warn` | none | no |
| `soft` | `warn` | `soft` | no |
| `soft`, hardened | `skip-artifact` | `soft` | yes |
| `hard` | `skip-artifact` | `hard` | yes |
| `failure` | the code's own default | none | per that default |

**The exit code is deliberately not a column here.** Stopping an artifact and failing the run are different questions, and the second is answered by [run-outcomes.md](run-outcomes.md) -- by whether the user named that artifact, not by which class stopped it.

Two of the four are not quarantine values at all, which is worth saying plainly because the single knob hides it: `allowed` means *no quarantine, carry on*, and `failure` means *no quarantine, and the code's existing action decides*. Only `soft` and `hard` populate the marker.

**`hard` and `failure` are not the same thing, and the difference is the whole reason both exist.** A hard quarantine is recorded *as a quarantine*: it appears in the quarantine list, it is reviewable, and an override in the quarantine policy file can excuse it. A `failure` is none of those. Both stop the artifact, and neither decides the exit code on its own.

Decision 2's "consequence to plan for" largely evaporates. It assumed the exit code would need to know about quarantines separately. It does not: hard quarantine maps to `skip-artifact`, which `is_failure()` already treats as a failure, and soft maps to `warn`, which it already does not. "Only hard quarantine fails the run" is then a *result* of the mapping rather than a rule needing its own machinery. What does not evaporate: `Summary` is keyed by `Code` and needs quarantine counts, or a report cannot say how many artifacts were flagged without the reader tallying records by hand.

## `signature-invalid` carried three dispositions

`Code` is the key the policy table is written against, so one code cannot hold two answers. `signature-invalid` meant all three of:

| Situation | Belongs at |
| --- | --- |
| the signature does not verify | fatal, never quarantine |
| the signing key is revoked | hard quarantine |
| the signing key had expired | soft quarantine, or nothing |

**These had to be split into distinct codes before the policy table existed**, because `Code` is API: a user's `problem-policy` naming `signature-invalid` would be naming all three at once, and splitting afterwards would break whatever they wrote. `signature-invalid` keeps "does not verify"; `signature-key-revoked` and `signature-key-expired` are the other two. `SigOutcome::UntrustedKey` already distinguished them (`Untrusted::Revoked` and `Untrusted::Expired`); only the code they reported under was wrong.

## Default classifications per code

Smart defaults, each overridable to `allowed`, `soft`, `hard`, or `failure`, and overridable again per artifact -- for instance marking `tuna@<2` `signature-key-revoked` as allowed because those were known to be published cleanly before the stolen credentials were released.

- `signature-missing` -- soft
- `signature-key-expired`, where the key expired *after* the signature was made -- allow, and no event is raised at all, because the key was still good when it signed
- `signature-key-expired`, where the key expired *before* the signature was made -- soft
- `signature-key-revoked` -- hard
- `checksum-mismatch` -- failure
- `size-mismatch` -- failure
- `malware-known` -- hard
- `license-forbidden` -- failure; license overrides happen in the license file, not in quarantine
- `publish-too-recent` -- **hard**. Listed as soft in the first pass, which was written before *soft* was settled as "copy it and flag it". Checked against that meaning, this is the only row where the classification would have changed existing behavior, and it would have changed it by gutting the control: a release cut an hour ago would be mirrored with a flag and the window would prevent nothing. It is also the only reading under which the per-artifact override workflow makes sense, since there is nothing to review about an artifact already taken. A per-artifact rule does excuse the window; see [resolution.md](resolution.md).
- `vulnerability-known` -- allowed until a maximum-CVSS threshold exists; quarantining every artifact with a known CVE would hold back nearly every real dependency graph.
- transport, config, and lock codes -- unchanged; none of them is a choice.

## User configuration

- A user can specify blanket code overrides, or overrides per artifact per code. They cannot override on a blanket artifact basis. The artifact override allows version matching rules for the corresponding ecosystem.
- **Hardening** is a separate, blanket switch, settable in the configuration and on the command line, that makes every soft quarantine skip. It **applies to soft decisions only**: a hard quarantine already skips in all cases, and `allowed` and `failure` are not quarantines at all.

  It is not the same as reclassifying a code as `hard`, and both are worth having: reclassifying says *this particular thing is serious*, and is a lasting statement about that code; hardening says *this run is strict*, which is what a release pipeline wants without rewriting the policy table that a development run shares.
- A **loosening override survives hardening**. Hardening raises a default; the quarantine policy file is an explicit per-artifact decision, and a blanket default that overrode an explicit one would make the file useless in precisely the mode where someone bothered to write it. A *tightening* override is unaffected either way.
- A user *may* add expirations to an acknowledgement. If not set, the entry must *explicitly* declare an open-ended acknowledgement.
- The `problem-policy` table sets **both** axes for a code -- the `Action` to take and the quarantine class -- because they are two answers to one question a user is asking about that code. They stay separate fields on `Problem` because `Action` drives control flow and the exit code while the quarantine class drives review, and only the second is overridable per artifact.
- The quarantine value reaches the report **whatever the action was**, so post-run analysis can see both what was skipped and what was allowed through on an acknowledgement. Reading a report for *non-skipped* quarantine issues has to be easy: that is the list of things a run proceeded with despite a reservation, which is exactly what someone auditing it needs.

## It was inert in a real run

**Every layer was right and none of it was reachable.** A walk never narrowed its context to an artifact, so `Ctx::subject()` was always `None`, `Dispositions` fell to `decide_without_artifact` every time, and the quarantine policy file changed nothing outside its own unit tests. Found by writing the end-to-end test for `ArtifactRecord.quarantine`, which is the only thing that exercises the whole path.

Two places narrow, and both are needed:

- **`repo::resolve`**, once a candidate version is chosen. A rule naming `@<2` has nothing to match until then, and the choice happens inside resolution rather than in its caller.
- **`Spider::descend_from`**, once resolution returns, for the visit and the dependency read.

**Findings are collected across both**, which needed a second concept. `Ctx::collecting` opens the list *before* resolution, with no subject yet, and `Ctx::for_artifact` inherits an existing list rather than starting one. Without that the two narrowings each made their own and the earlier was discarded with the context that held it -- which is what the first attempt did, and what the test caught.

The list holds **only quarantines**, and only for the artifact in hand. Everything else is in the sink and in the report's problem lines already, and copying it per artifact would be the unbounded collection the memory discipline forbids. Reservations are bounded by the number of quarantine-capable codes.

## What the building settled

`Config::dispositions` folds the `problem-policy` table, the quarantine policy file, and `--harden` into one `Dispositions`; `session::Session` hangs it on the context a command works through, layering a **host's** own quarantine policy in front for sources that read from it. `validate-config` is deliberately outside that path -- a broken configuration is its subject, so it reports rather than refuses.

Four things that would otherwise have been invented at report time:

- **The record is built from the recorded problem, never from a fresh decision.** A rule's expiry is evaluated when the decision is made, so re-deciding a long run's early problems at the end would have some of them lapse retroactively and the report would disagree with what the run actually did. That is why `Problem` carries an owned `Bypass` rather than a reference to the rule, and why `Decide` returns a `Ruling` rather than a bare `Disposition`.
- **A bypass is recorded whenever a rule answered**, not only when it loosened something. A rule that *tightened* an artifact is equally somebody's per-artifact decision, and a reader asking "why is this one different" needs the same answer either way.
- **Hardening is recorded separately from the class.** A hardened `soft` and a `hard` both stop an artifact and are not the same statement -- the first would not have stopped it yesterday. Recording the class as `hard` instead would be a lie about what the policy says.
- **The bypass is on the problem line too**, not only the artifact record. An artifact held back has no artifact record to carry it, and the problem line is then the only place a reader learns somebody had written a rule about it.

Host-scoped policies layer in front of the run's, first match wins -- the same rule that already orders entries *within* a file, extended across files. A **proxy** declares no host of its own, so only the run's policy applies to it; that is the honest answer rather than a gap, since its upstreams' hosts say where bytes come from and a quarantine rule is about the artifact.
