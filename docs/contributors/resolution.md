# Resolution

Turning a request into one exact version, and the criteria that version has to satisfy.

## The publish window cannot be applied at selection time

A request with no version resolves to the newest version matching every criterion, not merely the newest matching the specification. The window cannot be applied by `Ecosystem::select`, because publish time is not in the version list -- it arrives with the metadata, after a version has been picked -- so resolution steps down through candidates, newest first, bounded by `MAX_STEP_DOWN`.

**The two window failures carry different message ids**, which was the point: `publish-too-recent` and `publish-time-unknown` call for completely different responses -- wait, versus set `unknown-publish-time: allow` -- and a report rendering both the same way would send a user looking for a timestamp that was never there. They share a `Code`, because the *action* is the same and the code drives the action table; the id carries the diagnosis. A test asserts each path raises its own id and not the other's.

`GitHubSource` overrides `resolve` and had collapsed the two into one. It now splits them, with its own wording: there is no older tag to fall back to, because GitHub tags have no order to step down through.

## How the criteria are assembled

`session::ConfiguredSource::criteria(pre)` is what a resolution takes: a source's `minimum-publish-time` and `unknown-publish-time` resolved against `setup` by `criteria_for`, with `pre` supplied by the caller.

**Pre-releases left `criteria_for`.** They come from `--pre-release`, which is a statement about one invocation, and a source cannot make it on a user's behalf -- so a function whose job is *resolve this source's configuration* had no business taking it. `Criteria::pre_release` adds it, and `ConfiguredSource` stores only what the configuration decided.

For a **proxy** the proxy's own declaration supplies the window, not its upstreams'. It is the source being resolved against, and no proxy overrides `resolve`, so the default body drives the *proxy's* `versions` and `metadata` and an upstream's setting never comes into play. Pinned by a test with an hour on the proxy and thirty days on its upstream, because it is the kind of thing somebody will later try to "fix".

## A quarantine rule may excuse the window

The window stays a *criterion* rather than becoming a quarantine finding. `Criteria::old_enough` answers the same question it always did, and nothing about what the window *is* has changed. What changed is that its answer is no longer the last word: a version inside the window reports `publish-too-recent`, and **the disposition that comes back decides whether to step down**. A per-artifact rule below `skip-artifact` therefore takes the version.

This reuses the quarantine file as the bypass channel rather than growing a second per-artifact mechanism beside it. That is a deliberate trade and not a reclassification: the two remain categorically different -- one is a rule a version must satisfy, the other a reservation about a version -- and one reviewable file of per-artifact exceptions is worth more than perfect separation.

**The case it exists for.** Log4Shell is disclosed, a patched version is published, and a team decides to take that one artifact before the window has run, because the thing the window protects against is less dangerous than the thing being patched. That is a judgement about one artifact, with a written justification, which is exactly what the quarantine file is for. It is not an argument for shortening the window for everything.

### `allowed` and `soft` both take it, and differ afterwards

Any class below `skip-artifact` excuses the window, which is two of the four:

| Class | The artifact | In the quarantine list | Under `--harden` |
| --- | --- | --- | --- |
| `allowed` | taken | no | still taken |
| `soft` | taken | yes | refused again |

`soft` is usually the one wanted: the artifact is copied *and* stays in `ArtifactRecord.quarantine` for somebody to audit. `allowed` is the stronger statement, for a team that wants the exception to hold even in a run that hardens everything else. Both leave a `publish-too-recent` problem line carrying the rule's justification, so an artifact taken on an acknowledgement is never silent.

### The decision is read, not asked for twice

`Ctx::report` returns the action it decided, and that returned value is what the loop reads. Asking a second time -- some "what would happen" accessor -- would evaluate the rule's expiry again, and a long run crossing that expiry would then step down over a window it had just excused. One decision, one answer, which is the same rule [quarantine.md](quarantine.md) states for why a `Problem` carries an owned `Bypass`.

A consequence: neither window message may say what happens next. "Trying an older version" was accurate when stepping down was the only possible response and is wrong exactly when a rule excused the window, so both messages now state the finding and stop.

### What it does not excuse

Only the window.

- **A pre-release is still excluded** by `--pre-release` rather than by a finding, so no rule makes `2.15.0-rc1` a candidate. That is a question about the *request*, not a reservation about an artifact.
- **`publish-too-recent` and `publish-time-unknown` share a `Code`**, so a rule naming `publish-too-recent` excuses both. For one named artifact that is the reading somebody writing "take this one regardless of the window" would expect, but it is worth knowing it is what they get. Splitting the code would be the `signature-invalid` treatment in [quarantine.md](quarantine.md), and is not warranted while the action is genuinely the same.

### The GitHub override had to narrow first

`GitHubSource::resolve` reported every finding without narrowing the context to the chosen release, so `Dispositions` fell to `decide_without_artifact` every time and **no per-artifact quarantine rule could reach a GitHub release at all** -- not the window, not `version-unresolvable`, not `github-pre-release`. The same class of inertness as *It was inert in a real run* in [quarantine.md](quarantine.md), in the one adapter that opts out of the shared body.

It now narrows before judging the window, as `repo::resolve` does. With no order among tags there is no older release to step down to, so the disposition either takes the release or refuses the request.

## A returned error must agree with the reported problem

Resolution recorded `version-unresolvable` or `publish-too-recent` in the problem sink and then returned `Error::Malformed`, whose code is `metadata-malformed`. A caller reading the returned error classified the same event differently from one reading the sink, and the action table could have sent them in different directions. Nothing is malformed in these cases -- the repository answered clearly and no version it holds fits -- so `Error::Unresolvable` now carries them, reporting as `version-unresolvable`. Four sites in `repo::github` had the same mismatch.

Merging those two codes merged two buckets that had been hiding a duplicate: resolution recorded its diagnosis, and the spider recorded the returned error again, so one failure appeared on two lines. `Error::Unresolvable` now carries the `Problem` resolution already recorded (`Ctx::reported` hands it back), and a caller acts on it without recording it a second time.

## One extraction worth knowing about

`resolve<S: Source + ?Sized>` must be generic over `?Sized`. A plain `&impl Source` argument compiles, and then quietly makes `Source::resolve` undispatchable through the `Arc<dyn Source>` every caller actually holds.

## Maven parents and imported BOMs

A `scope=import` entry in `dependencyManagement` names a bill of materials whose own management applies to the importing POM. `MavenSource::effective_pom` resolves the chain once to learn the imports, expands each BOM (its own parent chain, then its own imports, recursively), and resolves again with them through `pom::effective_with`. The order is Maven's: the importer's own entries win, then each BOM in declaration order, the first to manage a coordinate taking it. A cycle between BOMs stops at the BOM already being expanded, and nesting past `MAX_BOM_DEPTH` is not followed; a BOM left out is reported as `maven-bom-not-expanded`.

The POMs reading an artifact needs, its parent and the BOMs it imports, are dependencies of the kind `build`. `SpiderSpec::resolve` adds `build` to any walk that follows anything, since a consumer's build reads them before it can resolve the rest; a run with `--dependencies=none` copies neither. Each is followed as a `type=pom` artifact, so only its POM is copied, and its own parent and BOMs follow in turn.
