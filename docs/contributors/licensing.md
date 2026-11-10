# The License Policy

It loaded, it validated, and nothing ever applied it: `LicensePolicy::evaluate` had no production call site outside its own tests. `ArtifactRecord.license` was always absent, `license-forbidden` never fired, and a user who wrote a policy forbidding GPL watched a clean run and was told something false.

## Where it is evaluated, and why not where it looked like it belonged

In the **walk** (`Spider::judged`), not in `repo::resolve`.

`resolve` is the obvious home and was the one this was filed against: it narrows the context to the chosen version before reading its metadata, which is exactly the context a verdict wants. But `Source::resolve` is a trait method with a default body, and `repo::github` already overrides it. An evaluation placed there is one an adapter can silently skip -- which is the same class of failure this entry exists to end, reintroduced one layer down. The walk is the single point every resolved artifact passes through, whatever produced it.

It runs **before** the refusal is read, which is what makes it work at all: `license-forbidden` is `skip-artifact`, so reporting it there is what makes the existing refusal check drop the artifact and prune its subtree. No new control flow was needed.

Reported under the **narrowed** context, so a per-artifact quarantine rule can excuse a forbidden license for one artifact exactly as it excuses anything else.

## Where the verdict lives

`core::license::{Verdict, Decision}`, moved out of `policy`.

The first plan was `model`, alongside `ResolvedArtifact`, by the argument that moved `LastDownload` there: domain vocabulary rather than one module's private type. That is wrong on a detail worth writing down. **`model` is a strict leaf** -- it imports nothing, and `core` depends on *it* -- while a `Verdict` names a `Message` and a `Code`, both `core`. Putting it in `model` would have inverted the one edge `lib.rs` documents as never inverted.

So it lives in `core`, which may use `model::DepKind`, and it is carried on the per-artifact `Ctx` beside the quarantine reservations rather than on `ResolvedArtifact`. Same effect -- evaluated once, travels with the artifact, read by the report where it already reads reservations -- with no inverted edge and no change to `ResolvedArtifact`'s seventeen construction sites.

`policy::license` re-exports both, because they are what `evaluate` answers with: moving them was about who may *depend* on the type, not about hiding it from the module that produces it.

## What a report says

`ArtifactRecord.license` carries the decision, the resolved SPDX expression, and the reason; a refused artifact also carries `outcome: refused` naming `license-forbidden`. An artifact the policy *allowed* still gets a verdict, so a report can say what was decided rather than only what was not -- and an artifact nobody judged gets `None` rather than an invented allow.

Only a verdict that names a problem raises one. An ordinary allowed artifact reports nothing, because a problem line per artifact would bury the ones that matter.

## Per source, not per run

`ConfiguredSource::licenses` resolves the policy the same way `decide` resolves the quarantine policy: a host's own `license-policy` wins over `setup`'s, and the file is read once per path rather than once per source. A user who set one per host will expect the other to follow.
