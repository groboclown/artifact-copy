# Several Targets in One Copy

Built. `copy` takes `--to` more than once and publishes what it reaches to each target, fetching each payload once.

## What already supported it

The report database was built for this, and tests cover two destinations in one run:

- `run_repository` allows several target bindings per run.
- `artifact_transfer` is keyed by artifact and destination, so each target keeps its own claim, state, and attempts.
- `file_transfer` keeps one download row per file and one upload row per file and destination, so one download can serve several uploads.
- `ReportState` (`claim`, `close`, `present`, `uploaded`) and `ReportQuery` (`holds`) take one destination per call, so calling them once per target needed no API change.
- `Session::target` builds a fresh target per call, and `ConfiguredTarget::holds` is already per target.
- The walk and the `Visitor` trait know nothing of targets, so fan-out fits inside the visitor.

## Shape

```text
  walk (unchanged) --visit(artifact)--> Copying
                                          |
                    for each target: claim, holds --> skip the held and the terminal
                                          |
                    upload::fetch once  (source side; a failure or refusal applies to all)
                                          |
                    for each remaining target, in --to order: upload::publish, close
                                          |
                    Fetched::discard only if every target took it
```

The source side -- resolution, policy, download, verification -- is about the artifact and happens once. The target side -- claim, presence, companions, publish -- is about the destination and happens per target.

## Decisions

1. **CLI.** `--to` is repeatable (`--to=a --to=b`), order kept. One `Role::Target` binding per name. A repeated name is refused.
2. **`upload::run` is split** into `fetch` (download, companion download, `Source::verify`, holds) and `publish` (per target: companions it takes, `Target::publish`, `Delivery`). Companions are fetched for the union of targets that do not decline them; each target is handed only the ones it accepts. `Fetched` owns the holds, so they live until the last publish returns.
3. **Fan-out inside `Copying`.** It holds one `Destination` per target, each with its own counters. `visit` claims each destination; a destination whose claim is terminal or whose target holds the artifact is done for this artifact. When none remain, nothing is fetched.
4. **Targets in sequence**, in `--to` order, for one artifact. One target's failure, or refusal at publish, does not stop the others: each closes its own claim. Concurrency across artifacts is unchanged, so a run still uses its worker count. Sequential rather than concurrent publishing keeps one target's slowness from multiplying memory.
5. **Abort.** An abort-classed failure closes every claim this artifact still holds as `failed` before unwinding.
6. **`discard`** unlinks a payload only after every remaining destination has published it. A failed or refused destination keeps it, so a retry does not fetch again.
7. **Outcome per destination.** `ArtifactRecord.outcomes: [{destination, outcome}]`, written only for a copy with several targets; `outcome` stays as the rolled-up worst (failed over refused over copied over already-present, first in `--to` order among equals) so a reader of one-target reports sees no change. `observation_outcome` holds them in the database, each reason a `problem` row it points at; schema version 10. Text and log renderers print each destination only when there are several.
8. **Refusals.** A source-side refusal (license, quarantine, signature, advisory) refuses the artifact for every destination: it is about the bytes. A publish-time refusal is per destination.
9. **`--from-db` work list.** `ReportQuery::outstanding` takes a list of destinations; an artifact is outstanding while any of them lacks a terminal transfer. `Cause::Report.destinations` is a list, stored in `provenance_destination`; in a message it travels as one comma-joined `destination` argument. One destination keeps the earlier rendering.
10. **Summary.** Counters per destination in `copy::Summary`; `copy::describe` logs one closing line per target, naming it only when there are several.
11. **`--refresh=target`** stays one flag for every target. A per-target form is a later option if somebody needs one.
12. **Walk resume.** `spider_walk.targets` holds the sorted, comma-joined target set, supplied by `Visitor::targets`; a resumed walk must match it, so a changed set starts a new walk.

## Corrections to the original plan

- `ReportQuery` has no `count`, and `--sample-size` belongs to `find`, so the plan's count clause did not apply.
- `holds` and `outstanding` are on `ReportQuery`, not `ReportState`.
- `copy::describe` had no caller; it now logs the per-target lines.
- No new `outstanding_any`: `outstanding` itself took the list, since `inspect::Outstanding` was its only caller.
