# Reporting

How a run's findings reach a report. The report *format* is [../reports.md](../reports.md); this is the machinery behind it.

## Problems reach the report as they occur

`Record::Problem` existed, `ProblemRecord: From<&Problem>` existed, the text renderer rendered it, and **nothing constructed it**. Two doc comments already described the design as though it were built: `report.rs` said "problems ride in the same stream as they occur", and `TAIL_CAPACITY` said the sink "only needs counts plus a short tail" *because* of that streaming. Only the streaming was missing, which left `ProblemSink::tail` with no production consumer at all.

**The hook is on the sink, not on the walk.** `ProblemSink::record` is the one funnel every problem passes through, and most problems are not about an artifact: a page that will not parse, a depth limit, a source that cannot be reached. A visitor-based hook would have seen none of those. It is also the only way a problem raised **after** an artifact's record was written reaches the report -- everything the dependency read finds -- because that record is written when the walk visits, and is long gone by then.

`core::problem::Watch` is the inversion that lets this happen without `core` knowing what a report is, the same shape as `Decide` and `net::Fetch`. The watcher is `report::Logged`, which also logs each problem it writes; see [logging.md](logging.md).

**The watcher is told outside the sink's lock, and that is load-bearing.** A report writer takes a lock of its own, and the real implementation records a problem when a write fails -- which re-enters `record`. Notifying inside the lock deadlocks on exactly that path; `watcher_may_record_a_problem_of_its_own` pins it, and hangs rather than fails if the notification is moved back inside.

**A failed write is logged, never propagated.** `record` answers with the action its caller must take, and that answer must not depend on whether anyone was watching: a run's behavior cannot turn on whether a report could be written. A report file that genuinely cannot be written still surfaces, through the artifact records, which do propagate.

Decisions taken rather than defaulted into:

- **Every problem gets a line**, not only those that changed what happened. The summary's per-code counts say *200 artifacts were unsigned*, never *which*, and a report whose job is to be audited cannot answer the second question from the first. The cost is one line per problem in a format built for streaming.
- **A quarantine finding appears twice** -- as a problem line and inside `ArtifactRecord.quarantine` -- and that is deliberate. They answer different questions: the record is that artifact's state, the line is an event with its own provenance and position in the stream. A consumer reading artifact records should not have to join against problem lines to learn an artifact was quarantined.
- **The record was not moved after the dependency read**, which would have made `ArtifactRecord.quarantine` complete. An `abort`-classed failure there would lose the record entirely, and a missing record is worse than an incomplete one.

The watcher attaches **after** the header and **before** the walk, so no problem line can precede the header and none is held back to the end. Problems recorded before a report exists -- loading the configuration -- are still outside it, which is inherent: there is nowhere to write them yet.

## The record types are separate from the writer

`report/record.rs` says what a line is; `report/stream.rs` writes them. Apart because the record types are the **published** shape that somebody's tooling parses, while the writer is one implementation of it, and a change to either is a very different kind of change. The tool itself never reads a line report back; see [report-as-database.md](report-as-database.md#report-sinks).
