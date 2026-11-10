# The Report Database

`--db=FILE` keeps each run of `find`, `inspect`, and `copy` in one SQLite file. The file accumulates runs, and serves as the tool's cache, its resume state, and its inventory of what each repository holds. See [the report database](../README.md#the-report-database) for the command-line options.

## Schema

[`schema/report-db.sql`](../schema/report-db.sql) is the schema, version 10. The tool compiles that file in and applies it verbatim, so it is the authority; this document does not repeat it. [report-as-database.md](contributors/report-as-database.md#high-level-schema) maps every table and explains the choices behind it.

| Group | Tables | Holds |
| --- | --- | --- |
| Vocabulary | `problem_code`, `transfer_state`, `file_state`, and other lookup tables | Values a newer build may extend. |
| Identity | `package`, `package_qualifier`, `artifact` | One row per name, and one per version under it. |
| Repositories | `repository`, `run_repository` | Each configured source, target, and enumerator, by role and name. |
| Inventory | `repository_artifact`, `repository_file` and its digest and signature tables | The latest known contents of each repository. |
| History | `run`, `report_record`, `artifact_observation`, `problem`, `run_summary` and their children | Every report record, in stream order. |
| Transfers | `artifact_transfer`, `file_transfer`, and their `_attempt` tables | Current state per artifact or file and destination, plus every attempt. |
| Cache | `cache_entry` | Payloads kept on disk under `setup.cache-dir`. |
| Walks | `repository_enumeration`, `spider_walk`, `spider_task`, `spider_claim` | Where an interrupted `find` or dependency walk resumes. |

Reading it by hand:

- A column ending `_ms` is milliseconds since the Unix epoch, UTC.
- Every table is `STRICT`.
- A purl is stored in pieces (`package.ecosystem`, `namespace`, `name`, `package_qualifier`, `artifact.version`) beside the rendered purl. Filter on the pieces, not with `LIKE` on the purl.
- SQL cannot order `version`: `ORDER BY version` puts `1.10.0` before `1.9.0`.
- Which transfer states are finished lives in `transfer_state.terminal` and `file_state.terminal`.
- A newer build may write a vocabulary value an older one does not know. Expect values beyond those the schema seeds.

## Inspecting

[`scripts/explore-report-db.py`](../scripts/explore-report-db.py) answers named queries against a database. It opens the file read-only, so it is safe beside a running `copy`.

```
scripts/explore-report-db.py FILE
```

On a terminal it prompts; otherwise it reads statements from standard input. A statement is `VERB [QUERY] [key=value ...]`, ended by a newline or `;`. Values take shell quoting, so `repo="my repo"` names a repository with a space in it. `show` prints CSV.

| Verb | Does |
| --- | --- |
| `show QUERY [key=value ...]` | Print a query's rows. |
| `help [verb=NAME]` | List the verbs, or describe one; `help verb=show` lists the queries. |
| `exit` | Exit. |

| Query | Keys (optional in brackets) | Answers |
| --- | --- | --- |
| `list-repositories` | | Every configured source, target, and enumerator binding. |
| `artifacts-for` | `repo` `[role]` | What one repository holds. |
| `files-for` | `purl` `repo` `[version]` | Files known for an artifact. |
| `left-to-copy` | `source` `destination` | What a source still has to deliver to a destination. |
| `runs` | | Every finished run, its artifact count, and its worst action. |
| `failures` | `[run]` `[code]` | Problems, with their message. |
| `quarantined` | `[run]` `[code]` | Quarantined artifacts without a bypass. |
| `blocked` | `[run]` | Artifacts refused whole, with the reason. |
| `unresolved` | `[run]` | Requests that matched no artifact, with the reason. |
| `discovered-problem-codes` | `[run]` | Each problem code and its count. |
| `unmatched-licenses` | `[run]` | Declared licenses with no known SPDX identifier. |
| `with-unknown-licenses` | `[run]` | Artifacts whose license is unknown. |

To compare what two repositories hold, use [`scripts/diff-report-db.py`](../README.md#compare-artifacts).

## Example: a resumable migration

Record what the source holds, then copy it:

```
artifact-copy find --from=old-npm --db=migration.db
artifact-copy copy --from=old-npm --to=new-npm --db=migration.db --from-db
```

Optionally, screen everything before copying any of it. The inspection reads its work from the database:

```
artifact-copy inspect --from=old-npm --db=migration.db --from-db
```

When the target already holds part of the source, record its contents first, so `copy` asks the database rather than the target once per artifact:

```
artifact-copy find --enumerator=new-npm-catalog --as-target=new-npm --db=migration.db
```

When a run is killed, run the same command again. `find` continues from its last page. `copy` skips every artifact that reached `new-npm`, and retries those left `pending`, `in-progress`, or `failed`.

Check progress, from another terminal if a run is still going:

```
$ scripts/explore-report-db.py migration.db
report> show left-to-copy source=old-npm destination=new-npm
report> show blocked
report> show failures code=checksum-mismatch
```

## Maintenance

- **Back up before any change**: `sqlite3 migration.db ".backup migration-backup.db"`. Copying the file alone is not enough while it has `-wal` and `-shm` files beside it.
- **Do not change the database while a run holds it open.** Reading is safe; writing races the run.
- **Keep it on a local filesystem.** SQLite over a network share is not safe.
- **Set connection options yourself.** A hand-opened connection needs `PRAGMA foreign_keys = ON`, which SQLite leaves off, and a `busy_timeout` so it waits on a running writer instead of failing.
- **History is pruned on request, never by the tool.** `scripts/db-maintenance.py prune-history migration.db --older-than "90 days"` deletes runs and everything recorded under them, keeps the inventory, transfer summaries, and `cache_entry`, removes the advisories, suppressions, bypasses, and provenance chains no remaining run references, and returns the space. `--keep-last N` spares the newest runs and `--run ID` names one; `--dry-run` lists what would go. Nothing is spared otherwise: pruning an unfinished run loses the walk a later run would resume, and pruning a repository's last complete walk loses the date "artifacts since" is measured from.
- **Cached files past their retention** are evicted when a run next reaches for them, and `setup.cache-size` is kept after each fetch. To delete files past retention that no run reaches for, or to shrink a cache no run is using, run `scripts/db-maintenance.py prune-cache CACHE_DIR [--max-size "20 GiB"] --db migration.db` (add `--dry-run` first); it also removes their `cache_entry` rows.
- **Moving `setup.cache-dir`** leaves the database naming payloads that are no longer there. The next run reports `cache-file-missing` and fetches them again.
- **Prefer `--refresh=PART` over editing.** It asks the server again for one part, and records the answer.

### Editing transfer state

These edit what `copy --from-db` treats as outstanding. Each takes the exact purl, version included, and the configured target name, as bound parameters. Never build the SQL by pasting a purl into it.

Mark an artifact skipped, so `copy` never sends it to that target:

```sql
INSERT INTO artifact_transfer (artifact_id, destination_repository_id, state, completed_ms)
SELECT a.artifact_id, r.repository_id, 'skipped', CAST(unixepoch('subsec') * 1000 AS INTEGER)
FROM artifact a, repository r
WHERE a.purl = :purl AND r.role = 'target' AND r.name = :target
ON CONFLICT (artifact_id, destination_repository_id)
DO UPDATE SET state = 'skipped', completed_ms = excluded.completed_ms;
```

It changes nothing when the database has never seen that target; run a `copy` to it first.

Make an artifact outstanding again, deleting its transfer history for that target:

```sql
DELETE FROM artifact_transfer
WHERE artifact_id = (SELECT artifact_id FROM artifact WHERE purl = :purl)
  AND destination_repository_id = (
      SELECT repository_id FROM repository WHERE role = 'target' AND name = :target);
```

The next `copy` may still find the artifact present at the target, from the target's recorded inventory or the target itself; add `--refresh=target` to ask the target. Do not make `copied` work outstanding unless the target lost it.

A claim left `in-progress` by a killed run needs no edit: the next run reclaims it.

**When you write a repair you expect to need again, add it to `scripts/db-maintenance.py`** and contribute it, so the next person with the same problem runs it rather than rewriting it.

## Schema versions

A build reads exactly one schema version, recorded in `PRAGMA user_version`. A database of any other version is refused with "FILE holds report schema version N, and this build reads version M". There is no upgrade path.

To continue with a newer build, start a new database, or pass `--refresh=all`, which replaces the file. Either loses the recorded inventory, transfer state, and history, so keep the old file and read it with the build and scripts that wrote it.

An earlier draft of this document described a schema version 1 with `task` and `attempt` tables. It was never released, and nothing reads it.
