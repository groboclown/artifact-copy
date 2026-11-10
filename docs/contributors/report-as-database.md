# Report Database

References: [PEP 658](https://peps.python.org/pep-0658/), [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md), [Maven repository metadata](https://maven.apache.org/ref/current/maven-repository-metadata/repository-metadata.html).

One SQLite report database retains every report fact, builds source inventories over many runs, records transfers to targets and cache storage, and supplies resumable copy work. It replaced a separate progress database, whose module was deleted. The user guide is [progress-db.md](../progress-db.md); the schema is [`schema/report-db.sql`](../../schema/report-db.sql).

## Design rules

- `package` owns name-level identity and `artifact` owns one row per version under it. A name-only inventory and a later versioned artifact enumeration join through the package, which is what lets several runs build one picture.
- **A purl is stored in pieces.** Ecosystem, namespace, name, and each qualifier are their own columns or rows, and the version is its own column on `artifact`. Every question worth asking of an inventory is a question about one piece -- every Maven artifact under a group, every source classifier, every version of one name -- and none of them should be a `LIKE` against a rendered string.
- **The rendered purl is stored beside the pieces and is the natural key.** One column, unique, and the value comes from `ArtifactId`, which owns the rendering. It is never assembled in SQL and never built by splicing: the version sits between the name and the qualifiers, so appending it to a stored purl produces a wrong purl for any ecosystem that uses qualifiers.
- **A reader rebuilds from the pieces, never from the rendered purl.** `ArtifactId::parse` can read a purl back, but the pieces need no parsing and cannot disagree with the columns a query filtered on. The rendered column is for keying rows and for a person reading the file.
- **A stored version carries its release class.** `Version` is text plus general-or-pre-release, and the class comes from an ecosystem's `VersionHandler`. Storing it lets a reader build a `Version` without a configured session, which the maintenance script needs. It is a derived fact like any other in the inventory: reconfiguring a version handler makes the stored class stale until the next artifact enumeration rewrites it.
- Source-specific facts never overwrite another source's facts.
- `repository` records each configured source, target, or enumerator binding separately. A generated key identifies the row, and equal names in different roles never merge.
- Event tables retain report history. Summary tables retain the latest state required by artifact enumeration, diffing, and resuming.
- `report_record` preserves stream order and lets a reader reproduce `Record` entries without inventing a second report model.
- A `Record` alone does not carry everything the database holds. Repository bindings, transfer claims, cache state, and enumerator cursors reach the database through a second interface, described below.
- Provenance is stored structurally rather than as the prose a line format renders. The database is not bound by a single-line rendering, and a stored `Cause` answers questions a string cannot. `Cause::message` renders each link as a message id plus named arguments, with the English as a fallback, through `message!` so the two cannot drift; `DbWriter` fills `provenance_item` from the id and arguments, never from the English, and `DbReader` rebuilds the message from the columns. `Cause::Dependency` carries the parent's resolved version, so the edge references the parent's `artifact` row at that version; the release class travels as an argument, because a purl cannot say it.
- Target inspection records an observation. Code, not the database, decides whether a source artifact matches a target artifact.

## Report sinks

`ReportWriter` and `ReportReader` are traits. `LineWriter` is the line-oriented writer, and `DbWriter` and `DbReader` are the database's. Only the database is read back: a line report is output for people and other tools, and `json` is the one format meant for them to ingest.

### The writer side

```text
trait ReportWriter          LineWriter<W: Write>    DbWriter
  write(&Record)              json, yaml, text        sqlite
  flush()
  artifact_count()
  state() -> Option<&dyn ReportState>
                              None                    Some(..)
```

`ToReport` holds a `Box<dyn ReportWriter>` rather than a `W: Write`, so the trait lives in `report` where the record types do.

`ReportState` and `ReportQuery` exist because the database answers them; a line writer answers `None` to both.

`ReportState` is the half a stream cannot answer. It records the run and its repository bindings, claims an artifact or a file before network work, closes a claim afterwards, checkpoints an enumerator cursor, and records cache state. A line writer answers `None`, so `copy --from-db` without a `--db` database fails with one clear message rather than part way through.

### The reader side

```text
trait ReportReader          DbReader
  records()                   stream order
  query() -> Option<&dyn ReportQuery>
                              Some(..)
```

`ReportQuery` is what `copy` and `inspect` ask: the artifacts to work through, the transfers still outstanding for a destination, the cursor an artifact enumeration stopped at, and the counts. Every listing pages by keyset on an integer primary key, never by `OFFSET`, because the run reading a list is usually the run mutating it.

A line report is not read back by the tool. `LineReader`, which once read one, was removed once the database answered everything a later run asks. A killed run still leaves a usable prefix for other tools: each complete line parses on its own.

### Formats and the file factory

The CLI asks a factory for a sink, given the format and the file name, rather than calling `File::create`. Truncation is a property of the format rather than of the open call.

| Format | Opens |
| --- | --- |
| `json` | Truncates. |
| `json-append` | Appends. |
| `yaml` | Truncates. |
| `yaml-append` | Appends, starting with a `---` document separator so the join is valid YAML. |
| `text` | Truncates. |
| `text-append` | Appends. |

**The database is not a report format.** `--db=FILE` opens it beside the line report, because the two serve different readers: a line report lets an outside tool follow a run, and the database is this tool's cache, resume state, and inventory. A run may keep both. `report::open` builds the writer:

```text
  line only   LineWriter
  db only     Refreshing(DbWriter)
  both        Tee(LineWriter, Refreshing(DbWriter))
```

`Tee` writes each record to both and takes state and queries from the database. `--db` adds a run to an existing database, or creates one; `--refresh=all` removes it first, and refuses a file that is not a report database. The old `sqlite` and `sqlite-new` TYPE spellings are refused with a message naming `--db`.

**A database is a cache by default.** Every lookup asks it first and falls back to the server. `--refresh=PART` makes `Refreshing` blank one part of the read view, so the lookup falls through, while writes still record what the server said:

| Part | Blanked | Falls back to |
| --- | --- | --- |
| `source` | `held`, `versions_held` | the live source, through `InventorySource` |
| `target` | `holds` | `Target::exists` |
| `payloads` | `cached` | a fresh download |
| `enumeration` | `resume_enumeration` | a walk from the start |
| `spider` | `resume_walk` | a dependency walk from its roots |

The work list (`outstanding`, `inventory`) and the history (`last_complete_enumeration`, which dates the next `find`'s narrowed walk) are never blanked. Each sub-command refuses a part it does not use. `--from-db` takes the work list from the database; without it, named artifacts are still read through `InventorySource`.

## High-level schema

The schema itself is [`schema/report-db.sql`](../../schema/report-db.sql), which the source includes at compile time, so the file a user reads is the file the tool applies. The table below is the map; the SQL is the territory.

| Table | Purpose | Relationships |
| --- | --- | --- |
| `database_metadata` | Holds the schema version, creation time, and the tool version that created the file. Mirrors `PRAGMA application_id` and `PRAGMA user_version`. | One row per database. |
| `repository` | Holds one configured source, target, or enumerator binding: role, configured name, host, base URL, and ecosystem. | One repository joins many `run_repository`, `repository_enumeration`, and `repository_artifact` rows. It never records source-target equivalence. |
| `run` | Holds one command invocation: command, tool version, start, finish, completion status, and worst action. | One run joins many report records, repository bindings, corpus states, observations, artifact enumerations, and transfer attempts. |
| `run_repository` | Records each repository binding used during a run, its role in that run, and its source priority. | Joins `run` to `repository`. Several target bindings in one run are allowed, so one copy may publish to more than one target. |
| `run_corpus` | Stores every `Header.corpus_age` entry. | Joins one `run` to an advisor name and its serialized `CorpusAge` fields. |
| `repository_enumeration` | Records one catalog walk: enumerator kind, the listing depth it declared, the requested scope, the last cursor, pages walked, artifacts found, whether the walk reached the end of the catalog, and the checkpoint time. | Belongs to `run` and `repository`, one row per pair however many pages the walk takes. Answers where an interrupted walk resumes, and when the last complete walk started. |
| `spider_walk` | Records one dependency walk: the source, the `--dependencies` spec it follows, and a copy's sorted targets (schema version 10). | Belongs to the `run` walking it; a later run adopts a killed run's walk by taking it over. Owns `spider_task` and `spider_claim`. |
| `spider_task` | Holds one discovered request: its dedup key, purl, version spec and provenance as JSON, depth, and state (`pending`, `in-progress`, `done`). The JSON is cleared once done. | Belongs to `spider_walk`. The key is unique per walk, which is the spider's push-time de-duplication. |
| `spider_claim` | Holds one resolved coordinate a walk claimed, and the task that claimed it. | Belongs to `spider_walk` and `spider_task`. The spider's visited set. |
| `report_record` | Preserves report stream sequence, timestamp, kind (`header`, `artifact`, `problem`, or `summary`), and the specialized row reference. | Belongs to one `run`; points to one artifact observation, problem, or run summary when applicable. |
| `run_summary` | Stores `Summary.artifacts`, `worst_action`, per-code counts, per-quarantine counts, and completion status. | One summary belongs to one `run`; child rows hold map and list values. |
| `summary_code_count` | Stores one `Summary.counts` entry. | Belongs to `run_summary`; keyed by problem code. |
| `summary_quarantine_count` | Stores one `Summary.quarantined` entry. | Belongs to `run_summary`; keyed by quarantine class. |
| `summary_unmatched_suppression` | Stores one `Summary.unmatched_suppressions` value. | Belongs to `run_summary`. |
| `package` | Holds name-level identity in pieces: ecosystem, namespace, and name, beside the rendered purl for everything up to the version. | One package owns many artifacts and its qualifiers. The rendered purl is unique, so it is what an upsert keys on; the pieces are what a query filters on. A name-only inventory needs nothing else. |
| `package_qualifier` | Stores one purl qualifier of a package: key and value. Maven uses `type` and `classifier`, PyPI uses `file_name`. | Belongs to `package`, keyed by package and qualifier key. Apart from `package` because the set is open and a query asks about one key at a time. |
| `artifact` | Holds one version of a package, or the name-only row when the version is null, beside the rendered exact purl and whether the version is a general or a pre-release. | Belongs to `package`. The exact purl is unique, which is also what keeps a package to one name-only row -- SQLite counts nulls in a unique index as distinct, so `(package, version)` could not. |
| `repository_artifact` | Holds the latest inventory state for one artifact at one repository: first and last observation, published time, last-download state and time, declared license, and the run that last observed it there (schema version 9). | Joins `repository` to `artifact`; owns `repository_file`; drives source priority and target inventory queries. |
| `repository_file` | Holds the latest inspected metadata for one file within one repository artifact: name, URL, size, and verification, with `listed_ms` and `resolved_ms` saying whether an artifact enumeration listed it, a resolution named it, or both (schema version 3), and `core_metadata` saying whether a resolution found a PEP 658 document beside it (schema version 5; NULL when only an artifact enumeration listed it). Inspection may create this row without transfer activity. | Belongs to `repository_artifact`; owns digest rows; references a `cache_entry` when the bytes have been fetched. |
| `repository_file_digest` | Stores every declared or observed digest for a repository file, from an artifact enumeration's listing and a resolution alike. Two values for one algorithm are a disagreement; see [sources-and-targets.md](sources-and-targets.md#the-combination-rule). | Belongs to `repository_file`; key includes algorithm and value. |
| `repository_file_core_metadata_digest` | Stores the digests the index published for a file's PEP 658 document, accumulated like `repository_file_digest`, so a copy driven from the database fetches and checks the document as one driven from the source would. | Belongs to `repository_file`; key includes algorithm and value. |
| `repository_file_signature` | Stores each `FileRef.signatures` member: scheme, key identifier, and the signature or the URL it lives at. A resolution replaces the file's rows. | Belongs to `repository_file`. Without it a copy driven from the database would publish files it could not check, and would be quietly less verified than the same copy driven from the source. |
| `cache_entry` | Holds one cached payload: host, the configured cache directory spelling, the sandbox-relative path, size, verification, download time, last use, and the cache's retention and freshness limits (schema version 9). | Keyed by host and relative path, because a sandbox is keyed per host and two repositories on one host share it. Many `repository_file` rows may reference one entry. |
| `artifact_observation` | Stores every `ArtifactRecord`: requested text, reported version, last-download state, declared license, published time, and outcome. It retains historical report facts even after a later artifact enumeration changes the summary row. | Belongs to `run` and `artifact`; optionally links the observing `repository_artifact`; owns observation children. |
| `observation_outcome` | Stores each `ArtifactRecord.outcomes` member: the target, its place in the `--to` list, the outcome, and the problem holding its reason (schema version 10). Written only for a copy with several targets; the observation's own `outcome` is then the worst of these. | Joins `artifact_observation` to the target's `repository`; optionally links `problem`. |
| `observation_file` | Stores each `ArtifactRecord.files` member exactly as reported. | Belongs to `artifact_observation`; optionally links the current `repository_file`. |
| `observation_file_digest` | Stores each digest from one `FileRecord`. | Belongs to `observation_file`. |
| `observation_file_core_metadata_digest` | Stores each digest of one `FileRecord.core_metadata`, in order. | Belongs to `observation_file`. |
| `observation_file_signature` | Stores each `FileRecord.signatures` member, in order. | Belongs to `observation_file`. |
| `observation_license` | Stores `ArtifactRecord.license`: decision, SPDX expression, and the reason as a message id, argument object, and English fallback. | One row per `artifact_observation`; owns usage decisions. |
| `observation_license_usage` | Stores each `LicenseRecord.usage` decision. | Belongs to `observation_license`; keyed by dependency kind. |
| `advisory` | De-duplicates advisory identity, kind (`malware` or `vulnerability`), and optional summary. | One advisory joins many `observation_advisory` rows. |
| `suppression` | Stores a VEX suppression's source, justification, and detail. | One suppression may join many advisory observations. |
| `observation_advisory` | Stores each `ArtifactRecord.advisories` member, with the advisor that supplied it and its `certainty`. Per observation, since another run may take the record from another corpus. | Joins `artifact_observation` to `advisory`; optionally links `suppression`. |
| `bypass` | Stores a quarantine acknowledgement's source, justification, and expiration. | One bypass may join many quarantines or problems. |
| `observation_quarantine` | Stores each `ArtifactRecord.quarantine` member, including code, class, hardened flag, and bypass. | Belongs to `artifact_observation`; optionally links `bypass`. |
| `provenance_chain` | Heads one leaf-first causal chain. | Referenced by an observation or a problem. |
| `provenance_item` | Stores one `Cause` with its ordinal position: the cause kind, and whichever of the request argument, lock file path and entry, parent artifact and dependency kind, enumerator name, or report path, entry, source, and run that kind carries, plus the rendered text (schema version 9). | Belongs to `provenance_chain`. A dependency's parent references its `artifact` row at the version it resolved to, created if the database has not seen it. |
| `provenance_destination` | Stores each target a report link's work was outstanding for, in `--to` order (schema version 10). | Belongs to `provenance_item`. None for an inventory. |
| `problem` | Stores every standalone `ProblemRecord` and every `Outcome` reason: code, action, quarantine class, bypass, and the message as an id, argument object, and English fallback. | Belongs to `run`; optionally links `report_record`, the `artifact` it was raised against, and an `artifact_observation` outcome; references a `provenance_chain`. |
| `artifact_transfer` | Denormalizes the current state for one artifact at one destination repository, with the source repository last used as an attribute. States include pending, in-progress, copied, already-present, refused, unresolved, failed, and skipped. | Keyed by artifact and destination, so a terminal row stops a lower-priority source from copying the same artifact again, and so two destinations keep separate state. |
| `artifact_transfer_attempt` | Retains one copy attempt, its run, the source repository it read from, timestamps, final state, verification, and linked problem. | Belongs to `artifact_transfer` and `run`; optionally links `problem`. |
| `file_transfer` | Denormalizes the current state for moving one `repository_file` in one direction: download into the cache, or upload to a destination repository. | Keyed by repository file, direction, and destination. A download names no destination repository and references the resulting `cache_entry`. |
| `file_transfer_attempt` | Retains one attempt, its run, timestamps, state, verification, the side that failed, the stage it failed at, and the linked problem. | Belongs to `file_transfer`; optionally links `artifact_transfer_attempt` and `problem`. |

`artifact_transfer` and `file_transfer` answer resume queries without scanning historical attempts. Their attempt tables retain audit history. A transaction updates the summary row and attempt row together before or after network work, according to the state transition.

The failing side and the failing stage are separate columns because they are separate facts. A source read failure and a source connection failure differ by stage; a target disk that filled and a source disk that would not read differ by side. One column cannot say both.

`ecosystem` stays plain text on `package` and `repository` rather than becoming a lookup table, unlike the enumerations below. An ecosystem arrives from an extension as easily as from a built-in, so the set is not the tool's to enumerate, and somebody reading the database by hand should be able to write `ecosystem = 'maven'` without first finding its number.

`version` is text, and **SQL cannot order it**. Ordering and pre-release detection are ecosystem rules that live in `crate::version`, so a query that wants the newest version asks the tool rather than writing `ORDER BY version`, which would put `1.10.0` before `1.9.0`.

`last_download` stores a state of `at`, `never`, or `unknown` beside an optional time. The three values are not an optional timestamp, and flattening them loses the difference between evidence of disuse and absence of evidence.

## Inventory

`report::db` is written in layers: identity (packages, artifacts, repositories), report history (runs, stream records, observations, problems, provenance, and summary children), the inventory, enumeration, transfers, and the cache. Every `record.rs` variant and optional field has a round-trip test.

`db::inventory` keeps the summary rows and their merge rules: repeated artifact enumerations, a name-only artifact followed by a versioned one, conflicting facts from two sources, source priority, and an inventory built up over many runs. A `Record` names no repository, so the inventory learns which repository it describes through `ReportState`, the seam beside the record stream; see *What the database finder needs up front*.

## The query `copy` resumes on

Written out because it is the query the schema exists to answer, and because a table that cannot serve it is wrong however tidy it looks. Given a source repository and a destination, the outstanding artifacts are three tables and one anti-join:

```sql
SELECT ra.repository_artifact_id, a.purl, a.version, a.release,
       ra.declared_license, ra.published_ms, ra.last_seen_run_id
FROM repository_artifact ra
JOIN artifact a ON a.artifact_id = ra.artifact_id
JOIN repository origin ON origin.repository_id = ra.repository_id
LEFT JOIN repository target
       ON target.role = 'target' AND target.name = :destination
LEFT JOIN artifact_transfer t
       ON t.artifact_id = a.artifact_id
      AND t.destination_repository_id = target.repository_id
LEFT JOIN transfer_state s ON s.state = t.state
WHERE origin.role = 'source' AND origin.name = :source
  AND (t.state IS NULL OR s.terminal = 0)
  AND ra.repository_artifact_id > :after
ORDER BY ra.repository_artifact_id
LIMIT :page
```

Which states count as finished lives in `transfer_state.terminal` rather than in the query, so adding a state does not mean finding every `WHERE` clause that listed the old ones. `package` is not joined even though it holds the pieces: the exact purl is stored precisely so a reader can recover them without one, and a caller needs an `ArtifactId` rather than columns. The destination is joined by name through an outer join, so asking about a target this database has never seen is an ordinary question with a full answer rather than an error.

**A row with no version is returned, not filtered.** A name-only row from npm's replication feed means the version is *unknown*, while a raw repository's directory has no version *because there is none*; the row cannot tell them apart, and filtering both made raw repositories uncopyable. The reader decides, through `Ecosystem::version_optional`. `last_seen_run_id` is the run that last recorded the artifact, which a `--from-db` root names in its `Cause::Report`.

`db::work` answers it as `ReportQuery::outstanding`, paged on the key, with each artifact's files and digests taken from the inventory rather than asked of the source again.

The anti-join is where source priority is settled: `artifact_transfer` is keyed by artifact and destination rather than by source, so an artifact a higher-priority source already delivered is excluded here without naming that source.

Each page then takes **two more queries, not two per artifact**: the files for the page's repository artifacts, and the qualifiers for their packages, each `WHERE ... IN (the page)`. Joining files into the query above would multiply artifact rows by file count and break the keyset paging, and asking per artifact would turn one page into a hundred round trips.

An `in-progress` row is retryable **only after its run is known to be over**. A run that is still going owns its claims, so the predicate above is the shape and the reclaim rule decides which `in-progress` rows reach it: a claim belongs to a run, and any run that is not this process has let go of it. One with no finish time crashed; one with a finish time closed without closing the claim, as a run unwinding from an abort once did (`copy` now closes a claim as `failed` before unwinding). Either way nobody is working on it. Recovering those is what makes a killed migration resumable rather than permanently stuck. A claim this run already holds is a race between its own workers, and is refused as `report-unusable`.

`db::transfer` holds the claims: `commands::copy` calls `ReportState::claim` before each upload and `close` after it. Tests cover a restart after each crash boundary, stale claim recovery, source-priority skips, and two destinations in one run.

**Files are recorded too.** `commands::upload` reports what it cached on its `Outcome` and where a failure happened on its `Failure`, and `copy` writes both through `ReportState::downloaded`, because `upload` holds no report and should not. `db::cache` keeps `cache_entry`, and `db::file_transfer` the file rows. The upload direction is filled from `repo::Delivery`, which `Target::publish` fills per file as it goes: `uploaded`, `already-present`, `skipped`, or, for a file still being sent when the publish failed, `failed`. Each upload attempt links to its `artifact_transfer_attempt`.

## What the database finder needs up front

The query above filters by destination, so whatever the database wears when it feeds a run has to be built knowing the destination. That decides three things earlier than they would otherwise be decided.

**A run declares its bindings when it opens**, not as each one is first touched. `run_repository` rows for the source, its priority, and the destination are written with the `run` row, so the finder can be built from repository keys that already exist rather than creating them mid-walk.

**An observation is attributed to the binding the run says it is observing.** A `Record` names no repository, so the inventory learns it from the bindings a run declared -- and from which of them carries `Observing::Contents`, because the *role* cannot say it. A `copy` binds a source and a target and describes the source; a `find --as-target` binds an enumerator and a target and describes the target the enumerator points at. `find --as-source` does the same for a source, which is what a `--from-db` run reads its work from. The rule is otherwise narrow: **zero or several observed bindings and nothing is attributed**, because a run that watched two repositories cannot say which one an artifact came from, and filing it under a guess would corrupt the one answer the inventory exists to give.

**The finder is opened with the work it is for**, which is one of two things:

```text
Inventory                     what this source holds        inspect, find
Outstanding { destination }   what is left to deliver       copy
```

The anti-join lives inside the finder rather than in `copy`, so that `count()` answers the outstanding total rather than the whole inventory -- otherwise `--sample-size=35%` on a resumed migration is a percentage of the wrong number -- and so a resumed copy pages through the work left instead of filtering a million rows it has already delivered.

**The database wears `Source`, not `Enumerator`.** An enumerator reports coordinates, and a copy fed by one would go back to the live repository for every file, checksum, license, and publish time that the inventory already holds. `versions` and `metadata` come straight out of `repository_artifact`, `repository_file`, and their digest and signature rows, which is what lets a copy run against an inventory without a populated cache.

**The inventory is the manifest.** The finder answers from the report even where the repository has moved on since the artifact enumeration. A migration driven from a report copies what the report *says*, so re-running it produces the same result rather than quietly widening; a mirror that wants the newest state re-runs the artifact enumeration, which is what enumerations are for.

**It falls back per question, not per run.** An inspection that did not finish leaves an inventory that knows some artifacts and not others, and a `find` alone leaves coordinates with no files at all -- an enumerator reports what a repository holds, not what each thing is. So the fallback to the real repository is decided one question at a time:

| Question | From the inventory when | Otherwise |
| --- | --- | --- |
| `versions` | the repository holds any version of that name | the repository |
| `metadata` | that exact version has files recorded | the repository |
| `deps` | never | the repository |

A row with no files is the case worth naming, because it is exactly what `find` produces. Reading it as "nothing to copy" would publish an empty release that nobody could tell from a real one, so it falls back.

`deps` never comes from the database because no forward dependency edges are stored: `provenance_item` records why an artifact was reached, which is the reverse edge and only for artifacts some earlier walk reached. Delegating rather than answering empty is what lets a report-fed copy still spider, though it seldom needs to -- a complete inventory is already the list.

**Two root providers read the work list.** `copy --from-db` walks `inspect::Outstanding`, over `ReportQuery::outstanding`, and `inspect --from-db` walks `inspect::Inventoried`, over `ReportQuery::inventory`; both read through `repo::InventorySource`, so an inspection replayed from its own report costs no requests at all. `inspect::walk_from` pulls roots a batch at a time rather than collecting them. Naming artifacts or a lock file alongside `--from-db` is refused rather than resolved one way: two answers to "what should this run look at" is a question for the person who typed them.

**A report used as a work list is its own `Cause`.** Each root carries `Cause::Report`, naming the report, the entry, the source, the destinations for a copy, and the run that last recorded the entry, from `repository_artifact.last_seen_run_id`.

**A target's contents are recorded under the target.** `find --as-target=NAME` records what an artifact enumeration finds as a configured target's contents, so a later `copy` asks the report what the target holds instead of asking the target once per artifact. The enumerator is still bound, since its cursor belongs to it, but the records are not about it. The equivalence is the user's assertion, made per run: the database records what an enumeration saw, never that one repository *is* another.

**A run asks its own writer for the read view.** A copy writing a report needs to ask that report what is left, and getting the query from the writer rather than opening the file again is what keeps the two from disagreeing about which store they mean. Safe alongside the writer because the database is in WAL mode, which is most of why WAL was chosen. It is one store, not one connection: a literally shared connection would serialize every read behind the writer's lock for no gain.

**Every look-up is indexed**, and that is a requirement rather than an optimization. A finder that walked the outstanding list to answer one artifact's question would cost more than the request it saved, and would turn a migration of N artifacts into N-squared row reads. Looking one artifact up is three index searches; looking up a package's versions is four; none of them is a scan.

Two rules decide what an artifact enumeration checkpoint means, and both are about not claiming more than was seen. **Only a walk that reached the end of the catalog dates an inventory**: a sampled walk saw a tenth of a repository, and treating that as complete would let a later run skip what it never looked at, which is the quietest way to lose artifacts in a migration. And **a resume is offered only for a walk that was killed** -- its run never closed *and* it did not reach the end. A run that ended tidily short of the end stopped for a reason of its own, and resuming it would be the tool doing work nobody asked for.

`db::enumeration` records the walk through `ReportState::checkpoint`: one row per run, however many pages the walk takes.

The enumerator kind travels with the cursor because a cursor belongs to the implementation that issued it, and some repositories reject an old one outright. `find --db` resumes the offered walk, seeding its pages and found count, and refuses a cursor recorded under another kind rather than guessing; `--refresh=enumeration` walks from the start.

**`find` has no depth option.** An enumerator declares how far its listing reaches (`Enumerator::depth`: names, versions, or files), `find` records whatever it lists, and the walk's `depth` column (schema version 8) keeps the declaration. A name-only inventory stays name-only; a catalog of names cannot be asked for versions.

## Dependency walks

`inspect` and `copy` keep the spider's frontier and visited set in the database (`DbFrontier`, `DbVisited`) instead of memory. Without `--db`, each keeps a temporary database for the run, `DbSpec::scratch`: a `(run-db)` directory under the cache root holding the file and its `-wal` and `-shm`, removed when the last report writer drops. It is a full database, so claims and target answers are recorded too, and none of it outlives the run. `find` keeps none, since an enumeration streams and holds nothing that grows. Under `--db=-`, `MemoryFrontier` caps the queue at `setup.maximum-in-memory-queued-dependencies` (default `DEFAULT_QUEUE_LIMIT_TASKS`, 100,000) and prunes past it, reporting the count under `spider-queue-full`; with it, the queue is bounded only by disk.

**A killed walk resumes** under the rule enumeration uses: the latest walk of the same source under the same spec, whose run never closed. Adoption returns `in-progress` tasks to `pending` and deletes the claims they made first; otherwise the retried task would find its own claim and drop the artifact. Roots fed again by the rerun hit the push de-duplication and cost nothing. `--refresh=spider` starts a new walk instead.

The task's provenance is stored as JSON rather than in `provenance_item`: a queued task is work state the walk reads back, not a record of what the run observed.

## Relationship sketch

```text
run --< run_repository >-- repository --< repository_artifact >-- artifact >-- package --< package_qualifier
 |          |                  |                    |
 |          |                  +--< repository_enumeration +--< repository_file --< repository_file_digest
 |          |                                               |        |--< repository_file_core_metadata_digest
 |          |                                               |        |--< repository_file_signature
 |          |                                               |        |
 |          |                                               |        +-- cache_entry
 +--< report_record                                         |
 |      |                                                   +--< file_transfer --< file_transfer_attempt
 |      +-- artifact_observation --< observation_file --< observation_file_digest
 |      |          |                                  --< observation_file_core_metadata_digest
 |      |          |                                  --< observation_file_signature
 |      |          |             --< observation_advisory >-- advisory
 |      |          |             --< observation_quarantine >-- bypass
 |      |          |             -- observation_license --< observation_license_usage
 |      |          +-- outcome problem
 |      +-- problem
 |
 +--< artifact_transfer --< artifact_transfer_attempt

provenance_chain --< provenance_item        (referenced by artifact_observation and problem)

run --< spider_walk >-- repository
           +--< spider_task --< spider_claim
```

## SQLite policy

- **Strict tables.** The bundled library is 3.50.2, well past the 3.37 that `STRICT` needs, and a published schema is worth the type enforcement. `STRICT` allows only `INT`, `INTEGER`, `REAL`, `TEXT`, `BLOB`, and `ANY`, so no column is declared `TIMESTAMP`.
- **Times are integer milliseconds since the Unix epoch, UTC**, in columns named with an `_ms` suffix. The chrono bindings render `NaiveDateTime` and `DateTime<Utc>` as two different strings that do not compare equal, and the current maintenance script writes a third; an integer cannot drift.
- **`page_size` and `auto_vacuum = INCREMENTAL` are set before the first table exists.** Neither can change afterwards without rewriting the whole file, and pruning without incremental vacuum never returns a byte.
- **`application_id` is 1095585874 and `user_version` is the schema version**, kept equal to `database_metadata`, so ordinary tools identify the file.
- **`foreign_keys = ON` on every connection**, including the maintenance script, where it is off by default. Owned children declare `ON DELETE CASCADE` so pruning is one statement rather than four.
- **`journal_mode = WAL` and `synchronous = NORMAL`.** A power cut may lose the last commits. See the decision below.
- **`busy_timeout` is set on every connection.** A reader that shares the file with a running copy otherwise fails immediately.
- **No transaction is held across network work.** Claim and commit, fetch, then commit the outcome.
- **Enumerations that grow get lookup tables**: problem codes, transfer states, and cause kinds. The writer inserts an unseen problem code on first use. Cause kinds are all seeded, and the writer refuses a link naming any other, because a kind it does not know has no columns to fill. `action`, `quarantine`, and `verification` stay `CHECK` constraints, because they are published report vocabulary and change only when the report format does. SQLite cannot alter a constraint, and rebuilding a multi-gigabyte table to add one problem code is not acceptable.
- **Resume indexes are partial, and the anti-join's is not.** In a finished migration nearly every transfer row is terminal, so an index that lists outstanding work is restricted to the non-terminal states and stays proportional to the work left. The anti-join above needs the opposite: a **full** unique index on `artifact_transfer (artifact_id, destination_repository_id)`, because an index that omitted terminal rows could not find the rows the query exists to exclude. Two indexes, two questions.
- **Narrow children with natural keys are `WITHOUT ROWID`**: qualifiers, digests, summary counts, and usage decisions.
- **A nullable column carries no uniqueness.** SQLite counts each null in a unique index as distinct, so anything that must be unique across a nullable column -- one name-only `artifact` per package -- is keyed on something else, or on a partial index that names the null case.
- **Iteration is keyset paged**, never `LIMIT`/`OFFSET`. Rows leave the pending set while a run reads it, and offsets then skip work.
- **Batch inserts stay under the bound variable limit.**
- **`ANALYZE` runs before close**, and `PRAGMA optimize` with it.
- **Opening checks before it trusts the file.** `report::db` refuses another application's file, a schema version it does not read, and a read-only open that would have created tables. There is no upgrade path between schema versions; see [progress-db.md](../progress-db.md#schema-versions).
- **One writing process, on a local filesystem.** SQLite over a network share is not safe, and a migration database is exactly the file somebody puts on one.

## Decisions

**Retention.** Historical observations remain until somebody prunes them, and the tool itself never does: deciding which history is worth keeping is the operator's call, not a run's. `scripts/db-maintenance.py prune-history` deletes runs, by age, by count, or by id; the schema's `ON DELETE CASCADE` takes everything recorded under a run with it, the script then removes dedup rows (`provenance_chain`, `advisory`, `suppression`, `bypass`) nothing references, and incremental vacuum returns the space. Current state -- the inventory, `artifact_transfer`, `file_transfer`, `cache_entry` -- does not hang off a run and stays; `repository_artifact.last_seen_run_id` and a report cause's run fall to null. It protects no run: an unfinished one owns a walk a later run resumes, and a repository's last complete walk dates `last_complete_enumeration`, and pruning either loses that by the operator's choice.

**The cache holds the single copy of a payload, and a target reads it in place.**

A payload is downloaded through the **source's** host into that host's cache -- which `ext::sandbox` documents as the host's cache -- verified in flight, and stays there. A built-in target is handed the cached file's path and reads it where it lies: nothing is copied, linked, or moved, so the cache keeps its one copy for the next run. Downloading through the target's host instead would need the target's constraints widened to cover the source's, which is the change that lets one host's credentials reach another; see [write-path.md](write-path.md#the-sources-cache-handed-to-the-target).

A cached payload is **read-only on disk** after download, and every place that replaces or removes one clears the flag first. Every write, rename, and remove inside a host cache, and what each does with a read-only file:

| Site | Touches | Verdict |
| --- | --- | --- |
| `repo::download::evict` | a stale payload before a replacing fetch | Clears the flag first. Already fixed. |
| `ReqwestClient::fetch_to_file` | renames the verified `.partial` onto the payload | Runs after `evict`. A payload `evict` could not remove fails the fetch with `file-unwritable` rather than quietly. |
| `commands::upload::discard` | a published payload under `payloads: discard` | Clears the flag first. The `restore` instance this step named went with the staging chain. |
| `Cache::stage` | copies a user-supplied corpus in | **Was broken on every platform.** A copy takes its source's permissions, so a read-only corpus landed read-only and the next run's copy over it failed. Now clears the flag before and after copying, so only a payload is ever read-only. |
| `Cache::discard` | removes the whole cache | Clears every flag and retries when the first removal fails, which is Windows's answer to a read-only file. Only the test host calls it today. |
| `Cache::write`, `index.sqlite` | corpus and index files | Never read-only; payload paths are hashed shards, so a name cannot collide with one. |
| `Sweep` | an unverified `.partial` | Never read-only. |


`writable` lives in `ext::cache`, below both its callers. Why a target is trusted with the cache's own file, and what protects it, is in [extensions.md](extensions.md#protecting-the-files-a-target-is-handed).

**Retention after a successful upload is a setting**, `setup.cache-payloads`, because a one-shot migration and a standing mirror want opposite things:

- `reuse` (the default) leaves the file in the cache, so a later run reuses the download rather than fetching it again. The default is the safe one rather than the frugal one.
- `discard` unlinks it once the publish succeeds. The transfer completed, so nothing needs those bytes, and a migration of a large repository never grows a second copy of it on local disk.

A failed publish leaves the payload under either setting: until the bytes are published they are work in progress, and removing them would make the retry fetch them again. When several targets in one copy arrive, `discard` must wait until **every** destination has taken the file, or a two-target run fetches every artifact twice.

**Blame is two facts, and neither is readable from an error alone.** `Error::Transport` names a URL without saying whose it was, so the *phase* supplies the end: fetching means the source, publishing means the target. But a **local fault outranks the phase** -- a write that fails while fetching from a source is this machine's disk, and filing it under the source would send somebody to check a repository that was answering perfectly. That is the same mistake `file-unreadable` made by covering reads and writes alike, which is why the two landed together: `Error::WriteFile` now reports `file-unwritable`, which is not a setup fault.

The stage comes from the error itself: `Error::Transport` carries `Contact`, set where the error is built. A failure reading a response body is `Stream`; a failure at `send` is `Connect` when the client never connected or could not build the request, and `Stream` otherwise, which covers an upload cut off mid-body and a response that never came. `Phase::blame` maps the two to the `connect` and `stream` stages. Both are still `host-unreachable`.

Bad bytes are the source's whichever phase noticed them, because the payload is what the source served. A failure that is not a transfer failure at all -- a configuration fault, a run already unwinding -- records no side rather than a guessed one, so that a count of source failures means what it says.

**A cached payload is reused only against a declared digest.** The bytes on disk are complete -- a download is written beside its destination and renamed, so an interrupted one never leaves a file that looks finished -- but complete is not current. A size is not enough, for the same reason `verified_as` refuses to call a size verification: a substitution preserving the length would pass it. A weak digest is enough, because it is what the fetch itself would have checked against and a stale cache is not the threat a collision-resistant hash exists for. A file with no digest at all is fetched again, which is unverified either way and costs a download rather than a wrong artifact.

A stale entry is removed before the replacing fetch rather than overwritten, because a cached payload is read-only: replacing in place fails outright on Windows and depends on directory permissions on Unix.

`ReportQuery::cached` answers what the report says about a file's bytes, and `commands::upload` compares it against what is on disk, so a run whose `cache-dir` moved, or whose cache was cleaned out, reports `cache-file-missing` rather than re-downloading silently -- a migration that quietly re-downloads a repository somebody thought was cached otherwise reads as merely slow.

A payload removed under `discard`, or by somebody clearing `cache-dir`, leaves a recorded entry naming a file that is not there. That needs no new state: the rule below already says a missing cache file warns and is treated as expired, which re-downloads it.

**Cache storage** is keyed by host and sandbox-relative path, because that is how the sandbox itself is keyed: two repositories on one host share one directory, and a per-repository cache record would claim two files where one exists. The entry retains the configured cache directory spelling, so moving or rebasing that directory can make a recorded file unavailable. The program warns on a missing cache file and treats it as expired, which triggers another download. A successful download overwrites the entry.

**A payload's sandbox-relative path is a hash of its URL**, `aa/bb/<sha256(url)>/<file name>`, not its file name: two artifacts on one host may share a file name, and a URL is unique within a host. The two shard levels keep a million-file repository to about fifteen entries per directory. Because a hash cannot be reversed, each host directory keeps `index.sqlite`, mapping each path to its URL, file name, and times; join `url` to `repository_file.url` for the purl. Payloads cached under the older flat layout are not found, so they are fetched again, and a report that recorded them warns `cache-file-missing`.

**Repository identity is loose**, on role and configured name. The tool records the endpoint details as last seen and does not refuse a run whose base URL or host has changed. Checking would cost flexibility the user needs to adjust a configuration over time; the assumption is that a user does not repoint a name at a different repository while reusing one database.

**Power loss may lose the last commits.** The worst case is a forgotten problem record and repeated work on a copy, both acceptable. Durability is not worth `synchronous = FULL` on every claim.

**Several targets in one copy** record exactly what two runs to different targets would: `run_repository` allows more than one target binding, and `artifact_transfer` is keyed by destination. See [several-targets.md](several-targets.md).

**Cache lifetimes.** A cached file has two limits, because they answer two questions:

```text
  fetched ----- used ----- used ---------------> now
     |<-- freshness -->|                         may it still be used?
                       |<---- retention ---->|   may it still be kept?
```

Freshness runs from the fetch and depends on what the file is: a `maven-metadata.xml` changes with every publish, a released jar never. Retention runs from the last use, so a file a migration keeps reusing stays and one nobody asks for ages out. Both are enforced when the tool reaches for a file, not by a sweep: an expired file is evicted, fetched again, recorded as `cache-entry-expired` (action `ignore`, `reason` `retention` or `freshness`), and logged at info, because expiry is configuration working rather than a fault. Deleting what no run reaches for is `scripts/db-maintenance.py prune-cache`, which reads the limits written beside each file in the cache's `index.sqlite` and so needs no configuration.

The times live in the cache index rather than the report database, so expiry works for a run without `--db`, and so an inventory document -- which the report database never records -- is judged the same way as a payload. `cache_entry` copies them for a reader and for pruning. A run judges by its own configuration, from the fetch and use times, so a changed setting applies at once.

Freshness rules are matched against a file's name, first match wins: the binding's `cache-freshness` (a server kind may render one into the source, as Maven Central does for `maven-metadata.xml*`), then `setup.cache-freshness`, then each ecosystem's built-in rules, combined because a repository manager serves several and the document names are distinct across them. A file nothing names is fresh forever. Retention is the binding's `cache-retention`, else `setup`'s, else forever. A capability is shared by every source reading one repository, so a binding's policy travels on a `Policed` handle wrapped around it rather than on the capability.

**Size caps** bound space where retention bounds age. `setup.cache-size` caps the whole cache directory and a binding's `cache-size` caps its repository's folder. After each fetch -- the one place a cache grows -- `ext::settle` records the file and trims: the binding's cap over its folder, then the shared one, least recently used first. The shared cap spans every folder under the directory, including ones no binding of the run opened, which is the point of a disk budget. Its total is summed from each folder's index once and then kept as files are recorded and removed, so a fetch does not pay for a scan.

A size eviction must never remove a file the run still needs, and a time window cannot say which those are: a long migration fetches everything within one run. So a file is **held** while it is needed -- a payload from download until its upload returns, a corpus or enumerator index until it is read -- and a held file is skipped. A run whose held files alone pass the cap stays over it rather than removing them. An eviction leaves its index row as a tombstone, so a later run that finds the file gone fetches it as a replacement instead of warning `cache-file-missing` about a loss that was policy. It is recorded as `cache-entry-evicted` (`ignore`, logged at info), with `reason` `repository` or `cache-dir`. `prune-cache --max-size` does the same for a cache no run is using.

Inside its lifetime a payload is still reused only on a digest's proof. Past its freshness, a document whose refetch fails is used anyway with `cache-entry-stale` (warn), unless the failure was a 404 or 410: that answers the question, and a copy of a document that is gone is wrong rather than old. Past its retention, a copy is evicted before the fetch and is never a fallback. The advisory corpus keeps its own stale rule, `advisory-source-stale`, and its advisor's `ttl` is its freshness.

What a source reads to learn what a repository holds is cached under a name a rule can match:

| Source site | Name |
| --- | --- |
| Maven artifact and snapshot metadata | `maven-metadata.xml` |
| Maven POM and its sidecars | the file's own name |
| Maven directory listing | `index.html` |
| npm packument | `packument.json` |
| PyPI simple page | `simple.html` |
| PyPI JSON detail | `detail.json` |
| PyPI PEP 658 document | the file's own name |
| `pypi-simple` enumerator index | `simple-index.json` |
| GitHub release | `release.json` |

Deliberately not cached, each for a reason of its own:

- **A target reading its own state.** Its answer has to be what it holds now: a cached copy would call an artifact absent after it was published, or present after it was deleted, and the copy would act on it. The PyPI simple page is cached at the source's call site for this reason, not inside the helper the target shares, and the Nexus raw target's reader is the source's type but not its handle.
- **Paged REST walks and listings** (Nexus, Artifactory, Artifact Keeper, GitHub's release list). A page is keyed by a continuation token or cursor the server may stop honoring, a walk already resumes from the report database, and a cached page would be one moment of a listing that moves under it.
- **Keyserver lookups and npm's registry keys.** A key may be revoked or rotated at any time, and a cached key would go on vouching for signatures its owner has withdrawn.
- **`HEAD` requests** for a publish time or a signature's existence. Cheap, and asking about the present.

**Turso** is not adopted. Revisit when something the bundled library cannot do turns up.

## Not in the initial version

**Merging two databases.** Surrogate keys make a merge an identifier remapping exercise rather than a concatenation, and the workflow it existed for is served by reusing one database across runs. `find` and `inspect` writing into the same file is the supported way to build one picture.

**An interactive explore script.** `scripts/explore-report-db.py` takes phrases that return summary reports; it is a first pass, and is meant to grow past it.

