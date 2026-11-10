-- The report database, schema version 10.
--
-- One database holds many runs of many commands against many repositories.
-- It answers three questions that a line report cannot: what does a source
-- hold, what has reached a target, and what is left to do.
--
-- The reasoning behind every choice here lives in
-- docs/contributors/report-as-database.md.  What follows is only the shape.
--
-- Conventions, applied without exception:
--
--   *_id     a surrogate integer key
--   *_ms     a time, as milliseconds since the Unix epoch, UTC
--   STRICT   every table, so a column's declared type is enforced
--
-- Times are integers rather than text because the two chrono renderings a
-- Rust writer produces do not compare equal to each other, and a
-- maintenance script written in another language produces a third.
--
-- An enumeration this tool may extend gets a lookup table rather than a
-- CHECK constraint, because SQLite cannot alter a constraint and rebuilding
-- a table of ten million rows to add one problem code is not acceptable.
-- The key is the text itself rather than a number: the space a number would
-- save is not worth making every hand-written query join to read a code.
-- An enumeration fixed by the published report format keeps its CHECK.

-- -- Durable settings ------------------------------------------------------
--
-- page_size and auto_vacuum take effect only before the first table exists,
-- and afterwards only a full VACUUM can change them.  auto_vacuum is
-- INCREMENTAL so that pruning history can return space to the filesystem.
--
-- Connection settings -- foreign_keys, busy_timeout, synchronous -- are not
-- here.  They are per connection and belong with the code that opens one.

PRAGMA page_size = 4096;
PRAGMA auto_vacuum = INCREMENTAL;

-- "AMPR", so that file(1) and every other tool can tell what this is.
PRAGMA application_id = 1095585874;
PRAGMA user_version = 10;

-- -- Vocabulary ------------------------------------------------------------

-- Problem codes, as core::problem::Code spells them.  A writer inserts an
-- unseen code on first use, so a database written by a newer tool stays
-- readable by an older one.
CREATE TABLE IF NOT EXISTS problem_code (
    code TEXT PRIMARY KEY
) STRICT, WITHOUT ROWID;

-- What became of one artifact at one destination.
--
-- `terminal` is what the resume query joins on, so the set of finished
-- states lives here rather than repeated in every WHERE clause.
CREATE TABLE IF NOT EXISTS transfer_state (
    state TEXT PRIMARY KEY,
    terminal INTEGER NOT NULL CHECK (terminal IN (0, 1))
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO transfer_state (state, terminal) VALUES
    ('pending', 0),
    ('in-progress', 0),
    ('failed', 0),
    ('copied', 1),
    ('already-present', 1),
    ('refused', 1),
    ('unresolved', 1),
    ('skipped', 1);

-- What became of one file, moving in one direction.
CREATE TABLE IF NOT EXISTS file_state (
    state TEXT PRIMARY KEY,
    terminal INTEGER NOT NULL CHECK (terminal IN (0, 1))
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO file_state (state, terminal) VALUES
    ('pending', 0),
    ('in-progress', 0),
    ('failed', 0),
    ('uploaded', 1),
    ('downloaded', 1),
    ('already-present', 1),
    ('skipped', 1);

-- Which end of a transfer failed, and at what point.  Two axes, because a
-- target that ran out of disk and a source that would not read differ by
-- side, while a connection that dropped and a read that failed differ by
-- stage.
--
-- `connect` means no connection was made: configuration or a firewall.
-- `stream` means one was made and then lost, timed out, or cut off part way
-- through a body in either direction: a flaky link that retrying fixes.
CREATE TABLE IF NOT EXISTS error_side (
    side TEXT PRIMARY KEY
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO error_side (side) VALUES ('source'), ('target'), ('local');

CREATE TABLE IF NOT EXISTS error_stage (
    stage TEXT PRIMARY KEY
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO error_stage (stage) VALUES
    ('connect'), ('stream'), ('request'), ('read'), ('write'), ('verify'), ('publish');

-- Why an artifact was looked at, as model::Cause spells it.
--
-- Unlike problem codes, the writer never inserts here: every kind this
-- build knows is seeded below, and a provenance link naming any other kind
-- is refused rather than stored.
CREATE TABLE IF NOT EXISTS cause_kind (
    kind TEXT PRIMARY KEY
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO cause_kind (kind) VALUES
    ('requested'), ('lock-file'), ('dependency'), ('enumerated'), ('report');

-- -- The database itself ---------------------------------------------------

-- One row, mirroring the pragmas above so a reader that cannot ask for a
-- pragma still learns what it has.
CREATE TABLE IF NOT EXISTS database_metadata (
    only_row INTEGER PRIMARY KEY CHECK (only_row = 1),
    schema_version INTEGER NOT NULL,
    created_ms INTEGER NOT NULL,
    created_by_tool_version TEXT NOT NULL
) STRICT;

-- -- Repositories and runs -------------------------------------------------

-- One configured binding.  Identity is the role and the configured name:
-- the endpoint details are recorded as last seen and are not checked, so a
-- user may adjust a configuration over time without rebuilding a database.
CREATE TABLE IF NOT EXISTS repository (
    repository_id INTEGER PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('source', 'target', 'enumerator')),
    name TEXT NOT NULL,
    host TEXT,
    base_url TEXT,
    ecosystem TEXT,
    UNIQUE (role, name)
) STRICT;

-- One command invocation.  Any command, not only a copy.
--
-- A run with no finish time and no live process crashed; that is what lets
-- a later run reclaim its abandoned claims.
CREATE TABLE IF NOT EXISTS run (
    run_id INTEGER PRIMARY KEY,
    command TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    started_ms INTEGER NOT NULL,
    finished_ms INTEGER,
    completion TEXT CHECK (completion IN ('finished', 'failed', 'cancelled')),
    worst_action TEXT CHECK (
        worst_action IN ('ignore', 'warn', 'stop-spider', 'skip-artifact', 'abort')
    )
) STRICT;

-- Every binding a run used, written when the run opens rather than when
-- each is first touched, so a finder can be built from keys that exist.
--
-- More than one target in a run is allowed: two destinations keep separate
-- transfer state, exactly as two runs to different targets would.
CREATE TABLE IF NOT EXISTS run_repository (
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    repository_id INTEGER NOT NULL REFERENCES repository (repository_id),

    -- Lower wins.  Only meaningful for a source.
    priority INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY (run_id, repository_id)
) STRICT, WITHOUT ROWID;

-- One Header.corpus_age entry.  Always written, even when empty, because a
-- clean report and an unscreened one must not look alike.
CREATE TABLE IF NOT EXISTS run_corpus (
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    advisor TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('consulted', 'skipped-by-request', 'unavailable')),
    modified_ms INTEGER,
    why TEXT,
    PRIMARY KEY (run_id, advisor)
) STRICT, WITHOUT ROWID;

-- One catalog walk, and where it stopped.
--
-- Without the cursor, resuming an interrupted walk of a million-artifact
-- repository means paging from the beginning again, which costs hours.
CREATE TABLE IF NOT EXISTS repository_enumeration (
    repository_enumeration_id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    repository_id INTEGER NOT NULL REFERENCES repository (repository_id),
    enumerator_kind TEXT NOT NULL,

    -- How far the enumerator's listing reaches, as it declared: a name-only
    -- inventory holds no versions, and a later reader must not take the
    -- absence of one as a repository without any.
    depth TEXT NOT NULL CHECK (depth IN ('names', 'versions', 'files')),

    -- What the walk was asked for, so a partial artifact enumeration is not
    -- mistaken for a complete inventory.
    scope TEXT,

    -- Opaque, and meaningful only to the enumerator that issued it.
    cursor TEXT,

    pages INTEGER NOT NULL DEFAULT 0,
    found INTEGER NOT NULL DEFAULT 0,

    -- Only a walk that reached the end of the catalog dates an inventory.
    reached_end INTEGER NOT NULL DEFAULT 0 CHECK (reached_end IN (0, 1)),

    checkpoint_ms INTEGER NOT NULL,

    -- One walk of one repository per run, updated in place as it pages.
    -- A row per page would make the history of a million-artifact walk
    -- larger than the inventory it produced.
    UNIQUE (run_id, repository_id)
) STRICT;

CREATE INDEX IF NOT EXISTS repository_enumeration_resume
    ON repository_enumeration (repository_id, repository_enumeration_id);

-- -- Identity --------------------------------------------------------------

-- Name-level identity, in pieces.
--
-- `purl` is everything up to the version, rendered by ArtifactId, and is
-- the key an upsert uses.  The pieces beside it are what a query filters
-- on, and what a reader rebuilds an ArtifactId from -- nothing in the tool
-- parses a purl.
CREATE TABLE IF NOT EXISTS package (
    package_id INTEGER PRIMARY KEY,
    purl TEXT NOT NULL UNIQUE,
    ecosystem TEXT NOT NULL,
    namespace TEXT,
    name TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS package_name ON package (ecosystem, name);

-- One purl qualifier.  Maven uses `type` and `classifier`, PyPI uses
-- `file_name`, and the set is open, so this is a table rather than columns.
CREATE TABLE IF NOT EXISTS package_qualifier (
    package_id INTEGER NOT NULL REFERENCES package (package_id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (package_id, key)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS package_qualifier_value ON package_qualifier (key, value);

-- One version of a package, or the name-only row when a catalog lists
-- names and the versions would cost a request each.
--
-- `purl` unique is what keeps a package to one name-only row: SQLite counts
-- each null in a unique index as distinct, so (package_id, version) could
-- not do it.
--
-- `release` is stored rather than recomputed so a reader can build a
-- Version without a configured session.  It is derived, so a reconfigured
-- version handler leaves it stale until the next artifact enumeration
-- rewrites it.
--
-- Not every row was observed.  A dependency link creates its parent's row
-- when the database has not seen it, so counting artifacts counts parents
-- too; join `repository_artifact` or `artifact_observation` to count what
-- a repository holds or a run reported.
CREATE TABLE IF NOT EXISTS artifact (
    artifact_id INTEGER PRIMARY KEY,
    package_id INTEGER NOT NULL REFERENCES package (package_id) ON DELETE CASCADE,
    purl TEXT NOT NULL UNIQUE,
    version TEXT,
    release TEXT CHECK (release IN ('general', 'pre-release')),
    CHECK ((version IS NULL) = (release IS NULL))
) STRICT;

CREATE INDEX IF NOT EXISTS artifact_of_package ON artifact (package_id, version);

-- -- Inventory -------------------------------------------------------------

-- What one repository holds, as last observed.  Facts from one repository
-- never overwrite another's.
CREATE TABLE IF NOT EXISTS repository_artifact (
    repository_artifact_id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repository (repository_id),
    artifact_id INTEGER NOT NULL REFERENCES artifact (artifact_id) ON DELETE CASCADE,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    published_ms INTEGER,

    -- Three states, not an optional time: a repository that records no
    -- download and one that reports no statistics are different facts, and
    -- only the first is evidence of disuse.
    last_download_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (last_download_state IN ('at', 'never', 'unknown')),
    last_download_ms INTEGER,

    declared_license TEXT,

    -- The run that last observed this artifact here, so work read back out
    -- of the inventory can say which run recorded it.  Null when only a
    -- target's contents were recorded: `copy` noting that a target holds
    -- an artifact writes no observation, so no run is set.  A source row
    -- always carries one.
    last_seen_run_id INTEGER REFERENCES run (run_id) ON DELETE SET NULL,

    UNIQUE (repository_id, artifact_id),
    CHECK ((last_download_state = 'at') = (last_download_ms IS NOT NULL))
) STRICT;

-- Serves the resume walk, which filters by repository and pages by key.
CREATE INDEX IF NOT EXISTS repository_artifact_walk
    ON repository_artifact (repository_id, repository_artifact_id);

-- One cached payload.
--
-- Keyed by host and sandbox-relative path because that is how the sandbox
-- itself is keyed: two repositories on one host share one directory, and a
-- per-repository cache row would claim two files where one exists.
CREATE TABLE IF NOT EXISTS cache_entry (
    cache_entry_id INTEGER PRIMARY KEY,
    host TEXT NOT NULL,

    -- The configured spelling, kept as written.  Rebasing it can make a
    -- recorded file unavailable, which the tool treats as an expired entry.
    cache_dir TEXT NOT NULL,

    relative_path TEXT NOT NULL,
    size_bytes INTEGER,
    verification TEXT CHECK (verification IN (
        'not-attempted', 'no-digest-declared', 'weak-digest-only', 'verified', 'failed'
    )),
    downloaded_ms INTEGER NOT NULL,

    -- The cache's own retention and freshness, copied from its index when
    -- the payload was last fetched or used: last use, and the times past
    -- which the cache would evict the file (null is forever).  A run judges
    -- by its own configuration; these are for a reader and for pruning.
    used_ms INTEGER NOT NULL,
    retain_until_ms INTEGER,
    fresh_until_ms INTEGER,
    UNIQUE (host, relative_path)
) STRICT;

-- One file of one repository artifact, as last inspected.  An `inspect`
-- creates this row with no transfer activity at all.
--
-- One row whoever named the file: an artifact enumeration listing the
-- catalog, a resolution, or both.  The two markers say which, and when
-- last; a copy combines them rather than trusting either alone.  See
-- docs/contributors/sources-and-targets.md.
CREATE TABLE IF NOT EXISTS repository_file (
    repository_file_id INTEGER PRIMARY KEY,
    repository_artifact_id INTEGER NOT NULL
        REFERENCES repository_artifact (repository_artifact_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    size_bytes INTEGER,
    verification TEXT CHECK (verification IN (
        'not-attempted', 'no-digest-declared', 'weak-digest-only', 'verified', 'failed'
    )),
    cache_entry_id INTEGER REFERENCES cache_entry (cache_entry_id) ON DELETE SET NULL,

    -- Whether a PEP 658 core-metadata document sits beside the file, at
    -- `{url}.metadata`.  NULL when only an artifact enumeration listed it,
    -- since a catalog does not say; its digests are in repository_file_core_metadata_digest.
    core_metadata INTEGER CHECK (core_metadata IN (0, 1)),

    -- When an artifact enumeration last listed this file, and when a
    -- resolution last named it.  At least one is set.
    listed_ms INTEGER,
    resolved_ms INTEGER,
    CHECK (listed_ms IS NOT NULL OR resolved_ms IS NOT NULL),
    UNIQUE (repository_artifact_id, name)
) STRICT;

CREATE TABLE IF NOT EXISTS repository_file_digest (
    repository_file_id INTEGER NOT NULL
        REFERENCES repository_file (repository_file_id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL,
    hex TEXT NOT NULL,
    PRIMARY KEY (repository_file_id, algorithm, hex)
) STRICT, WITHOUT ROWID;

-- The digests the index published for a file's core-metadata document, so
-- a copy driven from the database checks the document as the source would.
CREATE TABLE IF NOT EXISTS repository_file_core_metadata_digest (
    repository_file_id INTEGER NOT NULL
        REFERENCES repository_file (repository_file_id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL,
    hex TEXT NOT NULL,
    PRIMARY KEY (repository_file_id, algorithm, hex)
) STRICT, WITHOUT ROWID;

-- Without these, a copy driven from the database would publish files it
-- could not check, and would be quietly less verified than the same copy
-- driven from the source.
CREATE TABLE IF NOT EXISTS repository_file_signature (
    repository_file_signature_id INTEGER PRIMARY KEY,
    repository_file_id INTEGER NOT NULL
        REFERENCES repository_file (repository_file_id) ON DELETE CASCADE,
    scheme TEXT NOT NULL,
    key_id TEXT,

    -- The signature itself, or the URL it lives at for a detached scheme.
    value TEXT,
    url TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS repository_file_signature_of_file
    ON repository_file_signature (repository_file_id);

-- -- Provenance ------------------------------------------------------------

-- One leaf-first causal chain.  A chain per observation or problem; the
-- shape allows sharing one chain between them later without moving rows.
CREATE TABLE IF NOT EXISTS provenance_chain (
    provenance_chain_id INTEGER PRIMARY KEY
) STRICT;

-- One Cause, in pieces rather than as the prose a line report renders.
-- Only the columns its kind carries are set.
CREATE TABLE IF NOT EXISTS provenance_item (
    provenance_chain_id INTEGER NOT NULL
        REFERENCES provenance_chain (provenance_chain_id) ON DELETE CASCADE,

    -- 0 is the leaf, counting outwards to the root cause.
    ordinal INTEGER NOT NULL,

    -- A `Cause` crosses the report boundary as a message id plus named
    -- arguments, so the kind and the columns below come from those rather
    -- than from the English.
    kind TEXT NOT NULL REFERENCES cause_kind (kind),

    -- requested
    arg TEXT,

    -- lock-file
    lock_path TEXT,
    lock_entry TEXT,

    -- dependency: the parent, not this artifact, at the version it resolved
    -- to, so an edge is keyed on one release
    parent_artifact_id INTEGER REFERENCES artifact (artifact_id) ON DELETE SET NULL,
    dep_kind TEXT,

    -- enumerated
    enumerator TEXT,

    -- report: a report database used as a work list, the exact purl it
    -- listed, the source it was read for, and the run that recorded it; the
    -- targets the work was outstanding for are in provenance_destination
    report_path TEXT,
    report_entry TEXT,
    report_source TEXT,
    report_run_id INTEGER REFERENCES run (run_id) ON DELETE SET NULL,

    -- What a line report would have shown, kept so a database record and a
    -- JSONL record of the same run read alike.
    rendered TEXT NOT NULL,

    PRIMARY KEY (provenance_chain_id, ordinal)
) STRICT, WITHOUT ROWID;

-- The targets a report link's work was outstanding for, in the run's --to
-- order.  None for an inventory.
CREATE TABLE IF NOT EXISTS provenance_destination (
    provenance_chain_id INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,

    -- The target's place in the list, counting from 0.
    position INTEGER NOT NULL,

    destination TEXT NOT NULL,

    PRIMARY KEY (provenance_chain_id, ordinal, position),
    FOREIGN KEY (provenance_chain_id, ordinal)
        REFERENCES provenance_item (provenance_chain_id, ordinal) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

-- -- Acknowledgements ------------------------------------------------------

-- A quarantine acknowledgement somebody wrote in the policy file.
CREATE TABLE IF NOT EXISTS bypass (
    bypass_id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    justification TEXT,
    expires_ms INTEGER
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS bypass_identity
    ON bypass (source, IFNULL(justification, ''), IFNULL(expires_ms, -1));

-- A VEX statement.  Shaped like a bypass and kept apart from it: one comes
-- from a standard document with its own vocabulary, the other from this
-- tool's own file.
CREATE TABLE IF NOT EXISTS suppression (
    suppression_id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    justification TEXT,
    detail TEXT
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS suppression_identity
    ON suppression (source, IFNULL(justification, ''), IFNULL(detail, ''));

CREATE TABLE IF NOT EXISTS advisory (
    advisory_id INTEGER PRIMARY KEY,
    id TEXT NOT NULL,
    -- 'malware' or 'vulnerability'.
    kind TEXT NOT NULL,
    summary TEXT,
    UNIQUE (kind, id)
) STRICT;

-- -- The record stream -----------------------------------------------------

-- Stream order, so a reader reproduces the Record entries a line report
-- would have held without a second report model being invented.
CREATE TABLE IF NOT EXISTS report_record (
    report_record_id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    at_ms INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('header', 'artifact', 'problem', 'summary')),
    UNIQUE (run_id, sequence)
) STRICT;

-- Every ArtifactRecord, kept even after a later artifact enumeration
-- changes the summary row it fed.
CREATE TABLE IF NOT EXISTS artifact_observation (
    artifact_observation_id INTEGER PRIMARY KEY,
    report_record_id INTEGER REFERENCES report_record (report_record_id) ON DELETE SET NULL,
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    artifact_id INTEGER NOT NULL REFERENCES artifact (artifact_id) ON DELETE CASCADE,
    repository_artifact_id INTEGER
        REFERENCES repository_artifact (repository_artifact_id) ON DELETE SET NULL,

    -- What was asked for, when the request is worth keeping beside the
    -- answer: a request that resolved to nothing has no version for a
    -- second reason.
    requested TEXT,

    version TEXT,
    last_download_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (last_download_state IN ('at', 'never', 'unknown')),
    last_download_ms INTEGER,
    declared_license TEXT,
    published_ms INTEGER,

    -- Absent for `inspect` and `find`, which report rather than act.
    outcome TEXT CHECK (outcome IN (
        'copied', 'already-present', 'refused', 'unresolved', 'failed'
    )),
    outcome_verification TEXT CHECK (outcome_verification IN (
        'not-attempted', 'no-digest-declared', 'weak-digest-only', 'verified', 'failed'
    )),

    provenance_chain_id INTEGER
        REFERENCES provenance_chain (provenance_chain_id) ON DELETE SET NULL
) STRICT;

CREATE INDEX IF NOT EXISTS observation_of_run ON artifact_observation (run_id);
CREATE INDEX IF NOT EXISTS observation_of_artifact ON artifact_observation (artifact_id);

-- What became of an observed artifact at each target, when a copy had
-- several.  artifact_observation.outcome is then the worst of these.
CREATE TABLE IF NOT EXISTS observation_outcome (
    artifact_observation_id INTEGER NOT NULL
        REFERENCES artifact_observation (artifact_observation_id) ON DELETE CASCADE,
    destination_repository_id INTEGER NOT NULL
        REFERENCES repository (repository_id) ON DELETE CASCADE,

    -- The target's place in the run's --to list, counting from 0.
    ordinal INTEGER NOT NULL,

    outcome TEXT NOT NULL CHECK (outcome IN (
        'copied', 'already-present', 'refused', 'unresolved', 'failed'
    )),
    outcome_verification TEXT CHECK (outcome_verification IN (
        'not-attempted', 'no-digest-declared', 'weak-digest-only', 'verified', 'failed'
    )),

    -- The reason a refused or failed outcome carries.
    problem_id INTEGER REFERENCES problem (problem_id) ON DELETE SET NULL,

    PRIMARY KEY (artifact_observation_id, destination_repository_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS observation_file (
    observation_file_id INTEGER PRIMARY KEY,
    artifact_observation_id INTEGER NOT NULL
        REFERENCES artifact_observation (artifact_observation_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    size_bytes INTEGER,
    verification TEXT CHECK (verification IN (
        'not-attempted', 'no-digest-declared', 'weak-digest-only', 'verified', 'failed'
    )),
    origin TEXT NOT NULL CHECK (origin IN ('listed', 'resolved')),
    repository_file_id INTEGER REFERENCES repository_file (repository_file_id) ON DELETE SET NULL,

    -- As repository_file.core_metadata, for what this observation saw.
    core_metadata INTEGER CHECK (core_metadata IN (0, 1))
) STRICT;

-- Keyed by position rather than by digest, because this is an event table:
-- it holds what a registry declared, in the order it declared it. The
-- inventory's own digest table de-duplicates instead, which is the right
-- rule for a summary and the wrong one for a record of what was said.
CREATE TABLE IF NOT EXISTS observation_file_digest (
    observation_file_id INTEGER NOT NULL
        REFERENCES observation_file (observation_file_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    hex TEXT NOT NULL,
    PRIMARY KEY (observation_file_id, ordinal)
) STRICT, WITHOUT ROWID;

-- The digests of the core-metadata document, in the order declared.
CREATE TABLE IF NOT EXISTS observation_file_core_metadata_digest (
    observation_file_id INTEGER NOT NULL
        REFERENCES observation_file (observation_file_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    hex TEXT NOT NULL,
    PRIMARY KEY (observation_file_id, ordinal)
) STRICT, WITHOUT ROWID;

-- The signatures the registry declared, in the order declared; shaped as
-- repository_file_signature.
CREATE TABLE IF NOT EXISTS observation_file_signature (
    observation_file_id INTEGER NOT NULL
        REFERENCES observation_file (observation_file_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    key_id TEXT,
    value TEXT,
    url TEXT,
    PRIMARY KEY (observation_file_id, ordinal)
) STRICT, WITHOUT ROWID;

-- A message travels as an identifier plus named arguments, with the English
-- as a fallback.  The arguments are a JSON object rather than a child
-- table: Message::args is always string to string.
CREATE TABLE IF NOT EXISTS observation_license (
    artifact_observation_id INTEGER PRIMARY KEY
        REFERENCES artifact_observation (artifact_observation_id) ON DELETE CASCADE,
    decision TEXT NOT NULL,
    spdx TEXT,
    reason_id TEXT NOT NULL,
    reason_args TEXT CHECK (reason_args IS NULL OR json_valid(reason_args)),
    reason_text TEXT
) STRICT;

-- One allowed usage is enough to migrate an artifact, so this is where the
-- usages that refused it are recorded.
CREATE TABLE IF NOT EXISTS observation_license_usage (
    artifact_observation_id INTEGER NOT NULL
        REFERENCES observation_license (artifact_observation_id) ON DELETE CASCADE,
    dep_kind TEXT NOT NULL,
    decision TEXT NOT NULL,
    PRIMARY KEY (artifact_observation_id, dep_kind)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS observation_advisory (
    artifact_observation_id INTEGER NOT NULL
        REFERENCES artifact_observation (artifact_observation_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    advisory_id INTEGER NOT NULL REFERENCES advisory (advisory_id),
    -- The configured advisor whose corpus supplied the record.  Per
    -- observation rather than per advisory: the same record may come from
    -- a different corpus in another run.
    advisor TEXT NOT NULL,
    -- 'affected', or 'version-unusable' when no version in the advisory
    -- could be compared with this one.
    certainty TEXT NOT NULL,
    suppression_id INTEGER REFERENCES suppression (suppression_id),
    PRIMARY KEY (artifact_observation_id, ordinal)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS observation_advisory_by_advisory
    ON observation_advisory (advisory_id);

-- A reservation held against an artifact.  A bypass being present is the
-- interesting case: a reservation that held an artifact back shows in the
-- artifact's absence, one somebody waved through shows nowhere else.
CREATE TABLE IF NOT EXISTS observation_quarantine (
    artifact_observation_id INTEGER NOT NULL
        REFERENCES artifact_observation (artifact_observation_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    code TEXT NOT NULL REFERENCES problem_code (code),
    class TEXT NOT NULL CHECK (class IN ('soft', 'hard')),

    -- Whether the run's strictness rather than the class held this back.
    hardened INTEGER NOT NULL DEFAULT 0 CHECK (hardened IN (0, 1)),

    bypass_id INTEGER REFERENCES bypass (bypass_id),

    -- Keyed by position, not by code: an artifact can trip one code twice,
    -- and keying on the code would silently drop the second.
    PRIMARY KEY (artifact_observation_id, ordinal)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS observation_quarantine_by_code
    ON observation_quarantine (code);

-- Every standalone ProblemRecord, and every Outcome reason.
CREATE TABLE IF NOT EXISTS problem (
    problem_id INTEGER PRIMARY KEY,
    report_record_id INTEGER REFERENCES report_record (report_record_id) ON DELETE SET NULL,
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,

    -- The artifact the message's `purl` argument names, which a problem
    -- raised under a subject always has.  A problem sink sees many
    -- problems that are about no artifact at all.
    artifact_id INTEGER REFERENCES artifact (artifact_id) ON DELETE SET NULL,

    -- Set when this problem is an observation's outcome reason.
    artifact_observation_id INTEGER
        REFERENCES artifact_observation (artifact_observation_id) ON DELETE CASCADE,

    code TEXT NOT NULL REFERENCES problem_code (code),
    action TEXT NOT NULL CHECK (
        action IN ('ignore', 'warn', 'stop-spider', 'skip-artifact', 'abort')
    ),
    quarantine TEXT CHECK (quarantine IN ('soft', 'hard')),
    bypass_id INTEGER REFERENCES bypass (bypass_id),
    message_id TEXT NOT NULL,
    message_args TEXT CHECK (message_args IS NULL OR json_valid(message_args)),
    message_text TEXT,
    provenance_chain_id INTEGER
        REFERENCES provenance_chain (provenance_chain_id) ON DELETE SET NULL
) STRICT;

CREATE INDEX IF NOT EXISTS problem_of_run ON problem (run_id);
CREATE INDEX IF NOT EXISTS problem_of_artifact ON problem (artifact_id);
CREATE INDEX IF NOT EXISTS problem_by_code ON problem (code);

-- -- Summaries -------------------------------------------------------------

CREATE TABLE IF NOT EXISTS run_summary (
    run_id INTEGER PRIMARY KEY REFERENCES run (run_id) ON DELETE CASCADE,
    report_record_id INTEGER REFERENCES report_record (report_record_id) ON DELETE SET NULL,
    artifacts INTEGER NOT NULL,
    worst_action TEXT NOT NULL CHECK (
        worst_action IN ('ignore', 'warn', 'stop-spider', 'skip-artifact', 'abort')
    )
) STRICT;

CREATE TABLE IF NOT EXISTS summary_code_count (
    run_id INTEGER NOT NULL REFERENCES run_summary (run_id) ON DELETE CASCADE,
    code TEXT NOT NULL REFERENCES problem_code (code),
    count INTEGER NOT NULL,
    PRIMARY KEY (run_id, code)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS summary_quarantine_count (
    run_id INTEGER NOT NULL REFERENCES run_summary (run_id) ON DELETE CASCADE,
    class TEXT NOT NULL CHECK (class IN ('soft', 'hard')),
    count INTEGER NOT NULL,
    PRIMARY KEY (run_id, class)
) STRICT, WITHOUT ROWID;

-- As `document#advisory`.  An empty set does not mean every suppression is
-- live; it means none the run exercised were dead.
CREATE TABLE IF NOT EXISTS summary_unmatched_suppression (
    run_id INTEGER NOT NULL REFERENCES run_summary (run_id) ON DELETE CASCADE,
    statement TEXT NOT NULL,
    PRIMARY KEY (run_id, statement)
) STRICT, WITHOUT ROWID;

-- -- Transfers -------------------------------------------------------------

-- The current state of one artifact at one destination.
--
-- Keyed by artifact and destination rather than by source: an artifact a
-- higher-priority source already delivered must stop a lower-priority one
-- without that query naming either source.
CREATE TABLE IF NOT EXISTS artifact_transfer (
    artifact_transfer_id INTEGER PRIMARY KEY,
    artifact_id INTEGER NOT NULL REFERENCES artifact (artifact_id) ON DELETE CASCADE,
    destination_repository_id INTEGER NOT NULL REFERENCES repository (repository_id),

    -- The source the last attempt read from, which is an attribute and not
    -- part of the key.
    source_repository_id INTEGER REFERENCES repository (repository_id),

    state TEXT NOT NULL REFERENCES transfer_state (state),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    first_attempt_ms INTEGER,
    last_attempt_ms INTEGER,
    completed_ms INTEGER,
    UNIQUE (artifact_id, destination_repository_id)
) STRICT;

-- The resume walk asks "has this artifact reached this destination", which
-- is an outer join against every row including the finished ones, so the
-- unique index above is the one it uses.  This one answers the different
-- question of listing what is outstanding, and is restricted so that it
-- stays proportional to the work left rather than to the catalog.
CREATE INDEX IF NOT EXISTS artifact_transfer_outstanding
    ON artifact_transfer (destination_repository_id, artifact_id)
    WHERE state IN ('pending', 'in-progress', 'failed');

CREATE TABLE IF NOT EXISTS artifact_transfer_attempt (
    artifact_transfer_attempt_id INTEGER PRIMARY KEY,
    artifact_transfer_id INTEGER NOT NULL
        REFERENCES artifact_transfer (artifact_transfer_id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    source_repository_id INTEGER REFERENCES repository (repository_id),
    started_ms INTEGER NOT NULL,
    finished_ms INTEGER,
    state TEXT NOT NULL REFERENCES transfer_state (state),
    verification TEXT CHECK (verification IN (
        'not-attempted', 'no-digest-declared', 'weak-digest-only', 'verified', 'failed'
    )),
    problem_id INTEGER REFERENCES problem (problem_id) ON DELETE SET NULL
) STRICT;

CREATE INDEX IF NOT EXISTS artifact_transfer_attempt_of_transfer
    ON artifact_transfer_attempt (artifact_transfer_id, artifact_transfer_attempt_id);

CREATE INDEX IF NOT EXISTS artifact_transfer_attempt_of_run
    ON artifact_transfer_attempt (run_id, artifact_transfer_attempt_id);

-- Moving one file, in one direction.  A download names no destination
-- repository and ends at a cache entry; an upload names one.
--
-- Uniqueness is two partial indexes rather than one constraint, because a
-- null destination would make every download row distinct from every other.
CREATE TABLE IF NOT EXISTS file_transfer (
    file_transfer_id INTEGER PRIMARY KEY,
    repository_file_id INTEGER NOT NULL
        REFERENCES repository_file (repository_file_id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('download', 'upload')),
    destination_repository_id INTEGER REFERENCES repository (repository_id),
    cache_entry_id INTEGER REFERENCES cache_entry (cache_entry_id) ON DELETE SET NULL,
    state TEXT NOT NULL REFERENCES file_state (state),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    first_attempt_ms INTEGER,
    last_attempt_ms INTEGER,
    completed_ms INTEGER,
    CHECK ((direction = 'upload') = (destination_repository_id IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS file_transfer_download
    ON file_transfer (repository_file_id)
    WHERE direction = 'download';

CREATE UNIQUE INDEX IF NOT EXISTS file_transfer_upload
    ON file_transfer (repository_file_id, destination_repository_id)
    WHERE direction = 'upload';

CREATE TABLE IF NOT EXISTS file_transfer_attempt (
    file_transfer_attempt_id INTEGER PRIMARY KEY,
    file_transfer_id INTEGER NOT NULL
        REFERENCES file_transfer (file_transfer_id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,

    -- Set when this file moved as part of an artifact's copy.
    artifact_transfer_attempt_id INTEGER
        REFERENCES artifact_transfer_attempt (artifact_transfer_attempt_id) ON DELETE SET NULL,

    started_ms INTEGER NOT NULL,
    finished_ms INTEGER,
    state TEXT NOT NULL REFERENCES file_state (state),
    verification TEXT CHECK (verification IN (
        'not-attempted', 'no-digest-declared', 'weak-digest-only', 'verified', 'failed'
    )),
    error_side TEXT REFERENCES error_side (side),
    error_stage TEXT REFERENCES error_stage (stage),
    problem_id INTEGER REFERENCES problem (problem_id) ON DELETE SET NULL
) STRICT;

CREATE INDEX IF NOT EXISTS file_transfer_attempt_of_transfer
    ON file_transfer_attempt (file_transfer_id, file_transfer_attempt_id);

-- -- Dependency walks ------------------------------------------------------

-- One dependency walk of one source under one `--dependencies` spec, for
-- one set of targets.
--
-- Owned by the run walking it.  A later run adopts a walk whose run never
-- closed by taking it over, which is what resumes a killed walk.
CREATE TABLE IF NOT EXISTS spider_walk (
    spider_walk_id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES run (run_id) ON DELETE CASCADE,
    repository_id INTEGER NOT NULL REFERENCES repository (repository_id),
    spec TEXT NOT NULL,

    -- The copy's targets, sorted and comma-joined; empty for a walk that
    -- copies nothing.  Part of the key, because a walk marks what it
    -- visited, and a run with another set of targets has other work.
    targets TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX IF NOT EXISTS spider_walk_resume
    ON spider_walk (repository_id, spec, targets, spider_walk_id);

-- One request the walk discovered.
--
-- `version_spec` and `provenance` are the walk's own JSON, read back only
-- by the walk: work state, not report records.  Both are cleared once the
-- task is done; the key stays, so the request is not queued again.
CREATE TABLE IF NOT EXISTS spider_task (
    spider_task_id INTEGER PRIMARY KEY,
    spider_walk_id INTEGER NOT NULL
        REFERENCES spider_walk (spider_walk_id) ON DELETE CASCADE,
    request_key TEXT NOT NULL,
    purl TEXT NOT NULL,
    version_spec TEXT,
    provenance TEXT,
    depth INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'in-progress', 'done')),
    UNIQUE (spider_walk_id, request_key)
) STRICT;

-- Partial, so it stays the size of the work left.
CREATE INDEX IF NOT EXISTS spider_task_next
    ON spider_task (spider_walk_id, depth, spider_task_id)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS spider_task_in_progress
    ON spider_task (spider_walk_id)
    WHERE state = 'in-progress';

-- A resolved coordinate the walk claimed, and the task that claimed it.
--
-- The task is kept so a resumed walk can withdraw the claims of tasks that
-- never finished; otherwise the retried task would find its own claim and
-- drop the artifact.
CREATE TABLE IF NOT EXISTS spider_claim (
    spider_walk_id INTEGER NOT NULL
        REFERENCES spider_walk (spider_walk_id) ON DELETE CASCADE,
    resolved_purl TEXT NOT NULL,
    spider_task_id INTEGER NOT NULL
        REFERENCES spider_task (spider_task_id) ON DELETE CASCADE,
    PRIMARY KEY (spider_walk_id, resolved_purl)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS spider_claim_of_task
    ON spider_claim (spider_task_id);
