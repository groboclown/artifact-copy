#!/usr/bin/env python3
"""Explore a report database interactively.

Reads statements from standard input and prints what they ask for. A
statement is

    VERB [QUERY] [key=value ...]

ended by a newline, a `;`, or the end of input. Values take shell-style
quoting, so `repo="my repo"` names a repository with a space in it.

The schema is schema/report-db.sql, and the reasoning behind it is
docs/contributors/report-as-database.md.

    repl      read statements, prompt on a terminal, report errors
    verbs     what each verb does with a statement
    queries   the named queries `show` runs, and the keys each takes
    parse     text into statements
    db        a read-only connection to one report database
"""

import argparse
import csv
import shlex
import sqlite3
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TextIO

# -- db ---------------------------------------------------------------

# "AMPR", as schema/report-db.sql sets it.
APPLICATION_ID = 1_095_585_874

# The schema version this script reads.
SCHEMA_VERSION = 10

# How long a read waits on a running writer before giving up.
BUSY_TIMEOUT_MILLIS = 30_000

# Opens without creating, so a mistyped path fails instead of reporting an
# empty database.
READ_ONLY_URI_SUFFIX = "?mode=ro"


class ReportDbError(Exception):
    """The file is missing, unreadable, or not a report database."""


type Row = tuple[object, ...]


class ReportDb:
    """A read-only connection to one report database."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def open(cls, path: Path) -> "ReportDb":
        if not path.is_file():
            raise ReportDbError(f"{path}: no such file")

        try:
            connection = sqlite3.connect(
                path.resolve().as_uri() + READ_ONLY_URI_SUFFIX, uri=True
            )
            connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MILLIS}")
            _check_identity(connection, path)
        except sqlite3.Error as error:
            raise ReportDbError(f"{path}: {error}") from error

        return cls(connection)

    def fetch(
        self, sql: str, params: Mapping[str, str | None]
    ) -> tuple[list[str], list[Row]]:
        """Run one query, answering its column names and every row."""
        cursor = self._connection.execute(sql, params)
        columns = [column[0] for column in cursor.description]
        return columns, cursor.fetchall()

    def close(self) -> None:
        self._connection.close()


def _check_identity(connection: sqlite3.Connection, path: Path) -> None:
    """Refuse another application's file, or a schema this script cannot read."""
    (application_id,) = connection.execute("PRAGMA application_id").fetchone()
    if application_id != APPLICATION_ID:
        raise ReportDbError(f"{path}: not a report database")

    (user_version,) = connection.execute("PRAGMA user_version").fetchone()
    if user_version != SCHEMA_VERSION:
        raise ReportDbError(
            f"{path}: schema version {user_version}, expected {SCHEMA_VERSION}"
        )


# -- parse ------------------------------------------------------------

STATEMENT_END = ";"
KEY_VALUE_SEPARATOR = "="


class InputError(Exception):
    """A statement this script cannot run, reported and then skipped."""


class Verb(StrEnum):
    """The allowed verbs."""
    SHOW = "show"
    HELP = "help"
    EXIT = "exit"


@dataclass(frozen=True)
class Statement:
    verb: Verb
    query: str | None
    args: dict[str, str]


def parse(text: str) -> list[Statement]:
    """Split text into statements, e.g. "show a; help" into two."""
    statements = []
    for words in _split(text):
        if not words:
            continue

        statements.append(_statement(words))

    return statements


def _split(text: str) -> list[list[str]]:
    """Tokenize, grouping words between newlines and `;`."""
    groups: list[list[str]] = []
    for line in text.splitlines():
        lexer = shlex.shlex(line, posix=True, punctuation_chars=STATEMENT_END)
        lexer.whitespace_split = True
        group: list[str] = []

        try:
            for token in lexer:
                if token == STATEMENT_END:
                    groups.append(group)
                    group = []
                    continue

                group.append(token)
        except ValueError as error:
            raise InputError(str(error)) from error

        groups.append(group)

    return groups


class TakesSubcmd(StrEnum):
    """How the command uses a sub-command, if any."""
    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


def _statement(words: list[str]) -> Statement:
    head, *rest = words
    try:
        verb = Verb(head)
    except ValueError:
        raise InputError(f"unknown verb {head!r}; try `help`") from None

    # A query is the first word that is not key=value, when the verb takes one.
    query = None
    if (
        VERBS[verb].takes_subcmd == TakesSubcmd.OPTIONAL
        and rest and KEY_VALUE_SEPARATOR not in rest[0]
    ):
        query, *rest = rest
    if VERBS[verb].takes_subcmd == TakesSubcmd.REQUIRED:
        if not rest or KEY_VALUE_SEPARATOR in rest[0]:
            raise InputError(f"`{verb}` needs a sub-command; try `help {verb}`")
        query, *rest = rest

    return Statement(verb, query, _args(rest))


def _args(words: list[str]) -> dict[str, str]:
    args: dict[str, str] = {}
    for word in words:
        key, separator, value = word.partition(KEY_VALUE_SEPARATOR)
        if not separator or not key:
            raise InputError(f"expected key=value, found {word!r}")

        if key in args:
            raise InputError(f"key {key!r} given twice")

        args[key] = value

    return args


# -- queries ----------------------------------------------------------


class Role(StrEnum):
    SOURCE = "source"
    TARGET = "target"
    ENUMERATOR = "enumerator"


# Ecosystems whose artifacts may have no version, as each one's
# `Ecosystem::version_optional` answers. A row with no version elsewhere is
# a name nobody resolved, which `copy --from-db` skips.
VERSION_OPTIONAL_ECOSYSTEMS = ("raw",)
VERSION_OPTIONAL_SQL = ", ".join(f"'{ecosystem}'" for ecosystem in VERSION_OPTIONAL_ECOSYSTEMS)

# Keys whose values must come from a fixed set.
KEY_CHOICES: dict[str, type[StrEnum]] = {"role": Role}


@dataclass(frozen=True)
class Query:
    summary: str
    sql: str
    required: frozenset[str] = frozenset()
    optional: frozenset[str] = frozenset()


QUERIES: dict[str, Query] = {
    "list-repositories": Query(
        summary="Every configured source, target, and enumerator binding.",
        sql="SELECT name, role, host, base_url, ecosystem FROM repository",
    ),
    "artifacts-for": Query(
        summary="What one repository holds; role narrows a name shared across roles.",
        sql="""
            SELECT artifact.purl, artifact.version,
                   repository_artifact.last_download_state
            FROM repository_artifact
            JOIN artifact ON repository_artifact.artifact_id = artifact.artifact_id
            JOIN repository
              ON repository_artifact.repository_id = repository.repository_id
            WHERE repository.name = :repo
              AND (:role IS NULL OR repository.role = :role)
        """,
        required=frozenset({"repo"}),
        optional=frozenset({"role"}),
    ),
    "files-for": Query(
        summary="Files known for an artifact + version.",
        sql="""
            SELECT repository_file.name, repository_file.url, repository_file.size_bytes
            FROM repository_file
            JOIN repository_artifact ON repository_file.repository_artifact_id = repository_artifact.repository_artifact_id
            JOIN artifact ON repository_artifact.artifact_id = artifact.artifact_id
            JOIN repository
              ON repository_artifact.repository_id = repository.repository_id
            WHERE repository.name = :repo
              AND artifact.purl = :purl
              AND (:version IS NULL OR artifact.version = :version)
        """,
        required=frozenset({"purl", "repo"}),
        optional=frozenset({"version"}),
    ),
    # The resume query from report-as-database.md, without its paging, less
    # the rows `copy --from-db` skips: a row with no version is copied only
    # where its ecosystem has none to give (`Ecosystem::version_optional`).
    "left-to-copy": Query(
        summary="What a source still has to deliver to a destination.",
        sql=f"""
            SELECT ra.repository_artifact_id, a.purl, a.version, a.release,
                   ra.declared_license, ra.published_ms
            FROM repository_artifact ra
            JOIN artifact a ON a.artifact_id = ra.artifact_id
            JOIN package p ON p.package_id = a.package_id
            JOIN repository origin ON origin.repository_id = ra.repository_id
            LEFT JOIN repository target
                   ON target.role = 'target' AND target.name = :destination
            LEFT JOIN artifact_transfer t
                   ON t.artifact_id = a.artifact_id
                  AND t.destination_repository_id = target.repository_id
            LEFT JOIN transfer_state s ON s.state = t.state
            WHERE origin.role = 'source' AND origin.name = :source
              AND (a.version IS NOT NULL
                   OR p.ecosystem IN ({VERSION_OPTIONAL_SQL}))
              AND (t.state IS NULL OR s.terminal = 0)
            ORDER BY ra.repository_artifact_id
        """,
        required=frozenset({"source", "destination"}),
    ),
    "runs": Query(
        summary="List all the runs.",
        sql="""
        SELECT
            run_id, artifacts, worst_action
        FROM run_summary
        """,
    ),
    "failures": Query(
        summary="Find the failures for a run.",
        sql="""
        SELECT
            run_id,
            code,
            message_text
        FROM problem
        WHERE
            (:run IS NULL OR run_id = :run)
            AND (:code IS NULL OR code = :code)
        """,
        optional=frozenset({"run", "code"}),
    ),
    "artifacts-not-found": Query(
        summary="List artifacts not found.",
        sql="""
        SELECT
            problem.run_id AS run_id,
            artifact.purl AS purl,
            -- artifact.version AS version,
            -- problem.message_args,
            -- json_extract(problem.message_args, '$.url') AS url,
            json_extract(problem.message_args, '$.file') AS file
        FROM problem
        LEFT JOIN artifact ON artifact.artifact_id = problem.artifact_id
        WHERE
            (:run IS NULL OR run_id = :run)
            AND code = 'artifact-not-found'
        """,
        optional=frozenset({"run"}),
    ),
    "quarantined": Query(
        summary="List quarantined artifacts.",
        sql="""
        -- Quarantines land in two places: reservations attached to an
        -- artifact record, and standalone problem records.  A database
        -- written before problems carried artifact_id falls back to the
        -- purl argument.
        WITH held AS (
            SELECT
                artifact_observation.run_id AS run_id,
                artifact_observation.artifact_id AS artifact_id,
                observation_quarantine.code AS code,
                observation_quarantine.class AS class
            FROM observation_quarantine
            JOIN artifact_observation
                ON artifact_observation.artifact_observation_id = observation_quarantine.artifact_observation_id
            WHERE observation_quarantine.bypass_id IS NULL
            UNION
            SELECT
                problem.run_id,
                COALESCE(
                    problem.artifact_id,
                    artifact_observation.artifact_id,
                    artifact.artifact_id
                ),
                problem.code,
                problem.quarantine
            FROM problem
            LEFT JOIN artifact_observation
                ON artifact_observation.artifact_observation_id = problem.artifact_observation_id
            LEFT JOIN artifact
                ON problem.artifact_id IS NULL
                AND artifact.purl = json_extract(problem.message_args, '$.purl')
            WHERE
                problem.quarantine IS NOT NULL
                AND problem.bypass_id IS NULL
        )
        SELECT
            package.ecosystem AS ecosystem,
            package.namespace AS namespace,
            package.name AS name,
            artifact.version AS version,
            held.code AS code,
            held.class AS class
        FROM held
        LEFT JOIN artifact ON artifact.artifact_id = held.artifact_id
        LEFT JOIN package ON package.package_id = artifact.package_id
        WHERE
            (:run IS NULL OR held.run_id = :run)
            AND (:code IS NULL or held.code = :code)
            AND (:class IS NULL or held.class = :class)
        """,
        optional=frozenset({"run", "code", "class"}),
    ),
    "blocked": Query(
        summary="List artifacts refused whole, with the reason.",
        sql="""
        -- Refusals land in two places: a copy's `refused` outcome, whose
        -- reason the problem names, and a `skip-artifact` problem raised by
        -- a command that records no outcome (find, inspect).  Problems about
        -- an artifact whose transfer failed are left out: that is a broken
        -- transfer, not a refusal.  A database written before problems
        -- carried artifact_id falls back to the purl argument.
        WITH blocked AS (
            SELECT
                artifact_observation.run_id AS run_id,
                artifact_observation.artifact_id AS artifact_id,
                problem.code AS code,
                problem.message_text AS reason
            FROM artifact_observation
            LEFT JOIN problem
                ON problem.artifact_observation_id = artifact_observation.artifact_observation_id
            WHERE artifact_observation.outcome = 'refused'
            UNION
            SELECT
                problem.run_id,
                COALESCE(problem.artifact_id, artifact.artifact_id),
                problem.code,
                problem.message_text
            FROM problem
            LEFT JOIN artifact
                ON problem.artifact_id IS NULL
                AND artifact.purl = json_extract(problem.message_args, '$.purl')
            WHERE
                problem.action = 'skip-artifact'
                AND problem.artifact_observation_id IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM artifact_observation AS failed
                    WHERE failed.run_id = problem.run_id
                        AND failed.artifact_id = COALESCE(problem.artifact_id, artifact.artifact_id)
                        AND failed.outcome = 'failed'
                )
        )
        SELECT
            blocked.run_id AS run,
            package.ecosystem AS ecosystem,
            package.namespace AS namespace,
            package.name AS name,
            artifact.version AS version,
            blocked.code AS code,
            blocked.reason AS reason
        FROM blocked
        JOIN artifact ON artifact.artifact_id = blocked.artifact_id
        JOIN package ON package.package_id = artifact.package_id
        WHERE (:run IS NULL OR blocked.run_id = :run)
        ORDER BY blocked.run_id, package.ecosystem, package.namespace, package.name, artifact.version
        """,
        optional=frozenset({"run"}),
    ),
    "unresolved": Query(
        summary="List requests that resolved to no artifact, with the reason.",
        sql="""
        -- An unresolved request has no version, so the request itself
        -- (e.g. `^2.0.0`) says what was asked for.
        SELECT
            artifact_observation.run_id AS run,
            package.ecosystem AS ecosystem,
            package.namespace AS namespace,
            package.name AS name,
            artifact_observation.requested AS requested,
            problem.code AS code,
            problem.message_text AS reason
        FROM artifact_observation
        JOIN artifact ON artifact.artifact_id = artifact_observation.artifact_id
        JOIN package ON package.package_id = artifact.package_id
        LEFT JOIN problem
            ON problem.artifact_observation_id = artifact_observation.artifact_observation_id
        WHERE
            artifact_observation.outcome = 'unresolved'
            AND (:run IS NULL OR artifact_observation.run_id = :run)
        ORDER BY artifact_observation.run_id, package.ecosystem, package.namespace, package.name
        """,
        optional=frozenset({"run"}),
    ),
    "discovered-problem-codes": Query(
        summary="List all problem codes discovered.",
        sql="""
        SELECT
            code,
            COUNT(1) AS count
        FROM problem
        WHERE (:run IS NULL OR run_id = :run)
        GROUP BY code
        """,
        optional=frozenset({"run"}),
    ),
    "unmatched-licenses": Query(
        summary="List all licenses that don't have a known SPDX.",
        sql="""
        SELECT
            DISTINCT json_extract(problem.message_args, '$.declared') AS license
        FROM problem
        WHERE
            (:run IS NULL OR run_id = :run)
            AND (code = 'license-unmatched')
        ORDER BY license
        """,
        optional=frozenset({"run"}),
    ),
    "with-unknown-licenses": Query(
        summary="List all artifacts with unknown licenses.",
        sql="""
        SELECT
            DISTINCT json_extract(problem.message_args, '$.purl') AS purl
        FROM problem
        WHERE
            (:run IS NULL OR run_id = :run)
            AND (code = 'license-unknown')
        ORDER BY purl
        """,
        optional=frozenset({"run"}),
    ),
}


def _lookup(name: str) -> Query:
    query = QUERIES.get(name)
    if query is None:
        raise InputError(f"unknown query {name!r}; try `help verb={Verb.SHOW}`")

    return query


def _params(query: Query, args: Mapping[str, str]) -> dict[str, str | None]:
    """Check args against what the query takes; absent optional keys bind null."""
    unknown = args.keys() - query.required - query.optional
    if unknown:
        raise InputError(f"unknown keys: {', '.join(sorted(unknown))}")

    missing = query.required - args.keys()
    if missing:
        raise InputError(f"missing keys: {', '.join(sorted(missing))}")

    for key, value in args.items():
        choices = KEY_CHOICES.get(key)
        if choices is None or value in choices:
            continue

        allowed = ", ".join(choices)
        raise InputError(f"{key} must be one of {allowed}, found {value!r}")

    return {key: args.get(key) for key in query.required | query.optional}


# -- verbs ------------------------------------------------------------

SYNTAX = "VERB [QUERY] [key=value ...]  (ended by newline, ;, or end of input)"

type Handler = Callable[[ReportDb, Statement, TextIO], None]


def _show(db: ReportDb, statement: Statement, out: TextIO) -> None:
    """Print one query's rows as CSV, header first; null prints empty."""
    assert statement.query is not None
    query = _lookup(statement.query)
    columns, rows = db.fetch(query.sql, _params(query, statement.args))

    writer = csv.writer(out)
    writer.writerow(columns)
    writer.writerows(rows)


def _help(_db: ReportDb, statement: Statement, out: TextIO) -> None:
    """List the verbs, or detail one."""
    name = statement.query
    if name is None:
        print(SYNTAX, file=out)
        for verb, spec in VERBS.items():
            print(f"  {verb:<6} {spec.summary}", file=out)

        return

    try:
        verb = Verb(name)
    except ValueError:
        raise InputError(f"unknown verb {name!r}") from None

    spec = VERBS[verb]
    print(spec.syntax, file=out)
    print(f"  {spec.summary}", file=out)
    if verb is Verb.SHOW:
        _describe_queries(out)


def _describe_queries(out: TextIO) -> None:
    """Each query, its keys (optional in brackets), and what it answers."""
    print("Queries:", file=out)
    for name, query in QUERIES.items():
        keys = [f"{key}=NAME" for key in sorted(query.required)]
        keys += [f"[{key}=NAME]" for key in sorted(query.optional)]
        print(f"  {' '.join([name, *keys])}", file=out)
        print(f"      {query.summary}", file=out)


@dataclass(frozen=True)
class VerbSpec:
    """Help + syntax + handler for a verb."""
    syntax: str
    summary: str
    takes_subcmd: TakesSubcmd
    handler: Handler


VERBS: dict[Verb, VerbSpec] = {
    Verb.SHOW: VerbSpec(
        syntax="show QUERY [key=value ...]",
        summary="Print a query's rows as CSV.",
        takes_subcmd=TakesSubcmd.REQUIRED,
        handler=_show,
    ),
    Verb.HELP: VerbSpec(
        syntax="help [NAME]",
        summary="List the verbs, or describe one.",
        takes_subcmd=TakesSubcmd.OPTIONAL,
        handler=_help,
    ),
    Verb.EXIT: VerbSpec(
        syntax="exit",
        summary="Exit the program.  Or, use ctrl-d.",
        takes_subcmd=TakesSubcmd.NONE,
        handler=lambda _x, _y, _z: sys.exit(0),
    ),
}


# -- repl -------------------------------------------------------------

PROMPT = "report> "


def _run(db: ReportDb, text: str) -> None:
    """Run every statement in text, reporting and skipping ones that fail."""
    try:
        statements = parse(text)
    except InputError as error:
        print(f"error: {error}", file=sys.stderr)
        return

    for statement in statements:
        try:
            VERBS[statement.verb].handler(db, statement, sys.stdout)
        except (InputError, sqlite3.Error) as error:
            print(f"error: {error}", file=sys.stderr)


def _interact(db: ReportDb) -> None:
    # Imported only here: it gives input() history and line editing.
    import readline  # noqa: F401

    while True:
        try:
            line = input(PROMPT)
        except EOFError:
            print()
            return
        except KeyboardInterrupt:
            print()
            continue

        _run(db, line)


# -- entrypoint -------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """The CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Explore a report database.")
    parser.add_argument("database", type=Path, help="the report database file")
    args = parser.parse_args(argv)

    try:
        db = ReportDb.open(args.database)
    except ReportDbError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        if sys.stdin.isatty():
            _interact(db)
            return 0

        for line in sys.stdin:
            _run(db, line)

        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
