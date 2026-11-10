#!/usr/bin/env python3
"""Compare what two repositories hold, as report databases recorded them.

Each side is one repository in one report database; both sides may come
from the same file. The comparison goes only as deep as both sides
recorded, per artifact:

    package   present on one side only
     version  when both sides list versions of the package
      file    when both sides list files of the artifact
       size   when both sides know the file's size
       digest per algorithm both sides recorded for the file

So a name-only inventory against a full inspection reports packages and
nothing below them, and a size recorded on one side only is not a
difference.

Writes one JSON object per difference, one per line (JSONL), e.g.

    {"level": "size", "change": "differs", "purl": "pkg:maven/g/a",
     "version": "1.2", "file": "a-1.2.jar", "left": 10, "right": 12}

The schema is schema/report-db.sql, and the reasoning behind it is
docs/contributors/report-as-database.md.

    db        a read-only connection to one report database
    load      one repository's packages, versions, files, and digests
    compare   the differences between two loaded repositories
"""

import argparse
import json
import sqlite3
import sys
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, field
from enum import Enum, StrEnum
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
        """Open the database from the file."""
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
        self, sql: str, params: Mapping[str, object]
    ) -> tuple[list[str], list[Row]]:
        """Run one query, answering its column names and every row."""
        cursor = self._connection.execute(sql, params)
        columns = [column[0] for column in cursor.description]
        return columns, cursor.fetchall()

    def close(self) -> None:
        """Close the database connection."""
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


# -- load -------------------------------------------------------------


class Role(StrEnum):
    """Role entry in the database."""
    SOURCE = "source"
    TARGET = "target"
    ENUMERATOR = "enumerator"


class ZeroSize(Enum):
    """What a recorded size of 0 means; some inspectors write 0 for unknown."""

    UNKNOWN = "unknown"
    KNOWN = "known"


class SideError(Exception):
    """The named repository is missing from the database, or ambiguous."""


@dataclass(frozen=True)
class Side:
    """One repository in one report database."""

    db: ReportDb
    path: Path
    name: str
    role: Role | None


@dataclass
class File:
    """Details about a file from the database."""
    # None when the database does not know it.
    size: int | None

    # Algorithm to every hex digest recorded under it.
    digests: dict[str, set[str]] = field(default_factory=dict)


# Package purl -> version (None for a name-only row) -> file name -> file.
type Files = dict[str, File]
type Versions = dict[str | None, Files]
type Inventory = dict[str, Versions]

REPOSITORY_SQL = """
    SELECT repository_id, role
    FROM repository
    WHERE name = :name
      AND (:role IS NULL OR role = :role)
"""

ARTIFACTS_SQL = """
    SELECT repository_artifact.repository_artifact_id, package.purl,
           artifact.version
    FROM repository_artifact
    JOIN artifact ON artifact.artifact_id = repository_artifact.artifact_id
    JOIN package ON package.package_id = artifact.package_id
    WHERE repository_artifact.repository_id = :repository
"""

FILES_SQL = """
    SELECT repository_file.repository_file_id,
           repository_file.repository_artifact_id,
           repository_file.name, repository_file.size_bytes
    FROM repository_file
    JOIN repository_artifact
      ON repository_artifact.repository_artifact_id = repository_file.repository_artifact_id
    WHERE repository_artifact.repository_id = :repository
"""

DIGESTS_SQL = """
    SELECT repository_file_digest.repository_file_id,
           repository_file_digest.algorithm, repository_file_digest.hex
    FROM repository_file_digest
    JOIN repository_file
      ON repository_file.repository_file_id = repository_file_digest.repository_file_id
    JOIN repository_artifact
      ON repository_artifact.repository_artifact_id = repository_file.repository_artifact_id
    WHERE repository_artifact.repository_id = :repository
"""


def load(side: Side, zero: ZeroSize) -> Inventory:
    """Everything one repository holds, keyed for comparison."""
    repository = _repository_id(side)
    params = {"repository": repository}

    # Each artifact row, and where its files go.
    inventory: Inventory = {}
    files_of: dict[int, Files] = {}
    _, rows = side.db.fetch(ARTIFACTS_SQL, params)
    for artifact_id, purl, version in rows:
        files = inventory.setdefault(purl, {}).setdefault(version, {})
        files_of[artifact_id] = files

    # Each file, under its artifact.
    by_file_id: dict[int, File] = {}
    _, rows = side.db.fetch(FILES_SQL, params)
    for file_id, artifact_id, name, size in rows:
        file = File(_size(size, zero))
        files_of[artifact_id][name] = file
        by_file_id[file_id] = file

    # Each digest, under its file.
    _, rows = side.db.fetch(DIGESTS_SQL, params)
    for file_id, algorithm, hex_digest in rows:
        by_file_id[file_id].digests.setdefault(algorithm, set()).add(hex_digest)

    return inventory


def _repository_id(side: Side) -> int:
    """The one repository row the side names."""
    _, rows = side.db.fetch(REPOSITORY_SQL, {"name": side.name, "role": side.role})
    if not rows:
        role = f" with role {side.role}" if side.role else ""
        raise SideError(f"{side.path}: no repository {side.name!r}{role}")

    if len(rows) > 1:
        roles = ", ".join(sorted(str(role) for _, role in rows))
        raise SideError(
            f"{side.path}: repository {side.name!r} has roles {roles}; name one"
        )

    ((repository_id, _),) = rows
    return repository_id


def _size(size: int | None, zero: ZeroSize) -> int | None:
    if size == 0 and zero is ZeroSize.UNKNOWN:
        return None

    return size


# -- compare ----------------------------------------------------------


class Level(StrEnum):
    """Difference level."""
    PACKAGE = "package"
    VERSION = "version"
    FILE = "file"
    SIZE = "size"
    DIGEST = "digest"


class Change(StrEnum):
    """Difference location."""
    LEFT_ONLY = "left-only"
    RIGHT_ONLY = "right-only"
    DIFFERS = "differs"


@dataclass(frozen=True)
class Difference:
    """One JSONL line; fields left None are not written."""

    level: Level
    change: Change
    purl: str
    version: str | None = None
    file: str | None = None
    algorithm: str | None = None
    left: object = None
    right: object = None

    def to_json(self) -> str:
        """Convert this difference into a JSON record."""
        record = {key: value for key, value in asdict(self).items() if value is not None}
        return json.dumps(record)


def compare(left: Inventory, right: Inventory) -> Iterator[Difference]:
    """Every difference, sorted by package, version, and file."""
    for purl in sorted(left.keys() | right.keys()):
        if purl not in right:
            yield Difference(Level.PACKAGE, Change.LEFT_ONLY, purl)
            continue

        if purl not in left:
            yield Difference(Level.PACKAGE, Change.RIGHT_ONLY, purl)
            continue

        yield from _versions(purl, left[purl], right[purl])


def _versions(purl: str, left: Versions, right: Versions) -> Iterator[Difference]:
    """Versions only when both sides list some; a name-only side lists none."""
    left_listed = {version for version in left if version is not None}
    right_listed = {version for version in right if version is not None}
    if not left_listed or not right_listed:
        return

    for version in sorted(left_listed | right_listed):
        if version not in right_listed:
            yield Difference(Level.VERSION, Change.LEFT_ONLY, purl, version)
            continue

        if version not in left_listed:
            yield Difference(Level.VERSION, Change.RIGHT_ONLY, purl, version)
            continue

        yield from _files(purl, version, left[version], right[version])


def _files(
    purl: str, version: str, left: Files, right: Files
) -> Iterator[Difference]:
    """Files only when both sides list some for the artifact."""
    if not left or not right:
        return

    for name in sorted(left.keys() | right.keys()):
        if name not in right:
            yield Difference(Level.FILE, Change.LEFT_ONLY, purl, version, name)
            continue

        if name not in left:
            yield Difference(Level.FILE, Change.RIGHT_ONLY, purl, version, name)
            continue

        yield from _file(purl, version, name, left[name], right[name])


def _file(
    purl: str, version: str, name: str, left: File, right: File
) -> Iterator[Difference]:
    """Size when both know it; digests under algorithms both recorded."""
    known = left.size is not None and right.size is not None
    if known and left.size != right.size:
        yield Difference(
            Level.SIZE, Change.DIFFERS, purl, version, name,
            left=left.size, right=right.size,
        )

    for algorithm in sorted(left.digests.keys() & right.digests.keys()):
        left_hex = left.digests[algorithm]
        right_hex = right.digests[algorithm]
        if left_hex == right_hex:
            continue

        yield Difference(
            Level.DIGEST, Change.DIFFERS, purl, version, name, algorithm,
            left=sorted(left_hex), right=sorted(right_hex),
        )


# -- entrypoint -------------------------------------------------------


def _write(differences: Iterator[Difference], out: TextIO) -> None:
    for difference in differences:
        print(difference.to_json(), file=out)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare two repositories recorded in report databases."
    )
    parser.add_argument("left_db", type=Path, help="the left report database")
    parser.add_argument(
        "right_db", type=Path, help="the right report database; may be the left one"
    )
    parser.add_argument("--left", required=True, help="the left repository name")
    parser.add_argument(
        "--left-role", type=Role, choices=list(Role),
        help="the left repository role, when its name has several",
    )
    parser.add_argument("--right", required=True, help="the right repository name")
    parser.add_argument(
        "--right-role", type=Role, choices=list(Role),
        help="the right repository role, when its name has several",
    )
    parser.add_argument(
        "--zero-size-known", action="store_true",
        help="compare a recorded size of 0 as a size, not as unknown",
    )
    parser.add_argument(
        "--output", type=Path, help="the JSONL file to write; standard output if absent"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """The CLI entrypoint."""
    args = _parser().parse_args(argv)
    zero = ZeroSize.KNOWN if args.zero_size_known else ZeroSize.UNKNOWN

    opened: list[ReportDb] = []
    try:
        left_db = ReportDb.open(args.left_db)
        opened.append(left_db)
        right_db = ReportDb.open(args.right_db)
        opened.append(right_db)

        left = load(Side(left_db, args.left_db, args.left, args.left_role), zero)
        right = load(Side(right_db, args.right_db, args.right, args.right_role), zero)
    except (ReportDbError, SideError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        for db in opened:
            db.close()

    if args.output is None:
        _write(compare(left, right), sys.stdout)
        return 0

    with args.output.open("w", encoding="utf-8") as out:
        _write(compare(left, right), out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
