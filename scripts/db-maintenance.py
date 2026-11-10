#!/usr/bin/env python3
"""Maintain a cache directory and the report database that records it.

    scripts/db-maintenance.py prune-cache CACHE_DIR [--max-size SIZE] [--db FILE]
        [--dry-run]
    scripts/db-maintenance.py prune-history DB [--older-than DURATION]
        [--keep-last N] [--run ID ...] [--dry-run]

Each repair is a sub-command. When you write a repair you expect to need
again, add it here as another, so the next person with the same problem
runs it rather than rewriting it.

    prune-cache     delete cached files past their retention, then the least
                    recently used until the cache fits --max-size
    prune-history   delete old runs from a report database

The cache layout is the one `ext::cache` writes:

    CACHE_DIR/<host>/index.sqlite        one row per cached file
    CACHE_DIR/<host>/3f/a2/3fa2...e1/<file>
    CACHE_DIR/<host>/documents/...

Do not run this while the tool holds the cache or the database open.
"""

import argparse
import heapq
import re
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# -- report database --------------------------------------------------

# "AMPR", as schema/report-db.sql sets it.
APPLICATION_ID = 1_095_585_874

# The schema version this script reads.
SCHEMA_VERSION = 10

# How long a statement waits on another connection before giving up.
BUSY_TIMEOUT_MILLIS = 30_000

# -- cache ------------------------------------------------------------

# The index beside every host's cached files, as `ext::cache` names it.
INDEX_FILE = "index.sqlite"

MILLIS_PER_SECOND = 1_000

# -- durations --------------------------------------------------------

# The units the tool's configuration accepts for a duration, in
# milliseconds, so `--older-than 90days` means what `cache-retention: 90 days`
# does.
MILLIS_PER_UNIT = {
    "ms": 1,
    "millisecond": 1,
    "milliseconds": 1,
    "": 1_000,
    "sec": 1_000,
    "second": 1_000,
    "seconds": 1_000,
    "min": 60_000,
    "minute": 60_000,
    "minutes": 60_000,
    "hr": 3_600_000,
    "hour": 3_600_000,
    "hours": 3_600_000,
    "day": 86_400_000,
    "days": 86_400_000,
}

# The units the tool's configuration accepts for a size, in bytes.
BYTES_PER_UNIT = {
    "": 1,
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kb": 1_000,
    "kib": 1_024,
    "k": 1_024,
    "mb": 1_000_000,
    "mib": 1_048_576,
    "m": 1_048_576,
    "gb": 1_000_000_000,
    "gib": 1_073_741_824,
    "g": 1_073_741_824,
}

DURATION_PATTERN = re.compile(r"^\s*([0-9_]+)\s*([a-z]*)\s*$")


class MaintenanceError(Exception):
    """A file this script will not change."""


@dataclass(frozen=True)
class Pruned:
    """What one host directory gave up."""

    host: str
    files: int
    size_bytes: int
    paths: list[str]


def now_ms() -> int:
    return int(time.time() * MILLIS_PER_SECOND)


def size_bytes(text: str) -> int:
    """A size as the configuration spells it, e.g. "20 GiB", in bytes."""
    found = DURATION_PATTERN.match(text.lower())
    if found is None or found.group(2) not in BYTES_PER_UNIT:
        raise argparse.ArgumentTypeError(f"not a size: {text!r}")

    return int(found.group(1).replace("_", "")) * BYTES_PER_UNIT[found.group(2)]


def duration_ms(text: str) -> int:
    """A duration as the configuration spells it, e.g. "90 days", in ms."""
    found = DURATION_PATTERN.match(text.lower())
    if found is None or found.group(2) not in MILLIS_PER_UNIT:
        raise argparse.ArgumentTypeError(f"not a duration: {text!r}")

    return int(found.group(1).replace("_", "")) * MILLIS_PER_UNIT[found.group(2)]


def open_report(path: Path) -> sqlite3.Connection:
    """A writable connection to a report database, refusing anything else."""
    if not path.is_file():
        raise MaintenanceError(f"{path}: no such file")

    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MILLIS}")

    # Off by default in SQLite; the schema's cascades depend on it.
    connection.execute("PRAGMA foreign_keys = ON")

    (application_id,) = connection.execute("PRAGMA application_id").fetchone()
    if application_id != APPLICATION_ID:
        raise MaintenanceError(f"{path}: not a report database")

    (user_version,) = connection.execute("PRAGMA user_version").fetchone()
    if user_version != SCHEMA_VERSION:
        raise MaintenanceError(
            f"{path}: schema version {user_version}, expected {SCHEMA_VERSION}"
        )

    return connection


# -- prune-cache ------------------------------------------------------


def writable(path: Path) -> None:
    """Clear a read-only flag, which a cached payload carries, so it can go."""
    try:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IWUSR)
    except OSError:
        pass


def remove_empty_parents(path: Path, stop: Path) -> None:
    """Remove the shard directories a deleted file leaves empty."""
    parent = path.parent
    while parent != stop and stop in parent.parents:
        try:
            parent.rmdir()
        except OSError:
            return
        parent = parent.parent


def prune_host(host_dir: Path, at_ms: int, dry_run: bool) -> Pruned:
    """Delete one host directory's files past retention, and their rows."""
    index = sqlite3.connect(host_dir / INDEX_FILE)
    index.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MILLIS}")

    expired = index.execute(
        "SELECT relative_path FROM entry"
        " WHERE retain_until_ms IS NOT NULL AND retain_until_ms < ?",
        (at_ms,),
    ).fetchall()

    files = 0
    size_bytes = 0
    paths = []

    for (relative_path,) in expired:
        full = host_dir / relative_path

        # Refuse a row naming somewhere outside its own directory.
        if host_dir.resolve() not in full.resolve().parents:
            raise MaintenanceError(f"{host_dir / INDEX_FILE}: {relative_path!r} leaves the cache")

        paths.append(relative_path)

        if full.is_file():
            files += 1
            size_bytes += full.stat().st_size

        if dry_run:
            continue

        writable(full)
        full.unlink(missing_ok=True)
        remove_empty_parents(full, host_dir)

        index.execute("DELETE FROM entry WHERE relative_path = ?", (relative_path,))

    index.commit()
    index.close()

    return Pruned(host_dir.name, files, size_bytes, paths)


def prune_report(report: sqlite3.Connection, pruned: Pruned, dry_run: bool) -> int:
    """Delete the report's `cache_entry` rows for what a host gave up.

    `repository_file` and `file_transfer` keep their rows; their link to the
    entry is cleared by the schema's `ON DELETE SET NULL`.
    """
    removed = 0

    for relative_path in pruned.paths:
        cursor = report.execute(
            "SELECT COUNT(*) FROM cache_entry WHERE host = ? AND relative_path = ?",
            (pruned.host, relative_path),
        )
        removed += cursor.fetchone()[0]

        if dry_run:
            continue

        report.execute(
            "DELETE FROM cache_entry WHERE host = ? AND relative_path = ?",
            (pruned.host, relative_path),
        )

    return removed


def shrink(host_dirs: list[Path], max_bytes: int, at_ms: int, dry_run: bool) -> list[Pruned]:
    """Remove the least recently used files, across every host, until the
    files still cached total `max_bytes` or less.

    Each removed file's row stays as a tombstone, as the tool leaves one, so
    a later run knows the file went for size rather than going missing.
    """
    indexes = {host_dir: sqlite3.connect(host_dir / INDEX_FILE) for host_dir in host_dirs}
    total = sum(
        index.execute(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM entry WHERE evicted_ms IS NULL"
        ).fetchone()[0]
        for index in indexes.values()
    )

    def oldest(host_dir: Path):
        rows = indexes[host_dir].execute(
            "SELECT used_ms, relative_path, COALESCE(size_bytes, 0) FROM entry"
            " WHERE evicted_ms IS NULL ORDER BY used_ms, relative_path"
        ).fetchall()
        return ((used_ms, path, size, host_dir) for used_ms, path, size in rows)

    removed: dict[Path, list[tuple[str, int]]] = {host_dir: [] for host_dir in host_dirs}

    for _, relative_path, size, host_dir in heapq.merge(*(oldest(host_dir) for host_dir in host_dirs)):
        if total <= max_bytes:
            break

        full = host_dir / relative_path
        removed[host_dir].append((relative_path, size))
        total -= size

        if dry_run:
            continue

        writable(full)
        full.unlink(missing_ok=True)
        remove_empty_parents(full, host_dir)
        indexes[host_dir].execute(
            "UPDATE entry SET evicted_ms = ? WHERE relative_path = ?", (at_ms, relative_path)
        )

    for index in indexes.values():
        index.commit()
        index.close()

    return [
        Pruned(host_dir.name, len(files), sum(size for _, size in files), [path for path, _ in files])
        for host_dir, files in removed.items()
        if files
    ]


def prune_cache(args: argparse.Namespace) -> int:
    cache_dir: Path = args.cache_dir
    if not cache_dir.is_dir():
        raise MaintenanceError(f"{cache_dir}: no such directory")

    report = open_report(args.db) if args.db else None
    at_ms = now_ms()
    verb = "would delete" if args.dry_run else "deleted"

    host_dirs = sorted(
        path for path in cache_dir.iterdir() if path.is_dir() and (path / INDEX_FILE).is_file()
    )

    def show(pruned: Pruned, why: str) -> None:
        line = f"{pruned.host}: {verb} {pruned.files} files, {pruned.size_bytes} bytes {why}"

        if report is not None:
            rows = prune_report(report, pruned, args.dry_run)
            line += f", {rows} report rows"

        print(line)

    for host_dir in host_dirs:
        show(prune_host(host_dir, at_ms, args.dry_run), "past retention")

    if args.max_size is not None:
        for pruned in shrink(host_dirs, args.max_size, at_ms, args.dry_run):
            show(pruned, "for size")

    if report is not None:
        report.commit()
        report.close()

    return 0


# -- prune-history ----------------------------------------------------


def count(text: str) -> int:
    """A count of runs, which cannot be negative."""
    if not text.isdigit():
        raise argparse.ArgumentTypeError(f"not a count: {text!r}")

    return int(text)


# Rows only history referenced, removed once the runs that referenced them
# are gone. Each query deletes the rows no surviving row points at.
ORPHANS = {
    "provenance_chain": """
        DELETE FROM provenance_chain
        WHERE provenance_chain_id NOT IN (
                SELECT provenance_chain_id FROM artifact_observation
                WHERE provenance_chain_id IS NOT NULL)
          AND provenance_chain_id NOT IN (
                SELECT provenance_chain_id FROM problem
                WHERE provenance_chain_id IS NOT NULL)
    """,
    "advisory": """
        DELETE FROM advisory
        WHERE advisory_id NOT IN (SELECT advisory_id FROM observation_advisory)
    """,
    "suppression": """
        DELETE FROM suppression
        WHERE suppression_id NOT IN (
                SELECT suppression_id FROM observation_advisory
                WHERE suppression_id IS NOT NULL)
    """,
    "bypass": """
        DELETE FROM bypass
        WHERE bypass_id NOT IN (
                SELECT bypass_id FROM observation_quarantine
                WHERE bypass_id IS NOT NULL)
          AND bypass_id NOT IN (
                SELECT bypass_id FROM problem WHERE bypass_id IS NOT NULL)
    """,
}


def selected_runs(report: sqlite3.Connection, args: argparse.Namespace) -> list[int]:
    """The runs the options name, newest last.

    `--run` and `--older-than` add runs; with neither, `--keep-last` starts
    from every run. `--keep-last` then spares the newest N of the whole
    database, whatever else selected them.
    """
    runs = report.execute("SELECT run_id, started_ms FROM run ORDER BY started_ms, run_id").fetchall()

    named = set(args.run or [])
    cutoff_ms = None if args.older_than is None else now_ms() - args.older_than

    chosen = [
        run_id
        for run_id, started_ms in runs
        if run_id in named
        or (cutoff_ms is not None and started_ms < cutoff_ms)
        or (not named and cutoff_ms is None)
    ]

    if args.keep_last is None:
        return chosen

    spared = {run_id for run_id, _ in runs[len(runs) - args.keep_last :]}

    return [run_id for run_id in chosen if run_id not in spared]


def prune_history(args: argparse.Namespace) -> int:
    if args.run is None and args.older_than is None and args.keep_last is None:
        raise MaintenanceError("name what to prune: --older-than, --keep-last, or --run")

    report = open_report(args.db)
    runs = selected_runs(report, args)
    verb = "would delete" if args.dry_run else "deleted"

    if args.dry_run:
        print(f"{verb} {len(runs)} runs: {', '.join(map(str, runs)) or 'none'}")
        report.close()
        return 0

    # One transaction: a run is history in a dozen tables, and the schema's
    # cascades remove all of it with the run row.
    report.executemany("DELETE FROM run WHERE run_id = ?", [(run_id,) for run_id in runs])

    orphans = {table: report.execute(sql).rowcount for table, sql in ORPHANS.items()}
    report.commit()

    # Outside the transaction, which it cannot run inside.
    report.execute("PRAGMA incremental_vacuum")
    report.close()

    removed = ", ".join(f"{count} {table}" for table, count in orphans.items())
    print(f"{verb} {len(runs)} runs: {', '.join(map(str, runs)) or 'none'}; orphans: {removed}")

    return 0


# -- entrypoint -------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    prune = commands.add_parser(
        "prune-cache", help="delete cached files past their retention"
    )
    prune.add_argument("cache_dir", type=Path, help="the configured setup.cache-dir")
    prune.add_argument(
        "--max-size", type=size_bytes, metavar="SIZE",
        help="then remove the least recently used files until the cache fits, e.g. '20 GiB'",
    )
    prune.add_argument(
        "--db", type=Path, help="a report database whose cache_entry rows to prune too"
    )
    prune.add_argument(
        "--dry-run", action="store_true", help="report what would go, change nothing"
    )
    prune.set_defaults(run_command=prune_cache)

    history = commands.add_parser(
        "prune-history",
        help="delete old runs from a report database",
        description=(
            "Delete runs and everything recorded under them: report records, "
            "observations, problems, summaries, transfer attempts, walks. The "
            "inventory, the transfer summaries, and cache_entry are current "
            "state and stay. Nothing is spared: pruning an unfinished run "
            "loses the walk a later run would resume, and pruning a "
            "repository's last complete walk loses the date 'artifacts since' "
            "is measured from."
        ),
    )
    history.add_argument("db", type=Path, help="the report database")
    history.add_argument(
        "--older-than", type=duration_ms, metavar="DURATION",
        help="runs that started longer ago than this, e.g. '90 days'",
    )
    history.add_argument(
        "--keep-last", type=count, metavar="N",
        help="spare the newest N runs; alone, prune every other run",
    )
    history.add_argument(
        "--run", type=int, action="append", metavar="ID",
        help="a run to prune, as 'show runs' lists them; repeatable",
    )
    history.add_argument(
        "--dry-run", action="store_true", help="list the runs, change nothing"
    )
    history.set_defaults(run_command=prune_history)

    args = parser.parse_args(argv)

    try:
        return args.run_command(args)
    except (MaintenanceError, sqlite3.Error, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
