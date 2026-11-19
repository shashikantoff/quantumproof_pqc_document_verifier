"""Create, verify, and restore PostgreSQL custom-format backups via Compose."""

import argparse
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import BinaryIO


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_USER = "verifier"
SOURCE_DATABASE = "verifier"


def _compose(*arguments: str, stdin: BinaryIO | None = None, stdout=None) -> None:
    subprocess.run(
        ["docker", "compose", *arguments],
        cwd=PROJECT_ROOT,
        stdin=stdin,
        stdout=stdout,
        check=True,
    )


def _backup_archive(path: Path) -> None:
    with path.open("rb") as archive:
        _compose(
            "exec",
            "-T",
            "db",
            "pg_restore",
            "--list",
            stdin=archive,
            stdout=subprocess.DEVNULL,
        )


def _restore_archive(path: Path, database: str) -> None:
    with path.open("rb") as archive:
        _compose(
            "exec",
            "-T",
            "db",
            "pg_restore",
            "-U",
            DATABASE_USER,
            "--no-owner",
            "--no-acl",
            "--exit-on-error",
            "--dbname",
            database,
            stdin=archive,
        )


def _create_database(database: str) -> None:
    _compose(
        "exec",
        "-T",
        "db",
        "createdb",
        "-U",
        DATABASE_USER,
        "--template",
        "template0",
        database,
    )


def _drop_database(database: str) -> None:
    _compose("exec", "-T", "db", "dropdb", "-U", DATABASE_USER, database)


def _verify_database(database: str) -> None:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            DATABASE_USER,
            "-d",
            database,
            "-At",
            "-c",
            "SELECT count(*) FROM documents",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    if not result.stdout.strip().isdigit():
        raise RuntimeError("restored database did not return a valid document count")


def _temporary_restore(path: Path) -> None:
    database = f"qp_restore_test_{uuid.uuid4().hex[:12]}"
    _create_database(database)
    try:
        _restore_archive(path, database)
        _verify_database(database)
    finally:
        _drop_database(database)


def backup(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing backup: {path}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            _compose(
                "exec",
                "-T",
                "db",
                "pg_dump",
                "-U",
                DATABASE_USER,
                "-d",
                SOURCE_DATABASE,
                "--format=custom",
                "--no-owner",
                "--no-acl",
                stdout=output,
            )
        _backup_archive(temporary_path)
        if path.exists():
            raise FileExistsError(f"refusing to overwrite existing backup: {path}")
        temporary_path.rename(path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def verify(path: Path) -> None:
    _backup_archive(path)
    _temporary_restore(path)


def restore(path: Path, database: str) -> None:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,62}", database):
        raise ValueError("database name must be 1-63 letters, digits, or underscores")
    if database == SOURCE_DATABASE:
        raise ValueError("restore requires a new database name, not the live database")

    _create_database(database)
    try:
        _restore_archive(path, database)
        _verify_database(database)
    except Exception:
        _drop_database(database)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    backup_parser = commands.add_parser("backup", help="create a custom-format backup")
    backup_parser.add_argument("--output", required=True, type=Path)

    verify_parser = commands.add_parser(
        "verify",
        help="restore the archive into a disposable database and validate it",
    )
    verify_parser.add_argument("archive", type=Path)

    restore_parser = commands.add_parser(
        "restore",
        help="restore into a new database without overwriting existing data",
    )
    restore_parser.add_argument("archive", type=Path)
    restore_parser.add_argument("--database", required=True)

    args = parser.parse_args()
    if args.command == "backup":
        backup(args.output.expanduser().resolve())
        print(f"Backup created and archive-checked: {args.output}")
    elif args.command == "verify":
        verify(args.archive.expanduser().resolve())
        print("Backup restored successfully into a disposable database.")
    else:
        restore(args.archive.expanduser().resolve(), args.database)
        print(
            f"Backup restored to new database {args.database!r}; "
            "the existing verifier database was not changed."
        )


if __name__ == "__main__":
    main()
