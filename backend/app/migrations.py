"""Apply versioned database migrations and safely adopt legacy create_all schemas."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from .database import Base


_LEGACY_TABLES = frozenset(
    {
        "admin_users",
        "admin_sessions",
        "issuers",
        "issuer_audit_events",
        "documents",
        "audit_events",
        "development_ledger_records",
    }
)


def _migration_config(connection) -> Config:
    backend_dir = Path(__file__).resolve().parents[1]
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "migrations").replace("%", "%%"))
    config.attributes["connection"] = connection
    return config


def _adopt_legacy_schema(connection) -> bool:
    inspector = inspect(connection)
    existing_tables = set(inspector.get_table_names())
    if "alembic_version" in existing_tables:
        return False

    application_tables = existing_tables & _LEGACY_TABLES
    if not application_tables:
        return False
    if application_tables != _LEGACY_TABLES:
        missing = sorted(_LEGACY_TABLES - application_tables)
        raise RuntimeError(
            "Cannot adopt a partial legacy schema; missing tables: "
            + ", ".join(missing)
        )

    missing_columns: list[str] = []
    for table_name in sorted(_LEGACY_TABLES):
        actual = {column["name"] for column in inspector.get_columns(table_name)}
        expected = set(Base.metadata.tables[table_name].columns.keys())
        missing_columns.extend(
            f"{table_name}.{column}" for column in sorted(expected - actual)
        )
    if missing_columns:
        raise RuntimeError(
            "Cannot adopt a legacy schema with missing columns: "
            + ", ".join(missing_columns)
        )
    return True


def run_migrations(engine: Engine) -> None:
    """Upgrade an empty database or migrate a validated legacy schema to head."""
    with engine.connect() as connection:
        config = _migration_config(connection)
        should_adopt = _adopt_legacy_schema(connection)
    if should_adopt:
        with engine.connect() as connection:
            config = _migration_config(connection)
            command.stamp(config, "0001_initial")
    with engine.connect() as connection:
        config = _migration_config(connection)
        command.upgrade(config, "head")
