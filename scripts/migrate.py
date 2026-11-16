#!/usr/bin/env python3
"""
Database Migration Script
Handles database schema migrations
"""

import asyncio
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.database import db_manager, Base
from sqlalchemy import text


MIGRATIONS = [
    {
        "version": 1,
        "description": "Initial schema",
        "sql": None,  # Handled by Base.metadata.create_all
    },
    {
        "version": 2,
        "description": "Add evidence table indexes",
        "sql": """
            CREATE INDEX IF NOT EXISTS idx_evidence_finding_type ON evidence(finding_id, type);
            CREATE INDEX IF NOT EXISTS idx_evidence_created ON evidence(created_at);
        """,
    },
    {
        "version": 3,
        "description": "Add finding duplicate tracking",
        "sql": """
            CREATE INDEX IF NOT EXISTS idx_findings_duplicate ON findings(duplicate_of);
        """,
    },
    {
        "version": 4,
        "description": "Add scan session indexes",
        "sql": """
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_sessions(status);
            CREATE INDEX IF NOT EXISTS idx_scans_type ON scan_sessions(scan_type);
        """,
    },
    {
        "version": 5,
        "description": "Add activity log indexes",
        "sql": """
            CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_log(action);
            CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at);
        """,
    },
    {
        "version": 6,
        "description": "Add scope checklist indexes",
        "sql": """
            CREATE INDEX IF NOT EXISTS idx_scope_status ON scope_checklist(status);
            CREATE INDEX IF NOT EXISTS idx_scope_type ON scope_checklist(item_type);
        """,
    },
    {
        "version": 7,
        "description": "Add target indexes for recon",
        "sql": """
            CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip);
            CREATE INDEX IF NOT EXISTS idx_targets_service ON targets(service);
        """,
    },
    {
        "version": 8,
        "description": "Add endpoint indexes",
        "sql": """
            CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);
            CREATE INDEX IF NOT EXISTS idx_endpoints_method ON endpoints(method);
        """,
    },
]


async def get_current_version() -> int:
    """Get current migration version"""
    async with db_manager.get_session() as session:
        # Create migration table if not exists
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        await session.commit()

        result = await session.execute(text("SELECT MAX(version) FROM schema_migrations"))
        version = result.scalar()
        return version or 0


async def apply_migration(migration: dict) -> bool:
    """Apply a single migration"""
    async with db_manager.get_session() as session:
        try:
            if migration["sql"]:
                await session.execute(text(migration["sql"]))

            # Record migration
            await session.execute(text(
                "INSERT INTO schema_migrations (version, description) VALUES (:version, :description)"
            ), {"version": migration["version"], "description": migration["description"]})

            await session.commit()
            return True
        except Exception as e:
            print(f"Migration {migration['version']} failed: {e}")
            await session.rollback()
            return False


async def run_migrations():
    """Run all pending migrations"""
    await db_manager.initialize()

    current_version = await get_current_version()
    print(f"Current schema version: {current_version}")

    pending = [m for m in MIGRATIONS if m["version"] > current_version]

    if not pending:
        print("No pending migrations")
        return

    print(f"Found {len(pending)} pending migrations")

    for migration in pending:
        print(f"Applying migration {migration['version']}: {migration['description']}")
        success = await apply_migration(migration)
        if success:
            print(f"  ✓ Migration {migration['version']} applied")
        else:
            print(f"  ✗ Migration {migration['version']} failed")
            return False

    print("All migrations completed successfully")
    return True


async def create_tables():
    """Create all tables from models"""
    await db_manager.initialize()
    await db_manager.create_tables()
    print("Tables created successfully")


async def drop_tables():
    """Drop all tables (DANGEROUS)"""
    confirm = input("This will DELETE ALL DATA. Type 'YES' to confirm: ")
    if confirm != "YES":
        print("Cancelled")
        return

    await db_manager.initialize()
    async with db_manager.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    print("All tables dropped")


async def reset_database():
    """Reset database (drop and recreate)"""
    await drop_tables()
    await create_tables()
    print("Database reset complete")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Database migration tool")
    parser.add_argument("command", choices=["migrate", "create", "drop", "reset", "version"],
                       help="Command to run")
    args = parser.parse_args()

    if args.command == "migrate":
        asyncio.run(run_migrations())
    elif args.command == "create":
        asyncio.run(create_tables())
    elif args.command == "drop":
        asyncio.run(drop_tables())
    elif args.command == "reset":
        asyncio.run(reset_database())
    elif args.command == "version":
        asyncio.run(db_manager.initialize())
        version = await get_current_version()
        print(f"Schema version: {version}")