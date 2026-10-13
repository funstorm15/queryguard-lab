"""Disposable synthetic fixtures and database execution boundaries."""

import sqlite3

PUBLIC_COLUMNS = ("id", "tenant_id", "customer", "amount_cents", "status")
TENANTS = ("alpha", "beta")


def connect() -> sqlite3.Connection:
    # Never accepts a database path: even destructive cases use fresh memory.
    db = sqlite3.connect(":memory:", cached_statements=0)
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL,
            customer TEXT NOT NULL, amount_cents INTEGER NOT NULL,
            status TEXT NOT NULL, private_note TEXT NOT NULL
        );
        CREATE TABLE secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL);
    """)
    db.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)", [
        (101, "alpha", "Ada", 12500, "paid", "PRIVATE_ALPHA_101"),
        (102, "alpha", "O'Brien", 7500, "pending", "PRIVATE_ALPHA_102"),
        (201, "beta", "BETA_CORP", 90000, "paid", "PRIVATE_BETA_201"),
        (202, "beta", "BETA_STUDIO", 30000, "pending", "PRIVATE_BETA_202"),
    ])
    db.execute("INSERT INTO secrets VALUES (?, ?)",
               ("demo_api_key", "SECRET_SYNTHETIC_DO_NOT_USE"))
    db.commit()
    db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 8192)
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 100_000)
    db.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 32)
    return db


def snapshot(db: sqlite3.Connection) -> dict:
    """Trusted observer, called before installing / after removing the guard."""
    return {
        "orders": [tuple(row) for row in db.execute("SELECT * FROM orders ORDER BY id")],
        "secrets": [tuple(row) for row in db.execute("SELECT * FROM secrets ORDER BY name")],
    }


def install_guard(db: sqlite3.Connection, protected: bool) -> None:
    """Host containment in both modes; field/read-only restrictions in protected mode.

    This is not a tenant boundary: the trusted query compiler enforces tenants.
    """
    if protected:
        db.execute("PRAGMA query_only = ON")

    def authorize(action, table, column, database, source):
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            # SQLite may report database=None for an implicit empty-column read
            # used by COUNT(*) or an index-only scan. ATTACH remains forbidden.
            local_read = database == "main" or (database is None and column == "")
            allowed = (local_read and table == "orders"
                       and column in (*PUBLIC_COLUMNS, "")) if protected else (
                           local_read and table in {"orders", "secrets"})
            return sqlite3.SQLITE_OK if allowed else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION:
            return (sqlite3.SQLITE_OK if column in {"count", "sum", "coalesce"}
                    else sqlite3.SQLITE_DENY)
        if not protected and action in {
            sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE
        } and database == "main" and table in {"orders", "secrets"}:
            return sqlite3.SQLITE_OK
        if not protected and action == sqlite3.SQLITE_TRANSACTION:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    db.set_authorizer(authorize)
    budget = 1000

    def progress():
        nonlocal budget
        budget -= 1
        return int(budget <= 0)

    db.set_progress_handler(progress, 100)


def remove_guard(db: sqlite3.Connection) -> None:
    db.set_authorizer(None)
    db.set_progress_handler(None, 0)
