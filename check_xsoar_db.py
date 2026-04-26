import sys, sqlite3
sys.path.insert(0, ".")
from services.xsoar_timeline_db import get_connection

with get_connection() as conn:
    cols = [c[1] for c in conn.execute("PRAGMA table_info(xsoar_tickets)").fetchall()]
    print("Columns in xsoar_tickets:")
    for c in cols:
        print(f"  {c}")

    print(f"\nTotal rows: {conn.execute('SELECT COUNT(*) FROM xsoar_tickets').fetchone()[0]}")

    # Check if there's a raw_json column
    has_raw = "raw_json" in cols
    print(f"\nHas raw_json column: {has_raw}")

    # Sample a recent ticket to see what's populated
    row = conn.execute("SELECT * FROM xsoar_tickets WHERE id = 979980").fetchone()
    if row:
        d = dict(row)
        print(f"\nSample ticket 979980:")
        for k, v in d.items():
            val_str = str(v)[:100] if v else "(empty)"
            print(f"  {k}: {val_str}")

    # Check all tables in the DB
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    print(f"\nAll tables: {[t[0] for t in tables]}")
