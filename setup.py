"""
Initial setup script for IPDR system
"""
import sys
from sqlalchemy import text
from app.database import Base, engine
from dotenv import load_dotenv

load_dotenv()


def init_database():
    """Create database tables"""
    print("[INFO] Creating database tables...")
    try:
        Base.metadata.create_all(bind=engine)
        print("[SUCCESS] Database tables created successfully")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to create tables: {str(e)}")
        return False


def upgrade_schema():
    """Add IPv6 / protocol columns on existing PostgreSQL installations."""
    print("[INFO] Checking schema upgrades (IPv6 / protocols)...")
    statements = [
        "ALTER TABLE ipdr_records ALTER COLUMN source_ip TYPE VARCHAR(64)",
        "ALTER TABLE ipdr_records ALTER COLUMN destination_ip TYPE VARCHAR(64)",
        "ALTER TABLE ipdr_records ALTER COLUMN protocol TYPE VARCHAR(32)",
        "ALTER TABLE ipdr_records ADD COLUMN IF NOT EXISTS ip_version INTEGER DEFAULT 4",
        "ALTER TABLE ipdr_records ADD COLUMN IF NOT EXISTS protocol_number INTEGER",
        "ALTER TABLE traffic_summaries ALTER COLUMN source_ip TYPE VARCHAR(64)",
        "ALTER TABLE traffic_summaries ALTER COLUMN destination_ip TYPE VARCHAR(64)",
        "ALTER TABLE traffic_summaries ALTER COLUMN protocol TYPE VARCHAR(32)",
        "ALTER TABLE traffic_summaries ADD COLUMN IF NOT EXISTS ip_version INTEGER",
        "ALTER TABLE security_events ALTER COLUMN source_ip TYPE VARCHAR(64)",
        "ALTER TABLE security_events ALTER COLUMN destination_ip TYPE VARCHAR(64)",
        "CREATE INDEX IF NOT EXISTS ix_ipdr_records_ip_version ON ipdr_records (ip_version)",
        "CREATE INDEX IF NOT EXISTS ix_ipdr_records_protocol_number ON ipdr_records (protocol_number)",
    ]
    try:
        with engine.begin() as conn:
            for stmt in statements:
                try:
                    conn.execute(text(stmt))
                except Exception as e:
                    # Ignore benign errors on fresh installs / non-PG dialects
                    logger_msg = str(e).lower()
                    if "already exists" in logger_msg or "does not exist" in logger_msg:
                        continue
                    print(f"[WARN] {stmt}: {e}")
        print("[SUCCESS] Schema upgrade checks completed")
        return True
    except Exception as e:
        print(f"[WARN] Schema upgrade skipped/failed: {e}")
        return True


def check_database_connection():
    """Check database connection"""
    print("[INFO] Checking database connection...")
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()
        print("[SUCCESS] Database connection established")
        return True
    except Exception as e:
        print(f"[ERROR] Database connection failed: {str(e)}")
        print("\n[TIPS]")
        print("   - Ensure PostgreSQL is running (systemctl status postgresql)")
        print("   - Check .env and set DATABASE_URL")
        print("   - Create the database and user if they do not exist")
        print("   - See INSTALL-FA.md (Persian) or README.md for Linux setup")
        return False


def main():
    """Main function"""
    print("=" * 50)
    print("IPDR System Setup")
    print("=" * 50)
    print()

    if not check_database_connection():
        sys.exit(1)

    if not init_database():
        sys.exit(1)

    upgrade_schema()

    print()
    print("=" * 50)
    print("[SUCCESS] Setup completed successfully!")
    print("=" * 50)
    print()
    print("Next steps:")
    print("   1. Run server: uvicorn app.main:app --reload")
    print("   2. Open browser: http://localhost:8000")
    print("   3. View dashboard: http://localhost:8000/dashboard")
    print("   4. API docs: http://localhost:8000/docs")
    print("   5. Protocol list: http://localhost:8000/api/ipdr/protocols")
    print()


if __name__ == "__main__":
    main()
