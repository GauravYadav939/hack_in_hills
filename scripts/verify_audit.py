"""
Standalone audit log verification utility.

This script can be run independently to verify the integrity of the audit log
without starting the full broker application.

Usage:
    python scripts/verify_audit.py [--db-path PATH] [--key KEY]
"""

import sys
import argparse
import base64
from pathlib import Path

# Add parent directory to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.audit.logger import AuditLogger
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description="Verify Glasshouse audit log integrity")
    parser.add_argument(
        "--db-path",
        default="./data/audit.db",
        help="Path to audit database (default: ./data/audit.db)"
    )
    parser.add_argument(
        "--key",
        help="Base64-encoded audit signing key (or set AUDIT_SIGNING_KEY env var)"
    )

    args = parser.parse_args()

    # Get signing key
    signing_key = args.key
    if not signing_key:
        # Try environment variable
        import os
        from dotenv import load_dotenv
        load_dotenv()
        signing_key = os.getenv("AUDIT_SIGNING_KEY")

    if not signing_key:
        print("ERROR: Audit signing key not provided", file=sys.stderr)
        print("Provide via --key argument or AUDIT_SIGNING_KEY environment variable", file=sys.stderr)
        sys.exit(1)

    # Check if database exists
    db_path = Path(args.db_path)
    if not db_path.exists():
        print(f"ERROR: Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 70)
    print("Glasshouse Audit Log Verification")
    print("=" * 70)
    print(f"Database: {db_path}")
    print(f"Started: {datetime.utcnow().isoformat()}")
    print()

    try:
        # Create logger (for verification only)
        logger = AuditLogger(str(db_path), signing_key)

        # Run verification
        print("Verifying audit log integrity...")
        print("Checking: hash chain, signatures, sequence gaps")
        print()

        result = logger.verify_integrity()

        print("=" * 70)
        print("VERIFICATION RESULTS")
        print("=" * 70)

        if result["valid"]:
            print("✓ AUDIT LOG IS VALID")
            print(f"  Total entries verified: {result['total_entries']}")
            print()
            print("All checks passed:")
            print("  ✓ Hash chain intact")
            print("  ✓ All signatures valid")
            print("  ✓ No sequence gaps")
            print()
            sys.exit(0)
        else:
            print("✗ AUDIT LOG VERIFICATION FAILED")
            print(f"  Total entries: {result['total_entries']}")
            print(f"  First invalid entry: #{result['first_invalid_entry']}")
            print(f"  Error: {result['error_message']}")
            print()
            print("⚠ WARNING: The audit log has been tampered with or corrupted!")
            print()
            sys.exit(1)

    except Exception as e:
        print(f"✗ VERIFICATION ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
