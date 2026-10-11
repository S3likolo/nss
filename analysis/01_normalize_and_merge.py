#!/usr/bin/env python3
"""
Web PKI Historical Root Store Normalization and Consolidation
=============================================================
This script consolidates raw Root Store historical datasets from Mozilla,
Google, Apple, and Microsoft into an analytical DuckDB database.

Key Transformations:
  1. Cleanse & normalize SHA-256 fingerprints to 64-character lowercase hex.
  2. Cast snapshot timestamps to standard ISO DATE format.
  3. Construct 'ca_metadata' dimension table mapping cert fingerprints to Subject DNs.
  4. Build consolidated 'unified_trust_history' master table enriched with metadata.
  5. Run automated data quality and plausibility checks.

Usage:
  python analysis/01_normalize_and_merge.py
  python analysis/01_normalize_and_merge.py --db-path data/normalized/root_stores.duckdb
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict

import duckdb

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("analysis.normalize_and_merge")

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
DEFAULT_RAW_DIR = Path("data/raw")
DEFAULT_NORMALIZED_DIR = Path("data/normalized")
DEFAULT_DB_PATH = DEFAULT_NORMALIZED_DIR / "root_stores.duckdb"

RAW_FILES: Dict[str, str] = {
    "mozilla": "mozilla_history.parquet",
    "google": "google_history.parquet",
    "apple": "apple_history.parquet",
    "microsoft": "microsoft_history.parquet",
}


# ---------------------------------------------------------------------------
# Normalization Pipeline
# ---------------------------------------------------------------------------
class RootStoreNormalizer:
    """
    Manages loading, standardizing, joining, and verifying root store datasets in DuckDB.
    """

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        raw_dir: Path = DEFAULT_RAW_DIR,
        normalized_dir: Path = DEFAULT_NORMALIZED_DIR,
    ) -> None:
        self.db_path = Path(db_path)
        self.raw_dir = Path(raw_dir)
        self.normalized_dir = Path(normalized_dir)
        self.normalized_dir.mkdir(parents=True, exist_ok=True)
        self.conn: duckdb.DuckDBPyConnection | None = None

    def connect(self) -> duckdb.DuckDBPyConnection:
        """Initializes or connects to the target DuckDB database file."""
        logger.info("Connecting to DuckDB database: %s", self.db_path.resolve())
        self.conn = duckdb.connect(str(self.db_path))
        return self.conn

    def verify_raw_files(self) -> Dict[str, Path]:
        """Ensures all vendor Parquet raw inputs exist before proceeding."""
        resolved: Dict[str, Path] = {}
        missing = []
        for vendor, fname in RAW_FILES.items():
            path = self.raw_dir / fname
            if not path.exists():
                missing.append(f"{vendor} ({path})")
            else:
                resolved[vendor] = path

        if missing:
            msg = f"Missing required raw input Parquet files: {', '.join(missing)}"
            logger.error(msg)
            raise FileNotFoundError(msg)

        logger.info("All 4 vendor raw files located successfully.")
        return resolved

    def normalize_and_load(self, vendor_paths: Dict[str, Path]) -> None:
        """
        Loads raw vendor datasets into temporary staging tables with
        strict fingerprint and date standardization.
        """
        assert self.conn is not None

        # Build union query with string and date cleansing
        union_clauses = []
        for vendor, p in vendor_paths.items():
            # Use forward slashes for cross-platform DuckDB SQL compatibility
            p_posix = p.as_posix()
            clause = f"""
            SELECT 
                LOWER(TRIM(vendor)) AS vendor,
                CAST(snapshot_date AS DATE) AS snapshot_date,
                LOWER(REGEXP_REPLACE(sha256_fingerprint, '[^0-9a-fA-F]', '', 'g')) AS sha256_fingerprint,
                NULLIF(TRIM(subject_dn), '') AS raw_subject_dn,
                valid_from,
                valid_until,
                NULLIF(TRIM(trust_bits), '') AS trust_bits,
                LOWER(TRIM(data_source_type)) AS data_source_type,
                TRIM(provenance_url_or_hash) AS provenance_url_or_hash
            FROM '{p_posix}'
            """
            union_clauses.append(clause)

        full_staging_sql = f"""
        CREATE OR REPLACE TABLE _staging_raw_snapshots AS
        {' UNION ALL '.join(union_clauses)};
        """

        logger.info("Ingesting raw Parquet files into temporary staging table...")
        self.conn.execute(full_staging_sql)

        count = self.conn.execute("SELECT COUNT(*) FROM _staging_raw_snapshots").fetchone()[0]
        logger.info("Staged %d total snapshot rows across all vendors.", count)

    def create_ca_metadata_table(self) -> None:
        """
        Builds the 'ca_metadata' dimension table mapping unique SHA-256 certificate hashes
        to the most informative Subject DN and certificate validity boundaries.
        Prioritizes RFC 4514 DNs from Mozilla and Apple over MS Friendly Names.
        """
        assert self.conn is not None
        logger.info("Generating 'ca_metadata' dimension table...")

        sql = """
        CREATE OR REPLACE TABLE ca_metadata AS
        WITH candidate_metadata AS (
            SELECT
                sha256_fingerprint,
                raw_subject_dn,
                valid_from,
                valid_until,
                vendor,
                ROW_NUMBER() OVER (
                    PARTITION BY sha256_fingerprint
                    ORDER BY 
                        -- Priority 1: Mozilla (RFC 4514 DN)
                        -- Priority 2: Apple (Official Trust Store CA Name)
                        -- Priority 3: Microsoft (Friendly Name)
                        -- Priority 4: Any other vendor with non-null DN
                        CASE 
                            WHEN vendor = 'mozilla' AND raw_subject_dn IS NOT NULL THEN 1
                            WHEN vendor = 'apple' AND raw_subject_dn IS NOT NULL THEN 2
                            WHEN vendor = 'microsoft' AND raw_subject_dn IS NOT NULL THEN 3
                            WHEN raw_subject_dn IS NOT NULL THEN 4
                            ELSE 5
                        END,
                        -- Prefer entries with valid_from/valid_until timestamps populated
                        CASE WHEN valid_from IS NOT NULL THEN 0 ELSE 1 END,
                        snapshot_date DESC
                ) AS rn
            FROM _staging_raw_snapshots
        ),
        distinct_certs AS (
            SELECT DISTINCT sha256_fingerprint FROM _staging_raw_snapshots
        )
        SELECT
            d.sha256_fingerprint,
            m.raw_subject_dn AS subject_dn,
            m.valid_from,
            m.valid_until,
            m.vendor AS metadata_source_vendor
        FROM distinct_certs d
        LEFT JOIN (SELECT * FROM candidate_metadata WHERE rn = 1) m
            ON d.sha256_fingerprint = m.sha256_fingerprint;
        """

        self.conn.execute(sql)
        meta_count = self.conn.execute("SELECT COUNT(*) FROM ca_metadata").fetchone()[0]
        dn_count = self.conn.execute("SELECT COUNT(subject_dn) FROM ca_metadata").fetchone()[0]
        logger.info(
            "Created 'ca_metadata' with %d unique certificates (%d have Subject DN = %.1f%%).",
            meta_count,
            dn_count,
            (dn_count * 100.0 / meta_count) if meta_count else 0,
        )

    def create_unified_trust_history(self) -> None:
        """
        Creates the consolidated master table 'unified_trust_history'.
        Fills missing subject_dn and validity timestamps from 'ca_metadata'.
        """
        assert self.conn is not None
        logger.info("Constructing master table 'unified_trust_history'...")

        sql = """
        CREATE OR REPLACE TABLE unified_trust_history AS
        SELECT DISTINCT
            s.vendor,
            s.snapshot_date,
            s.sha256_fingerprint,
            COALESCE(s.raw_subject_dn, m.subject_dn) AS subject_dn,
            COALESCE(s.valid_from, m.valid_from) AS valid_from,
            COALESCE(s.valid_until, m.valid_until) AS valid_until,
            s.trust_bits,
            s.data_source_type,
            s.provenance_url_or_hash
        FROM _staging_raw_snapshots s
        LEFT JOIN ca_metadata m
            ON s.sha256_fingerprint = m.sha256_fingerprint;
        """

        self.conn.execute(sql)

        # Drop temporary staging table
        self.conn.execute("DROP TABLE IF EXISTS _staging_raw_snapshots;")

        # Create analytical indices
        logger.info("Creating primary lookup indices...")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_uth_vendor_date ON unified_trust_history(vendor, snapshot_date);"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_uth_cert_hash ON unified_trust_history(sha256_fingerprint);"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_meta_cert_hash ON ca_metadata(sha256_fingerprint);"
        )

        rows = self.conn.execute("SELECT COUNT(*) FROM unified_trust_history").fetchone()[0]
        logger.info("Master table 'unified_trust_history' created with %d rows.", rows)

    def export_normalized_parquet(self) -> None:
        """Exports unified tables to Parquet files for portable downstream access."""
        assert self.conn is not None
        uth_parquet = self.normalized_dir / "unified_trust_history.parquet"
        meta_parquet = self.normalized_dir / "ca_metadata.parquet"

        logger.info("Exporting DuckDB tables to persistent Parquet files...")
        self.conn.execute(
            f"COPY unified_trust_history TO '{uth_parquet.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD);"
        )
        self.conn.execute(
            f"COPY ca_metadata TO '{meta_parquet.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD);"
        )
        logger.info("Parquet exports completed: %s and %s", uth_parquet.name, meta_parquet.name)

    def run_data_quality_checks(self) -> None:
        """
        Executes automated Data Quality and Plausibility checks and prints formatted tables.
        """
        assert self.conn is not None

        print("\n" + "=" * 90)
        print("DATA QUALITY CHECKS & PLAUSIBILITY VERIFICATION")
        print("=" * 90)

        # Query 1: Number of snapshots and total entries per vendor
        q1 = """
        SELECT 
            vendor,
            COUNT(DISTINCT snapshot_date) AS snapshot_count,
            COUNT(*) AS total_snapshot_entries,
            COUNT(DISTINCT sha256_fingerprint) AS distinct_root_certs
        FROM unified_trust_history
        GROUP BY vendor
        ORDER BY vendor;
        """
        print("\n[CHECK 1] Snapshot and Record Counts per Vendor:")
        print("-" * 90)
        df1 = self.conn.execute(q1).df()
        print(df1.to_string(index=False))

        # Query 2: Total unique certificate hashes across entire dataset
        q2 = """
        SELECT 
            COUNT(DISTINCT sha256_fingerprint) AS global_unique_roots,
            (SELECT COUNT(*) FROM ca_metadata WHERE subject_dn IS NOT NULL) AS roots_with_subject_dn,
            (SELECT COUNT(*) FROM ca_metadata WHERE valid_from IS NOT NULL) AS roots_with_validity_dates,
            ROUND((SELECT COUNT(*) FROM ca_metadata WHERE subject_dn IS NOT NULL) * 100.0 / COUNT(DISTINCT sha256_fingerprint), 2) AS pct_metadata_coverage
        FROM unified_trust_history;
        """
        print("\n[CHECK 2] Global Certificate Corpus Metrics:")
        print("-" * 90)
        df2 = self.conn.execute(q2).df()
        print(df2.to_string(index=False))

        # Query 3: Earliest and latest snapshot timestamp per vendor (Data Availability Range)
        q3 = """
        SELECT 
            vendor,
            MIN(snapshot_date) AS earliest_snapshot,
            MAX(snapshot_date) AS latest_snapshot,
            DATEDIFF('day', MIN(snapshot_date), MAX(snapshot_date)) AS observation_span_days,
            ANY_VALUE(data_source_type) AS primary_source_type
        FROM unified_trust_history
        GROUP BY vendor
        ORDER BY vendor;
        """
        print("\n[CHECK 3] Temporal Availability Range per Vendor:")
        print("-" * 90)
        df3 = self.conn.execute(q3).df()
        print(df3.to_string(index=False))

        # Query 4: Metadata Enrichment Effect (Subject DN availability before vs after)
        q4 = """
        SELECT 
            vendor,
            COUNT(*) AS total_records,
            COUNT(subject_dn) AS records_with_subject_dn,
            ROUND(COUNT(subject_dn) * 100.0 / COUNT(*), 2) AS subject_dn_coverage_pct
        FROM unified_trust_history
        GROUP BY vendor
        ORDER BY vendor;
        """
        print("\n[CHECK 4] Subject DN Completeness in Master Table:")
        print("-" * 90)
        df4 = self.conn.execute(q4).df()
        print(df4.to_string(index=False))

        # Query 5: Sanity check on SHA-256 fingerprint syntax
        q5 = """
        SELECT 
            COUNT(*) AS invalid_fingerprint_count
        FROM unified_trust_history
        WHERE LENGTH(sha256_fingerprint) != 64
           OR sha256_fingerprint ~ '[^0-9a-f]';
        """
        invalid_count = self.conn.execute(q5).fetchone()[0]
        print("\n[CHECK 5] Cryptographic Hash Format Integrity:")
        print("-" * 90)
        print(f"Invalid SHA-256 hashes detected (must be 0): {invalid_count}")
        assert invalid_count == 0, f"Error: Found {invalid_count} malformed sha256_fingerprint values!"

        print("\n" + "=" * 90)
        print("ALL DATA QUALITY CHECKS PASSED SUCCESSFULLY")
        print("=" * 90 + "\n")

    def close(self) -> None:
        """Closes the active database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.info("DuckDB connection closed.")


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def parse_arguments() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Normalize and merge historical Root Store Parquet datasets into DuckDB."
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Target DuckDB database path (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=DEFAULT_RAW_DIR,
        help=f"Directory containing raw vendor parquet files (default: {DEFAULT_RAW_DIR}).",
    )
    parser.add_argument(
        "--normalized-dir",
        type=Path,
        default=DEFAULT_NORMALIZED_DIR,
        help=f"Directory for normalized outputs (default: {DEFAULT_NORMALIZED_DIR}).",
    )
    parser.add_argument(
        "--no-parquet-export",
        action="store_true",
        help="Skip exporting unified_trust_history and ca_metadata to Parquet files.",
    )
    return parser.parse_args()


def main() -> None:
    """Main execution function."""
    args = parse_arguments()

    normalizer = RootStoreNormalizer(
        db_path=args.db_path,
        raw_dir=args.raw_dir,
        normalized_dir=args.normalized_dir,
    )

    try:
        # Step 1: Connect to DuckDB
        normalizer.connect()

        # Step 2: Verify and standardize raw inputs
        vendor_paths = normalizer.verify_raw_files()
        normalizer.normalize_and_load(vendor_paths)

        # Step 3: Build ca_metadata and master unified_trust_history
        normalizer.create_ca_metadata_table()
        normalizer.create_unified_trust_history()

        # Optional Parquet exports
        if not args.no_parquet_export:
            normalizer.export_normalized_parquet()

        # Step 4: Run automated quality and plausibility checks
        normalizer.run_data_quality_checks()

    except Exception as exc:
        logger.exception("Normalization and merge pipeline failed: %s", exc)
        sys.exit(1)
    finally:
        normalizer.close()


if __name__ == "__main__":
    main()
