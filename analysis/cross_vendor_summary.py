"""
Cross-Vendor Web PKI Root Store Analysis
========================================
Analyzes historical trust store data from Mozilla, Google, Apple, and Microsoft
stored in data/raw/*.parquet using DuckDB.
"""

from pathlib import Path
import duckdb
import pandas as pd

DATA_DIR = Path("data/raw")


def run_analysis() -> None:
    conn = duckdb.connect()

    files = {
        "mozilla": DATA_DIR / "mozilla_history.parquet",
        "google": DATA_DIR / "google_history.parquet",
        "apple": DATA_DIR / "apple_history.parquet",
        "microsoft": DATA_DIR / "microsoft_history.parquet",
    }

    print("=" * 80)
    print("WEB PKI ROOT STORE HISTORICAL DATASET SUMMARY")
    print("=" * 80)

    # 1. Vendor Overview
    union_query = f"""
    WITH all_data AS (
        SELECT vendor, snapshot_date, sha256_fingerprint, subject_dn, trust_bits, data_source_type 
        FROM '{files["mozilla"].as_posix()}'
        UNION ALL
        SELECT vendor, snapshot_date, sha256_fingerprint, subject_dn, trust_bits, data_source_type 
        FROM '{files["google"].as_posix()}'
        UNION ALL
        SELECT vendor, snapshot_date, sha256_fingerprint, subject_dn, trust_bits, data_source_type 
        FROM '{files["apple"].as_posix()}'
        UNION ALL
        SELECT vendor, snapshot_date, sha256_fingerprint, subject_dn, trust_bits, data_source_type 
        FROM '{files["microsoft"].as_posix()}'
    )
    SELECT
        vendor,
        ANY_VALUE(data_source_type) as source_type,
        COUNT(*) as total_rows,
        COUNT(DISTINCT sha256_fingerprint) as unique_certs,
        COUNT(DISTINCT snapshot_date) as snapshots_count,
        MIN(snapshot_date) as earliest_snapshot,
        MAX(snapshot_date) as latest_snapshot
    FROM all_data
    GROUP BY vendor
    ORDER BY vendor;
    """
    df_vendors = conn.execute(union_query).df()
    print("\n1. Per-Vendor Overview:")
    print(df_vendors.to_string(index=False))

    # 2. Cross-Vendor Overlap
    overlap_query = f"""
    WITH distinct_vendor_certs AS (
        SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["mozilla"].as_posix()}'
        UNION ALL
        SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["google"].as_posix()}'
        UNION ALL
        SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["apple"].as_posix()}'
        UNION ALL
        SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["microsoft"].as_posix()}'
    ),
    cert_membership AS (
        SELECT 
            sha256_fingerprint,
            COUNT(DISTINCT vendor) as vendor_count,
            STRING_AGG(DISTINCT vendor, ', ' ORDER BY vendor) as vendor_list
        FROM distinct_vendor_certs
        GROUP BY sha256_fingerprint
    )
    SELECT
        vendor_count,
        COUNT(*) as certificate_count,
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM cert_membership), 2) as pct_of_total
    FROM cert_membership
    GROUP BY vendor_count
    ORDER BY vendor_count DESC;
    """
    df_overlap = conn.execute(overlap_query).df()
    print("\n2. Certificate Vendor Distribution (Ubiquity vs Fragmentation):")
    print(df_overlap.to_string(index=False))

    # 3. Ubiquitous Root CAs (Trusted by ALL 4 vendors)
    ubiquitous_query = f"""
    WITH all_subjects AS (
        SELECT sha256_fingerprint, FIRST(subject_dn) as subject_dn
        FROM (
            SELECT sha256_fingerprint, subject_dn FROM '{files["mozilla"].as_posix()}' WHERE subject_dn IS NOT NULL
            UNION ALL
            SELECT sha256_fingerprint, subject_dn FROM '{files["apple"].as_posix()}' WHERE subject_dn IS NOT NULL
            UNION ALL
            SELECT sha256_fingerprint, subject_dn FROM '{files["microsoft"].as_posix()}' WHERE subject_dn IS NOT NULL
        )
        GROUP BY sha256_fingerprint
    ),
    four_way_roots AS (
        SELECT sha256_fingerprint
        FROM (
            SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["mozilla"].as_posix()}'
            UNION ALL
            SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["google"].as_posix()}'
            UNION ALL
            SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["apple"].as_posix()}'
            UNION ALL
            SELECT DISTINCT vendor, sha256_fingerprint FROM '{files["microsoft"].as_posix()}'
        )
        GROUP BY sha256_fingerprint
        HAVING COUNT(DISTINCT vendor) = 4
    )
    SELECT 
        r.sha256_fingerprint,
        COALESCE(s.subject_dn, 'Unknown') as subject_dn
    FROM four_way_roots r
    LEFT JOIN all_subjects s ON r.sha256_fingerprint = s.sha256_fingerprint
    ORDER BY subject_dn
    LIMIT 10;
    """
    df_ubiquitous = conn.execute(ubiquitous_query).df()
    print("\n3. Sample Ubiquitous Root Certificates (Trusted across Mozilla, Google, Apple, Microsoft):")
    print(df_ubiquitous.to_string(index=False))

    print("\n" + "=" * 80)
    print("Analysis complete.")
    print("=" * 80)


if __name__ == "__main__":
    run_analysis()
