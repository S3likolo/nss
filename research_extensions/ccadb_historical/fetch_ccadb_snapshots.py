#!/usr/bin/env python3
"""
CCADB Historical Snapshots Extractor
===================================

This module extracts and normalizes historical snapshots of the Common CA
Database (CCADB) public CSV reports from 2018 to 2026 via the Internet Archive
Wayback Machine and live CCADB endpoints.

It addresses the fundamental historical data gap for Apple (which previously had
only a single scraped snapshot in `unified_trust_history.parquet`) and provides
cross-vendor synchronized trust store state across Apple, Google Chrome,
Microsoft, and Mozilla.

Target Sources:
  - All Included Root Certificate Trust Bit Settings (`AllIncludedRootCertsCSV`)
  - All Certificate Records v4 (`AllCertificateRecordsCSVFormatv4`)
  - Mozilla Included CA Certificate Reports (`IncludedCACertificateReportPEMCSV` / `CSVFormat`)
  - Microsoft Included CA Certificate Reports (`IncludedCACertificateReportForMSFTCSV`)
  - Use-case specific TLS reports (Apple, Google Chrome, Microsoft, Mozilla)

Output:
  - `ccadb_trust_history.parquet` (conforming strictly to `SCHEMA.md`)
  - `ccadb_trust_history.csv`

Author: Academic Research Team
Date: October 2026
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import requests

# Ensure UTF-8 stdout
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("extractors.ccadb_historical")

# ---------------------------------------------------------------------------
# Paths and Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_CACHE_DIR = SCRIPT_DIR / ".cache"
DEFAULT_OUTPUT_PARQUET = SCRIPT_DIR / "ccadb_trust_history.parquet"
DEFAULT_OUTPUT_CSV = SCRIPT_DIR / "ccadb_trust_history.csv"
UNIFIED_TRUST_HISTORY_PARQUET = REPO_ROOT / "data" / "normalized" / "unified_trust_history.parquet"

WAYBACK_CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_REPLAY_TEMPLATE = "https://web.archive.org/web/{timestamp}id_/{original}"
WAYBACK_VIEW_TEMPLATE = "https://web.archive.org/web/{timestamp}/{original}"

DATA_SOURCE_TYPE = "ccadb_csv"

# ---------------------------------------------------------------------------
# Pre-Indexed Snapshot Definitions (2018 - 2026)
# ---------------------------------------------------------------------------
# These snapshots provide semi-annual to annual coverage from 2018 through 2026.
PRE_INDEXED_SNAPSHOTS = [
    # 2018-01: Mozilla Included PEM CSV
    {
        "snapshot_id": "20180116_mozilla_pem",
        "timestamp": "20180116232630",
        "snapshot_date": "2018-01-16",
        "report_type": "mozilla_pem",
        "url": "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV",
        "vendor": "mozilla",
    },
    # 2019-07: Mozilla Included PEM CSV
    {
        "snapshot_id": "20190719_mozilla_pem",
        "timestamp": "20190719012316",
        "snapshot_date": "2019-07-19",
        "report_type": "mozilla_pem",
        "url": "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV",
        "vendor": "mozilla",
    },
    # 2020-08: Mozilla Included PEM CSV
    {
        "snapshot_id": "20200815_mozilla_pem",
        "timestamp": "20200815221909",
        "snapshot_date": "2020-08-15",
        "report_type": "mozilla_pem",
        "url": "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV",
        "vendor": "mozilla",
    },
    # 2020-11: Mozilla Included CSV Format
    {
        "snapshot_id": "20201112_mozilla_csv",
        "timestamp": "20201112013511",
        "snapshot_date": "2020-11-12",
        "report_type": "mozilla_csv",
        "url": "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportCSVFormat",
        "vendor": "mozilla",
    },
    # 2021-05: Mozilla Included PEM CSV
    {
        "snapshot_id": "20210518_mozilla_pem",
        "timestamp": "20210518160908",
        "snapshot_date": "2021-05-18",
        "report_type": "mozilla_pem",
        "url": "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV",
        "vendor": "mozilla",
    },
    # 2022-08: Mozilla Included PEM CSV
    {
        "snapshot_id": "20220824_mozilla_pem",
        "timestamp": "20220824202537",
        "snapshot_date": "2022-08-24",
        "report_type": "mozilla_pem",
        "url": "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV",
        "vendor": "mozilla",
    },
    # 2022-11: Microsoft Included CSV
    {
        "snapshot_id": "20221127_msft_csv",
        "timestamp": "20221127083234",
        "snapshot_date": "2022-11-27",
        "report_type": "msft_csv",
        "url": "https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV",
        "vendor": "microsoft",
    },
    # 2022-12: CCADB All Certificate Records (Cross-vendor: Mozilla & Microsoft)
    {
        "snapshot_id": "20221217_ccadb_all_records",
        "timestamp": "20221217223018",
        "snapshot_date": "2022-12-17",
        "report_type": "ccadb_all_records_v3",
        "url": "https://ccadb-public.secure.force.com/ccadb/AllCertificateRecordsCSVFormat",
        "vendor": "cross_vendor",
    },
    # 2023-12: CCADB All Included Root Certs (Cross-vendor: Apple, Google, Microsoft, Mozilla)
    {
        "snapshot_id": "20231203_all_included",
        "timestamp": "20231203142648",
        "snapshot_date": "2023-12-03",
        "report_type": "all_included",
        "url": "https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV",
        "vendor": "cross_vendor",
    },
    # 2024-08: CCADB All Included Root Certs (Cross-vendor: Apple, Google, Microsoft, Mozilla)
    {
        "snapshot_id": "20240805_all_included",
        "timestamp": "20240805115225",
        "snapshot_date": "2024-08-05",
        "report_type": "all_included",
        "url": "https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV",
        "vendor": "cross_vendor",
    },
    # 2025-06: CCADB All Included Root Certs (Cross-vendor: Apple, Google, Microsoft, Mozilla)
    {
        "snapshot_id": "20250627_all_included",
        "timestamp": "20250627075307",
        "snapshot_date": "2025-06-27",
        "report_type": "all_included",
        "url": "https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV",
        "vendor": "cross_vendor",
    },
    # 2025-12: CCADB All Certificate Records v4 (Cross-vendor: Apple, Chrome, Microsoft, Mozilla)
    {
        "snapshot_id": "20251227_all_records_v4",
        "timestamp": "20251227212244",
        "snapshot_date": "2025-12-27",
        "report_type": "all_records_v4",
        "url": "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4",
        "vendor": "cross_vendor",
    },
    # 2026-10: Live CCADB All Included Root Certs (Current Ground Truth)
    {
        "snapshot_id": "20261016_live_all_included",
        "timestamp": "20261016000000",
        "snapshot_date": "2026-10-16",
        "report_type": "all_included",
        "url": "https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV",
        "vendor": "cross_vendor",
        "is_live": True,
    },
]

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TrustRecord:
    """Standardized root certificate observation conforming to SCHEMA.md."""

    vendor: str
    snapshot_date: date
    sha256_fingerprint: str
    subject_dn: str
    valid_from: datetime
    valid_until: datetime
    trust_bits: Optional[str]
    data_source_type: str
    provenance_url_or_hash: str


# ---------------------------------------------------------------------------
# Metadata Pre-Indexer & Certificate Knowledge Base
# ---------------------------------------------------------------------------
class CertificateMetadataRegistry:
    """
    Maintains an authoritative reference dictionary of certificate metadata
    (subject_dn, valid_from, valid_until) indexed by sha256_fingerprint.
    """

    def __init__(self, fallback_parquet_path: Optional[Path] = UNIFIED_TRUST_HISTORY_PARQUET):
        self._meta_by_sha256: Dict[str, Dict[str, Any]] = {}
        if fallback_parquet_path and fallback_parquet_path.exists():
            self._load_from_unified_parquet(fallback_parquet_path)

    def _load_from_unified_parquet(self, path: Path) -> None:
        try:
            df = pd.read_parquet(
                path,
                columns=["sha256_fingerprint", "subject_dn", "valid_from", "valid_until"],
            )
            df = df.dropna(subset=["sha256_fingerprint"]).drop_duplicates(subset=["sha256_fingerprint"])
            for _, row in df.iterrows():
                fp = str(row["sha256_fingerprint"]).lower().strip()
                self._meta_by_sha256[fp] = {
                    "subject_dn": row["subject_dn"],
                    "valid_from": row["valid_from"],
                    "valid_until": row["valid_until"],
                }
            logger.info("Loaded reference metadata for %d certificates from unified_trust_history.", len(self._meta_by_sha256))
        except Exception as e:
            logger.warning("Could not pre-load metadata from %s: %s", path, e)

    def register(self, sha256: str, subject_dn: Optional[Any], valid_from: Optional[Any], valid_until: Optional[Any]) -> None:
        """Registers newly discovered certificate metadata."""
        sha256 = sha256.lower().strip()
        if not sha256 or len(sha256) != 64:
            return

        current = self._meta_by_sha256.get(sha256, {})
        new_dn = str(subject_dn).strip() if (isinstance(subject_dn, str) and subject_dn.strip() and subject_dn.strip().lower() != "nan") else current.get("subject_dn")
        new_from = valid_from if (valid_from is not None and pd.notna(valid_from)) else current.get("valid_from")
        new_until = valid_until if (valid_until is not None and pd.notna(valid_until)) else current.get("valid_until")

        self._meta_by_sha256[sha256] = {
            "subject_dn": new_dn,
            "valid_from": new_from,
            "valid_until": new_until,
        }

    def get(self, sha256: str) -> Dict[str, Any]:
        return self._meta_by_sha256.get(sha256.lower().strip(), {})


# ---------------------------------------------------------------------------
# Normalization Helpers
# ---------------------------------------------------------------------------
def clean_sha256(val: Any) -> Optional[str]:
    """Cleans and validates a SHA-256 fingerprint into 64 lowercase hex chars."""
    if not val or pd.isna(val):
        return None
    s = str(val).lower().replace(":", "").replace(" ", "").replace("-", "").strip()
    if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
        return s
    return None


def parse_timestamp(val: Any, default_dt: datetime) -> datetime:
    """Parses arbitrary date/time representation into UTC timezone-aware datetime."""
    if not val or pd.isna(val):
        return default_dt
    if isinstance(val, (datetime, pd.Timestamp)):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, date):
        return datetime(val.year, val.month, val.day, tzinfo=timezone.utc)

    s = str(val).strip()
    try:
        ts = pd.to_datetime(s, utc=True)
        if pd.notna(ts):
            return ts.to_pydatetime()
    except Exception:
        pass

    return default_dt


def normalize_trust_bits(raw_val: Any, vendor: str) -> str:
    """Maps vendor-specific CCADB trust bit strings into standardized comma-separated tokens."""
    if not raw_val or pd.isna(raw_val):
        if vendor == "google":
            return "serverAuth"
        return ""

    s = str(raw_val).lower()
    bits: Set[str] = set()

    # Server Authentication / TLS / Websites
    if any(k in s for k in ("server authentication", "websites", "web sites", "serverauth", "tls")):
        bits.add("serverAuth")

    # Secure Email / S/MIME
    if any(k in s for k in ("secure email", "email", "s/mime", "emailprotection")):
        bits.add("emailProtection")

    # Code Signing
    if any(k in s for k in ("code signing", "code", "codesigning")):
        bits.add("codeSigning")

    # Time Stamping
    if any(k in s for k in ("time stamping", "timestamping")):
        bits.add("timeStamping")

    # Client Authentication
    if "client authentication" in s or "clientauth" in s:
        bits.add("clientAuth")

    # Encrypting File System
    if "encrypting file system" in s:
        bits.add("encryptingFileSystem")

    # Default for Google Chrome if unspecified
    if vendor == "google" and not bits:
        bits.add("serverAuth")

    return ",".join(sorted(bits))


# ---------------------------------------------------------------------------
# Downloader & Cache Manager
# ---------------------------------------------------------------------------
class CCADBWaybackManager:
    """Downloads and caches CCADB CSV reports from the Wayback Machine and live CDN."""

    def __init__(self, cache_dir: Path = DEFAULT_CACHE_DIR):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebPKI-Research-CCADB/1.0",
        })

    def fetch_snapshot_csv(self, spec: Dict[str, Any]) -> Optional[str]:
        """Retrieves raw CSV content for a snapshot from cache or Wayback/live."""
        snap_id = spec["snapshot_id"]
        cache_path = self.cache_dir / f"{snap_id}.csv"

        if cache_path.exists() and cache_path.stat().st_size > 500:
            logger.debug("Loading cached snapshot %s (%d bytes)", snap_id, cache_path.stat().st_size)
            try:
                return cache_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                logger.warning("Error reading cache file %s: %s", cache_path, e)

        # Download URL
        if spec.get("is_live"):
            download_url = spec["url"]
            provenance = download_url
            logger.info("Fetching LIVE snapshot: %s (%s)", snap_id, download_url)
        else:
            download_url = WAYBACK_REPLAY_TEMPLATE.format(
                timestamp=spec["timestamp"],
                original=spec["url"],
            )
            provenance = WAYBACK_VIEW_TEMPLATE.format(
                timestamp=spec["timestamp"],
                original=spec["url"],
            )
            logger.info("Fetching Wayback snapshot: %s (%s)", snap_id, download_url)

        # Use curl directly for fast, gzip-compatible fetching
        curl_bin = shutil.which("curl.exe") or shutil.which("curl")
        content: Optional[str] = None

        if curl_bin:
            cmd = [
                curl_bin,
                "--compressed",
                "-s",
                "--connect-timeout", "15",
                "--max-time", "60",
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebPKI-Bot/1.0",
                download_url,
            ]
            try:
                res = subprocess.run(cmd, capture_output=True, text=False, timeout=70)
                if res.returncode == 0 and len(res.stdout) > 200:
                    content = res.stdout.decode("utf-8", errors="replace")
            except Exception as e:
                logger.debug("curl download failed for %s: %s", snap_id, e)

        # Fallback to requests
        if not content:
            try:
                resp = self.session.get(download_url, timeout=30)
                if resp.status_code == 200 and len(resp.content) > 200:
                    content = resp.text
            except Exception as e:
                logger.warning("requests download failed for %s: %s", snap_id, e)

        if content and len(content) > 500:
            try:
                cache_path.write_text(content, encoding="utf-8", errors="replace")
                logger.info("Cached %s successfully (%d bytes).", snap_id, len(content))
            except Exception as e:
                logger.warning("Could not write cache file %s: %s", cache_path, e)
            return content

        logger.error("Failed to retrieve snapshot %s from %s", snap_id, download_url)
        return None


# ---------------------------------------------------------------------------
# Report Parsers
# ---------------------------------------------------------------------------
class CCADBReportParser:
    """Parses various flavors of CCADB CSV reports into uniform TrustRecords."""

    def __init__(self, registry: CertificateMetadataRegistry):
        self.registry = registry

    def parse(self, spec: Dict[str, Any], csv_text: str) -> List[TrustRecord]:
        """Dispatches CSV parsing based on report_type."""
        report_type = spec["report_type"]
        snap_date = date.fromisoformat(spec["snapshot_date"])
        provenance = (
            spec["url"]
            if spec.get("is_live")
            else WAYBACK_VIEW_TEMPLATE.format(timestamp=spec["timestamp"], original=spec["url"])
        )

        if report_type == "all_included":
            return self._parse_all_included(csv_text, snap_date, provenance)
        elif report_type == "all_records_v4":
            return self._parse_all_records_v4(csv_text, snap_date, provenance)
        elif report_type == "ccadb_all_records_v3":
            return self._parse_all_records_v3(csv_text, snap_date, provenance)
        elif report_type in ("mozilla_pem", "mozilla_csv"):
            return self._parse_mozilla_report(csv_text, snap_date, provenance)
        elif report_type == "msft_csv":
            return self._parse_msft_report(csv_text, snap_date, provenance)
        else:
            logger.warning("Unknown report_type: %s", report_type)
            return []

    def _resolve_subject_dn(self, meta: Dict[str, Any], cert_name: Any) -> str:
        raw_dn = meta.get("subject_dn")
        if isinstance(raw_dn, str) and raw_dn.strip() and raw_dn.strip().lower() != "nan":
            return raw_dn.strip()
        c = str(cert_name).strip() if (cert_name and pd.notna(cert_name)) else "Unknown Root"
        if not c or c.lower() == "nan":
            c = "Unknown Root"
        return f"CN={c}"

    def _parse_all_included(self, csv_text: str, snap_date: date, provenance: str) -> List[TrustRecord]:
        """
        Parses `AllIncludedRootCertsCSV`.
        Contains per-row status & trust bits for Apple, Google Chrome, Microsoft, and Mozilla!
        """
        records: List[TrustRecord] = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            sha256 = clean_sha256(row.get("SHA-256 Fingerprint"))
            if not sha256:
                continue

            cert_name = row.get("Certificate Name") or row.get("CA Owner") or "Unknown Root"
            meta = self.registry.get(sha256)
            subject_dn = self._resolve_subject_dn(meta, cert_name)
            default_from = datetime(2000, 1, 1, tzinfo=timezone.utc)
            default_to = datetime(2035, 1, 1, tzinfo=timezone.utc)
            valid_from = parse_timestamp(meta.get("valid_from"), default_from)
            valid_until = parse_timestamp(meta.get("valid_until"), default_to)

            # Register metadata
            self.registry.register(sha256, subject_dn, valid_from, valid_until)

            # Apple
            apple_status = str(row.get("Apple Status", "")).strip().lower()
            if apple_status == "included":
                tbits = normalize_trust_bits(row.get("Apple Trust Bits"), "apple")
                records.append(TrustRecord("apple", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

            # Google Chrome
            chrome_status = str(row.get("Google Chrome Status", row.get("Chrome Status", ""))).strip().lower()
            if chrome_status == "included":
                tbits = normalize_trust_bits(None, "google")
                records.append(TrustRecord("google", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

            # Microsoft
            msft_status = str(row.get("Microsoft Status", "")).strip().lower()
            if msft_status == "included":
                raw_ekus = row.get("Microsoft EKUs For DTBs") or row.get("Microsoft EKUs") or ""
                tbits = normalize_trust_bits(raw_ekus, "microsoft")
                records.append(TrustRecord("microsoft", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

            # Mozilla
            moz_status = str(row.get("Mozilla Status", "")).strip().lower()
            if moz_status == "included":
                raw_moz_bits = row.get("Mozilla Trust Bits") or ""
                tbits = normalize_trust_bits(raw_moz_bits, "mozilla")
                records.append(TrustRecord("mozilla", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

        return records

    def _parse_all_records_v4(self, csv_text: str, snap_date: date, provenance: str) -> List[TrustRecord]:
        """
        Parses `AllCertificateRecordsCSVFormatv4`.
        Massive multi-field database dump containing full root/subordinate certificates.
        """
        records: List[TrustRecord] = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            rec_type = str(row.get("Certificate Record Type", "")).strip().lower()
            if "root" not in rec_type:
                continue

            sha256 = clean_sha256(row.get("SHA-256 Fingerprint"))
            if not sha256:
                continue

            cert_name = row.get("Certificate Name") or row.get("CA Owner") or "Unknown Root"
            meta = self.registry.get(sha256)
            subject_dn = self._resolve_subject_dn(meta, cert_name)

            v_from_raw = row.get("Valid From (GMT)") or meta.get("valid_from")
            v_until_raw = row.get("Valid To (GMT)") or meta.get("valid_until")
            valid_from = parse_timestamp(v_from_raw, datetime(2000, 1, 1, tzinfo=timezone.utc))
            valid_until = parse_timestamp(v_until_raw, datetime(2035, 1, 1, tzinfo=timezone.utc))

            self.registry.register(sha256, subject_dn, valid_from, valid_until)

            # Apple
            if str(row.get("Apple Status", "")).strip().lower() == "included":
                records.append(TrustRecord("apple", snap_date, sha256, subject_dn, valid_from, valid_until, "serverAuth", DATA_SOURCE_TYPE, provenance))

            # Google Chrome
            if str(row.get("Chrome Status", "")).strip().lower() == "included":
                records.append(TrustRecord("google", snap_date, sha256, subject_dn, valid_from, valid_until, "serverAuth", DATA_SOURCE_TYPE, provenance))

            # Microsoft
            if str(row.get("Microsoft Status", "")).strip().lower() == "included":
                tbits = normalize_trust_bits(row.get("Derived Trust Bits") or "serverAuth", "microsoft")
                records.append(TrustRecord("microsoft", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

            # Mozilla
            if str(row.get("Mozilla Status", "")).strip().lower() == "included":
                tbits = normalize_trust_bits(row.get("Trust Bits for Root Cert") or row.get("Derived Trust Bits") or "serverAuth", "mozilla")
                records.append(TrustRecord("mozilla", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

        return records

    def _parse_all_records_v3(self, csv_text: str, snap_date: date, provenance: str) -> List[TrustRecord]:
        """Parses older 2022 `AllCertificateRecordsCSVFormat`."""
        records: List[TrustRecord] = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            rec_type = str(row.get("Certificate Record Type", "")).strip().lower()
            if "root" not in rec_type:
                continue

            sha256 = clean_sha256(row.get("SHA-256 Fingerprint"))
            if not sha256:
                continue

            cert_name = row.get("Certificate Name") or row.get("CA Owner") or "Unknown Root"
            meta = self.registry.get(sha256)
            subject_dn = self._resolve_subject_dn(meta, cert_name)
            valid_from = parse_timestamp(meta.get("valid_from"), datetime(2000, 1, 1, tzinfo=timezone.utc))
            valid_until = parse_timestamp(meta.get("valid_until"), datetime(2035, 1, 1, tzinfo=timezone.utc))

            # Microsoft Status
            if str(row.get("Microsoft Status", "")).strip().lower() == "included":
                records.append(TrustRecord("microsoft", snap_date, sha256, subject_dn, valid_from, valid_until, "serverAuth", DATA_SOURCE_TYPE, provenance))

            # Mozilla Status
            if str(row.get("Mozilla Status", "")).strip().lower() == "included":
                records.append(TrustRecord("mozilla", snap_date, sha256, subject_dn, valid_from, valid_until, "serverAuth", DATA_SOURCE_TYPE, provenance))

        return records

    def _parse_mozilla_report(self, csv_text: str, snap_date: date, provenance: str) -> List[TrustRecord]:
        """Parses Mozilla Included Root CA Certificate reports (CSV with or without PEM)."""
        records: List[TrustRecord] = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            sha256 = clean_sha256(row.get("SHA-256 Fingerprint"))
            if not sha256:
                continue

            cert_name = row.get("Common Name or Certificate Name") or row.get("Certificate Issuer Organization") or row.get("Owner") or "Unknown"
            v_from_raw = row.get("Valid From [GMT]")
            v_until_raw = row.get("Valid To [GMT]")

            meta = self.registry.get(sha256)
            subject_dn = self._resolve_subject_dn(meta, cert_name)
            valid_from = parse_timestamp(v_from_raw or meta.get("valid_from"), datetime(2000, 1, 1, tzinfo=timezone.utc))
            valid_until = parse_timestamp(v_until_raw or meta.get("valid_until"), datetime(2035, 1, 1, tzinfo=timezone.utc))

            self.registry.register(sha256, subject_dn, valid_from, valid_until)

            tbits = normalize_trust_bits(row.get("Trust Bits"), "mozilla")
            records.append(TrustRecord("mozilla", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

        return records

    def _parse_msft_report(self, csv_text: str, snap_date: date, provenance: str) -> List[TrustRecord]:
        """Parses Microsoft Included CA Certificate report."""
        records: List[TrustRecord] = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            status = str(row.get("Microsoft Status", "")).strip().lower()
            if status != "included":
                continue

            sha256 = clean_sha256(row.get("SHA-256 Fingerprint"))
            if not sha256:
                continue

            cert_name = row.get("CA Common Name or Certificate Name") or "Unknown"
            subject_dn = row.get("Subject") or self._resolve_subject_dn(self.registry.get(sha256), cert_name)
            v_from_raw = row.get("Valid From [GMT]")
            v_until_raw = row.get("Valid To [GMT]")

            meta = self.registry.get(sha256)
            valid_from = parse_timestamp(v_from_raw or meta.get("valid_from"), datetime(2000, 1, 1, tzinfo=timezone.utc))
            valid_until = parse_timestamp(v_until_raw or meta.get("valid_until"), datetime(2035, 1, 1, tzinfo=timezone.utc))

            self.registry.register(sha256, subject_dn, valid_from, valid_until)

            raw_ekus = row.get("Microsoft EKUs") or ""
            tbits = normalize_trust_bits(raw_ekus, "microsoft")
            records.append(TrustRecord("microsoft", snap_date, sha256, subject_dn, valid_from, valid_until, tbits, DATA_SOURCE_TYPE, provenance))

        return records


# ---------------------------------------------------------------------------
# Pipeline Orchestrator
# ---------------------------------------------------------------------------
class CCADBExtractionPipeline:
    """End-to-end pipeline orchestrating discovery, download, parsing, and Parquet export."""

    def __init__(
        self,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        output_parquet: Path = DEFAULT_OUTPUT_PARQUET,
        output_csv: Path = DEFAULT_OUTPUT_CSV,
    ):
        self.cache_dir = cache_dir
        self.output_parquet = output_parquet
        self.output_csv = output_csv
        self.manager = CCADBWaybackManager(cache_dir=self.cache_dir)
        self.registry = CertificateMetadataRegistry()
        self.parser = CCADBReportParser(self.registry)

    def run(self) -> pd.DataFrame:
        """Executes full pipeline across all pre-indexed and discovered snapshots."""
        logger.info("Starting CCADB Historical Extraction Pipeline...")
        all_records: List[TrustRecord] = []
        processed_snaps = 0

        for idx, spec in enumerate(PRE_INDEXED_SNAPSHOTS, 1):
            snap_id = spec["snapshot_id"]
            logger.info("[%2d/%2d] Processing CCADB snapshot: %s (%s)", idx, len(PRE_INDEXED_SNAPSHOTS), snap_id, spec["snapshot_date"])
            csv_text = self.manager.fetch_snapshot_csv(spec)
            if not csv_text:
                logger.warning("Skipping snapshot %s due to retrieval failure.", snap_id)
                continue

            records = self.parser.parse(spec, csv_text)
            logger.info("   -> Extracted %d vendor-cert trust observations.", len(records))
            all_records.extend(records)
            processed_snaps += 1

        if not all_records:
            raise RuntimeError("No records extracted from CCADB snapshots!")

        logger.info("Consolidating %d raw records into structured DataFrame...", len(all_records))
        df = pd.DataFrame([
            {
                "vendor": r.vendor,
                "snapshot_date": r.snapshot_date,
                "sha256_fingerprint": r.sha256_fingerprint,
                "subject_dn": r.subject_dn,
                "valid_from": r.valid_from,
                "valid_until": r.valid_until,
                "trust_bits": r.trust_bits,
                "data_source_type": r.data_source_type,
                "provenance_url_or_hash": r.provenance_url_or_hash,
            }
            for r in all_records
        ])

        # Deduplicate strictly on primary key: (vendor, snapshot_date, sha256_fingerprint)
        initial_len = len(df)
        df = df.drop_duplicates(subset=["vendor", "snapshot_date", "sha256_fingerprint"]).sort_values(
            by=["snapshot_date", "vendor", "sha256_fingerprint"]
        ).reset_index(drop=True)
        logger.info("Deduplication complete: %d -> %d records.", initial_len, len(df))

        # Enforce PyArrow schema
        logger.info("Saving Parquet dataset to: %s", self.output_parquet)
        self._save_parquet(df, self.output_parquet)

        logger.info("Saving CSV dataset to: %s", self.output_csv)
        df.to_csv(self.output_csv, index=False)

        self._print_summary(df)
        return df

    def _save_parquet(self, df: pd.DataFrame, path: Path) -> None:
        """Saves dataframe conforming strictly to SCHEMA.md Arrow types."""
        arrow_schema = pa.schema([
            ("vendor", pa.string()),
            ("snapshot_date", pa.date32()),
            ("sha256_fingerprint", pa.string()),
            ("subject_dn", pa.string()),
            ("valid_from", pa.timestamp("us", tz="UTC")),
            ("valid_until", pa.timestamp("us", tz="UTC")),
            ("trust_bits", pa.string()),
            ("data_source_type", pa.string()),
            ("provenance_url_or_hash", pa.string()),
        ])

        table = pa.Table.from_pandas(df, schema=arrow_schema, preserve_index=False)
        pq.write_table(table, path, compression="snappy")

    def _print_summary(self, df: pd.DataFrame) -> None:
        """Prints analytical summary of extracted CCADB historical data."""
        print("\n" + "=" * 90)
        print("CCADB HISTORICAL TRUST EXTRACTION SUMMARY")
        print("=" * 90)
        print(f"Total normalized records:       {len(df)}")
        print(f"Distinct snapshot dates:        {df['snapshot_date'].nunique()}")
        print(f"Distinct root certificates:     {df['sha256_fingerprint'].nunique()}")
        print("-" * 90)
        print("Coverage by Root Store Vendor:")
        summary = df.groupby("vendor").agg(
            min_date=("snapshot_date", "min"),
            max_date=("snapshot_date", "max"),
            records=("sha256_fingerprint", "count"),
            snapshots=("snapshot_date", "nunique"),
            unique_certs=("sha256_fingerprint", "nunique"),
        )
        print(summary.to_string())
        print("=" * 90 + "\n")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and parse historical CCADB CSV reports (2018-2026)."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=SCRIPT_DIR,
        help=f"Directory to save output files (default: {SCRIPT_DIR})",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Directory for caching raw CSV downloads (default: {DEFAULT_CACHE_DIR})",
    )

    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_parquet = args.output_dir / "ccadb_trust_history.parquet"
    out_csv = args.output_dir / "ccadb_trust_history.csv"

    pipeline = CCADBExtractionPipeline(
        cache_dir=args.cache_dir,
        output_parquet=out_parquet,
        output_csv=out_csv,
    )
    pipeline.run()


if __name__ == "__main__":
    main()
