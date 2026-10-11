#!/usr/bin/env python3
"""
Apple Root Store Wayback Machine Extractor
==========================================

This module extracts historical snapshots of Apple's Root Certificate Store
by querying the Internet Archive Wayback Machine (CDX API) and scraping
archived Apple Support Knowledge Base articles with BeautifulSoup.

Because Apple publishes its root store as HTML support articles rather than
version-controlled code repositories, this extractor:
1. Queries the CDX Server API for historical snapshots of designated Apple
   seed support URLs.
2. Applies rate-limiting (default: 2.0s sleep) and on-disk caching to prevent
   Wayback Machine IP throttling and allow resume/idempotent runs.
3. Dynamically identifies tables and parses Certificate Names and SHA-256
   fingerprints, normalizing hex digests to 64 lowercase characters.
4. Maps conformed records to `SCHEMA.md` and saves them to
   `data/raw/apple_history.parquet`.

Author: Data Engineering & Security Research Team
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("extractors.apple")

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
WAYBACK_CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_REPLAY_URL_TEMPLATE = "https://web.archive.org/web/{timestamp}id_/{original}"
WAYBACK_VIEW_URL_TEMPLATE = "https://web.archive.org/web/{timestamp}/{original}"

DEFAULT_SEED_URLS = [
    "https://support.apple.com/en-us/HT213464",  # iOS 16 / macOS Ventura (2022-2024)
    "https://support.apple.com/en-us/HT209144",  # macOS High Sierra (2018-2020)
    "https://support.apple.com/en-us/HT204132",  # Classic Apple Root Store Article
]

DEFAULT_OUTPUT_PATH = Path("data/raw/apple_history.parquet")
DEFAULT_CACHE_DIR = Path("data/raw/.apple_cache")
VENDOR_NAME = "apple"
DATA_SOURCE_TYPE = "wayback_html"
DEFAULT_TRUST_BITS = "serverAuth"
DEFAULT_SLEEP_SECONDS = 2.0


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class WaybackSnapshotMetadata:
    """Metadata for an archived snapshot captured by the Wayback Machine."""

    timestamp: str
    original_url: str
    status_code: str = "200"

    @property
    def snapshot_date(self) -> date:
        """Parses YYYYMMDD... prefix into an ISO 8601 date."""
        year = int(self.timestamp[:4])
        month = int(self.timestamp[4:6])
        day = int(self.timestamp[6:8])
        return date(year, month, day)

    @property
    def replay_url(self) -> str:
        """Constructs raw identity Wayback replay URL for scraping without injected toolbar."""
        return WAYBACK_REPLAY_URL_TEMPLATE.format(
            timestamp=self.timestamp,
            original=self.original_url,
        )

    @property
    def provenance_url(self) -> str:
        """Constructs standard human-viewable Wayback replay URL for provenance tracking."""
        return WAYBACK_VIEW_URL_TEMPLATE.format(
            timestamp=self.timestamp,
            original=self.original_url,
        )


@dataclass(frozen=True)
class CertificateRecord:
    """Normalized certificate entry matching SCHEMA.md specifications."""

    vendor: str
    snapshot_date: date
    sha256_fingerprint: str
    subject_dn: Optional[str]
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    trust_bits: str
    data_source_type: str
    provenance_url_or_hash: str


# ---------------------------------------------------------------------------
# CDX API Client & HTML Scraper
# ---------------------------------------------------------------------------
class WaybackClient:
    """
    Manages querying the Wayback Machine CDX API and downloading archived HTML pages
    with rate limiting, exponential backoff, and local disk caching.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = DEFAULT_CACHE_DIR,
        sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
        max_retries: int = 3,
    ):
        self.cache_dir = cache_dir
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.sleep_seconds = sleep_seconds
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def fetch_snapshots_for_url(
        self,
        seed_url: str,
    ) -> List[WaybackSnapshotMetadata]:
        """
        Queries the CDX API for all archived snapshots of a seed URL.
        Caches CDX responses locally to avoid redundant API hits.
        """
        url_hash = hashlib.sha256(seed_url.encode("utf-8")).hexdigest()[:12]
        cache_file = self.cache_dir / f"cdx_{url_hash}.json" if self.cache_dir else None

        if cache_file and cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_rows = json.load(f)
                logger.info("Loaded %d snapshots from CDX cache for: %s", len(cached_rows), seed_url)
                return [WaybackSnapshotMetadata(**r) for r in cached_rows]
            except Exception as e:
                logger.warning("Could not read CDX cache for %s: %s", seed_url, e)

        logger.info("Querying Wayback CDX API for: %s ...", seed_url)
        params = {
            "url": seed_url,
            "output": "json",
            "fl": "timestamp,original,statuscode",
            "filter": "statuscode:200",
        }

        snapshots: List[WaybackSnapshotMetadata] = []
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(WAYBACK_CDX_API_URL, params=params, timeout=25)
                if resp.status_code == 200:
                    data = resp.json()
                    if len(data) > 1:
                        # Row 0 is header ["timestamp", "original", "statuscode"]
                        for row in data[1:]:
                            if len(row) >= 2 and len(row[0]) >= 8:
                                snapshots.append(
                                    WaybackSnapshotMetadata(
                                        timestamp=row[0],
                                        original_url=row[1],
                                        status_code=row[2] if len(row) > 2 else "200",
                                    )
                                )
                    logger.info("CDX API returned %d snapshots for %s", len(snapshots), seed_url)
                    break
                elif resp.status_code in (429, 503):
                    wait = 5 * attempt
                    logger.warning("Wayback CDX API rate-limited (HTTP %d). Waiting %ds...", resp.status_code, wait)
                    time.sleep(wait)
                else:
                    logger.warning("CDX API returned HTTP %d for %s", resp.status_code, seed_url)
                    break
            except requests.RequestException as e:
                logger.warning("CDX request attempt %d failed for %s: %s", attempt, seed_url, e)
                if attempt < self.max_retries:
                    time.sleep(3 * attempt)

        # Cache valid results
        if cache_file and snapshots:
            try:
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump([vars(s) for s in snapshots], f, indent=2)
            except Exception as e:
                logger.debug("Failed saving CDX cache: %s", e)

        return snapshots

    def fetch_html_content(
        self,
        snapshot: WaybackSnapshotMetadata,
    ) -> Optional[str]:
        """
        Retrieves archived HTML for a snapshot.
        Checks local cache first; otherwise requests over HTTP and sleeps sleep_seconds.
        """
        url_hash = hashlib.sha256(snapshot.original_url.encode("utf-8")).hexdigest()[:8]
        cache_file = self.cache_dir / f"html_{snapshot.timestamp}_{url_hash}.html" if self.cache_dir else None

        if cache_file and cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            except Exception as e:
                logger.debug("Error reading HTML cache: %s", e)

        replay_url = snapshot.replay_url
        logger.info("Fetching archived page from Wayback: %s ...", replay_url)

        content: Optional[str] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(replay_url, timeout=30)
                if resp.status_code == 200:
                    content = resp.text
                    break
                elif resp.status_code in (429, 503):
                    wait = 6 * attempt
                    logger.warning("Wayback replay rate-limited (HTTP %d). Backing off %ds...", resp.status_code, wait)
                    time.sleep(wait)
                else:
                    logger.warning("Wayback returned HTTP %d for %s", resp.status_code, replay_url)
                    break
            except requests.RequestException as e:
                logger.warning("Wayback fetch attempt %d failed for %s: %s", attempt, replay_url, e)
                if attempt < self.max_retries:
                    time.sleep(4 * attempt)

        # Enforce rate-limiting pause between HTTP requests
        time.sleep(self.sleep_seconds)

        if content and cache_file:
            try:
                with open(cache_file, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(content)
            except Exception as e:
                logger.debug("Failed saving HTML cache: %s", e)

        return content


# ---------------------------------------------------------------------------
# HTML Table Parser
# ---------------------------------------------------------------------------
class AppleTableParser:
    """
    Parses Apple Support HTML tables to extract certificate names and fingerprints.
    Dynamically identifies columns and cleans hexadecimal fingerprints.
    """

    _HEX_CLEAN_RE = re.compile(r"[^0-9a-fA-F]")

    @classmethod
    def clean_fingerprint(cls, raw: str) -> Optional[str]:
        """
        Removes spaces, colons, hyphens, and whitespace, converting to lowercase.
        Returns the 64-hex string if valid SHA-256, or None.
        """
        cleaned = cls._HEX_CLEAN_RE.sub("", raw).lower()
        if len(cleaned) == 64:
            return cleaned
        return None

    @classmethod
    def parse_tables(
        cls,
        html_content: str,
        snapshot_date: date,
        replay_url: str,
    ) -> List[CertificateRecord]:
        """
        Parses all HTML tables on an Apple Root Store page.
        Identifies certificate name and SHA-256 fingerprint columns dynamically.
        """
        soup = BeautifulSoup(html_content, "html.parser")
        tables = soup.find_all("table")
        records: List[CertificateRecord] = []

        for table_idx, table in enumerate(tables):
            # Check context from preceding header
            prev_header = table.find_previous(["h2", "h3", "h1"])
            header_text = prev_header.get_text(strip=True).lower() if prev_header else ""

            is_blocked = any(k in header_text for k in ["block", "distrust", "untrusted"])
            is_always_ask = "always ask" in header_text
            
            if is_blocked:
                trust_bits = ""
            elif is_always_ask:
                trust_bits = "alwaysAsk"
            else:
                trust_bits = DEFAULT_TRUST_BITS

            # Determine column mapping from table header
            rows = table.find_all("tr")
            if not rows:
                continue

            # First row may have <th> or <td>
            header_cells = rows[0].find_all(["th", "td"])
            headers = [c.get_text(strip=True).lower() for c in header_cells]

            fp_col_idx = -1
            name_col_idx = -1

            # Match fingerprint column (prioritizing SHA-256)
            for idx, h in enumerate(headers):
                if "sha-256" in h or "sha256" in h:
                    fp_col_idx = idx
                    break
                elif "fingerprint" in h and fp_col_idx == -1:
                    fp_col_idx = idx

            # Match certificate name column
            for idx, h in enumerate(headers):
                if any(k in h for k in ["certificate name", "certificate", "ca name", "ca"]) and name_col_idx == -1:
                    name_col_idx = idx
                    break

            # Fallback if headers didn't match: inspect data cells in first few rows
            if fp_col_idx == -1 and len(rows) > 1:
                sample_cells = [c.get_text(strip=True) for c in rows[1].find_all(["td", "th"])]
                for idx, cell_text in enumerate(sample_cells):
                    cleaned = cls.clean_fingerprint(cell_text)
                    if cleaned:
                        fp_col_idx = idx
                        break

            if fp_col_idx == -1:
                logger.debug("Table %d has no identifiable SHA-256 fingerprint column. Skipping.", table_idx)
                continue

            # Iterate data rows
            data_rows = rows[1:]
            for row in data_rows:
                cells = [c.get_text(strip=True) for c in row.find_all(["td", "th"])]
                if not cells or len(cells) <= fp_col_idx:
                    continue

                raw_fp = cells[fp_col_idx]
                fp = cls.clean_fingerprint(raw_fp)
                if not fp:
                    continue

                cert_name: Optional[str] = None
                if name_col_idx != -1 and len(cells) > name_col_idx:
                    cert_name = cells[name_col_idx].strip() or None

                records.append(
                    CertificateRecord(
                        vendor=VENDOR_NAME,
                        snapshot_date=snapshot_date,
                        sha256_fingerprint=fp,
                        subject_dn=cert_name,
                        valid_from=None,
                        valid_until=None,
                        trust_bits=trust_bits,
                        data_source_type=DATA_SOURCE_TYPE,
                        provenance_url_or_hash=replay_url,
                    )
                )

        return records


# ---------------------------------------------------------------------------
# Sampling Helper
# ---------------------------------------------------------------------------
def sample_snapshots(
    snapshots: Sequence[WaybackSnapshotMetadata],
    strategy: str = "yearly",
    max_count: Optional[int] = None,
) -> List[WaybackSnapshotMetadata]:
    """
    Subsamples snapshots based on timestamp:
    - 'yearly': latest snapshot of each year.
    - 'quarterly': latest snapshot of each quarter.
    - 'latest': only the single most recent snapshot.
    - 'all': all snapshots.
    """
    if not snapshots:
        return []

    sorted_snaps = sorted(snapshots, key=lambda s: s.timestamp)

    if strategy == "all":
        selected = list(sorted_snaps)
    elif strategy == "latest":
        selected = [sorted_snaps[-1]]
    else:
        grouped = defaultdict(list)
        for s in sorted_snaps:
            dt = s.snapshot_date
            if strategy == "yearly":
                key = dt.year
            elif strategy == "quarterly":
                quarter = (dt.month - 1) // 3 + 1
                key = (dt.year, quarter)
            else:
                raise ValueError(f"Unknown sampling strategy: '{strategy}'")
            grouped[key].append(s)

        selected = [snaps[-1] for _, snaps in sorted(grouped.items())]

    if max_count and len(selected) > max_count:
        # Sample evenly across the range
        step = len(selected) / max_count
        selected = [selected[int(i * step)] for i in range(max_count)]

    return selected


# ---------------------------------------------------------------------------
# Pipeline Orchestration
# ---------------------------------------------------------------------------
def run_extraction(
    seed_urls: Sequence[str] = DEFAULT_SEED_URLS,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    cache_dir: Optional[Path] = DEFAULT_CACHE_DIR,
    sampling: str = "yearly",
    max_snapshots_per_url: Optional[int] = None,
    sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
) -> pd.DataFrame:
    """
    Runs the Apple Root Store extraction pipeline:
    1. Collects snapshot metadata from CDX API.
    2. Subsamples snapshots (yearly, quarterly, etc.).
    3. Fetches archived HTML with rate-limiting.
    4. Parses certificate tables using BeautifulSoup.
    5. Saves conformed records to Parquet adhering to SCHEMA.md.
    """
    client = WaybackClient(
        cache_dir=cache_dir,
        sleep_seconds=sleep_seconds,
    )

    all_records: List[CertificateRecord] = []
    total_snapshots_processed = 0

    for url_idx, seed_url in enumerate(seed_urls, start=1):
        logger.info(
            "=== [%d/%d] Processing Seed URL: %s ===",
            url_idx,
            len(seed_urls),
            seed_url,
        )

        raw_snapshots = client.fetch_snapshots_for_url(seed_url)
        if not raw_snapshots:
            logger.warning("No snapshots available for %s. Skipping.", seed_url)
            continue

        selected_snaps = sample_snapshots(
            raw_snapshots,
            strategy=sampling,
            max_count=max_snapshots_per_url,
        )
        logger.info(
            "Selected %d snapshots (from %d total) using '%s' strategy for %s.",
            len(selected_snaps),
            len(raw_snapshots),
            sampling,
            seed_url,
        )

        for snap_idx, snapshot in enumerate(selected_snaps, start=1):
            total_snapshots_processed += 1
            logger.info(
                "[%d/%d] Scraping snapshot %s (%s)...",
                snap_idx,
                len(selected_snaps),
                snapshot.snapshot_date.isoformat(),
                snapshot.timestamp,
            )

            html = client.fetch_html_content(snapshot)
            if not html:
                logger.warning("Could not retrieve HTML for snapshot %s.", snapshot.timestamp)
                continue

            records = AppleTableParser.parse_tables(
                html_content=html,
                snapshot_date=snapshot.snapshot_date,
                replay_url=snapshot.provenance_url,
            )

            logger.info(
                "  -> Extracted %d certificates (trusted: %d)",
                len(records),
                sum(1 for r in records if r.trust_bits != ""),
            )
            all_records.extend(records)

    logger.info("Total certificate records extracted for Apple in this run: %d", len(all_records))

    new_df = pd.DataFrame([vars(r) for r in all_records])

    # Incremental checkpointing: merge with existing dataset if present
    if output_path.exists():
        try:
            existing_df = pd.read_parquet(output_path)
            if not new_df.empty:
                df = pd.concat([existing_df, new_df], ignore_index=True)
                logger.info("Merged %d new records with %d existing records.", len(new_df), len(existing_df))
            else:
                df = existing_df
        except Exception as e:
            logger.warning("Could not read existing parquet file (%s): %s", output_path, e)
            df = new_df
    else:
        df = new_df

    if df.empty:
        logger.warning("No records extracted and no existing dataset found.")
        return df

    # Deduplicate within same snapshot if multiple tables or duplicate rows occurred
    df = df.drop_duplicates(subset=["vendor", "snapshot_date", "sha256_fingerprint"])
    df = df.sort_values(by=["snapshot_date", "sha256_fingerprint"])

    # Enforce exact column typing according to SCHEMA.md
    df["snapshot_date"] = pd.to_datetime(df["snapshot_date"]).dt.date
    df["valid_from"] = pd.to_datetime(df["valid_from"], utc=True)
    df["valid_until"] = pd.to_datetime(df["valid_until"], utc=True)

    schema_columns = [
        "vendor",
        "snapshot_date",
        "sha256_fingerprint",
        "subject_dn",
        "valid_from",
        "valid_until",
        "trust_bits",
        "data_source_type",
        "provenance_url_or_hash",
    ]
    df = df[schema_columns]

    # Enforce PyArrow schema matching SCHEMA.md
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

    table = pa.Table.from_pandas(df, schema=arrow_schema)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, output_path)
    logger.info("Successfully saved dataset to: %s", output_path.resolve())
    logger.info("Dataset shape: %d rows x %d columns", df.shape[0], df.shape[1])

    return df


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def parse_arguments() -> argparse.Namespace:
    """Parse CLI options for the Apple Wayback extractor."""
    parser = argparse.ArgumentParser(
        description="Extract historical Apple Root Store snapshots via Wayback Machine HTML scraping."
    )
    parser.add_argument(
        "--seed-urls",
        nargs="+",
        default=DEFAULT_SEED_URLS,
        help="One or more Apple Support Seed URLs to scrape.",
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Target Parquet output file path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Directory for caching CDX and HTML data (default: {DEFAULT_CACHE_DIR}).",
    )
    parser.add_argument(
        "--sampling",
        choices=["yearly", "quarterly", "latest", "all"],
        default="yearly",
        help="Snapshot sampling frequency: yearly, quarterly, latest, or all (default: yearly).",
    )
    parser.add_argument(
        "--max-snapshots",
        type=int,
        default=None,
        help="Maximum snapshots to process per seed URL.",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=DEFAULT_SLEEP_SECONDS,
        help=f"Pause duration between live HTTP requests in seconds (default: {DEFAULT_SLEEP_SECONDS}).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable on-disk caching.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI execution entry point."""
    args = parse_arguments()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    cache_dir = None if args.no_cache else args.cache_dir

    run_extraction(
        seed_urls=args.seed_urls,
        output_path=args.output_path,
        cache_dir=cache_dir,
        sampling=args.sampling,
        max_snapshots_per_url=args.max_snapshots,
        sleep_seconds=args.sleep_seconds,
    )


if __name__ == "__main__":
    main()
