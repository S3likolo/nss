#!/usr/bin/env python3
"""
Google Chrome Root Store (CRS) Extractor
========================================

This module extracts historical snapshots of Google's Chrome Root Store (CRS)
from the Chromium open-source Git repository.

Google introduced its own Chrome Root Store around 2021/2022 to transition
from operating system trust stores to an independent Web PKI root store.
The authoritative source definition in Chromium is located at:
`net/data/ssl/chrome_root_store/root_store.textproto`.

Key Workflow:
1. Resource-efficient mining:
   Because the full Chromium Git repository is tens of gigabytes, this extractor
   mines revision history via the GitHub Commits REST API targeted strictly at
   `net/data/ssl/chrome_root_store/root_store.textproto` (with support for optional
   local repository access and disk caching).
2. Content Retrieval:
   Retrieves raw file contents for each commit SHA via raw.githubusercontent.com CDN,
   avoiding Git checkout overhead and REST API quota depletion.
3. Parsing .textproto format:
   Robust multi-pattern regex parser extracting hex SHA-256 digests (`sha256_hex`,
   `sha256_root_hash`, etc.) across historical syntax variations.
4. Schema Mapping & Persistence:
   Conforms strictly to `SCHEMA.md` (setting unknown X.509 metadata to None/NULL)
   and saves records to `data/raw/google_history.parquet`.

Author: Data Engineering & Security Research Team
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import requests

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("extractors.google")

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
GITHUB_API_COMMITS_URL = "https://api.github.com/repos/chromium/chromium/commits"
RAW_FILE_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/chromium/chromium/{sha}/{path}"
)
DEFAULT_TARGET_PATH = "net/data/ssl/chrome_root_store/root_store.textproto"
DEFAULT_OUTPUT_PATH = Path("data/raw/google_history.parquet")
DEFAULT_CACHE_DIR = Path("data/raw/.google_cache")
VENDOR_NAME = "google"
DATA_SOURCE_TYPE = "git_commit"
DEFAULT_TRUST_BITS = "serverAuth"  # Chrome Root Store anchors provide Web PKI TLS serverAuth


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CommitMetadata:
    """Git commit information for a specific revision."""

    sha: str
    date_iso: str
    message: str

    @property
    def commit_date(self) -> date:
        return datetime.fromisoformat(self.date_iso.replace("Z", "+00:00")).date()


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
# textproto File Parser
# ---------------------------------------------------------------------------
class TextprotoParser:
    """
    Parses Chromium .textproto files to extract root certificate SHA-256 hashes.
    Includes multiple extraction strategies to remain resilient against proto schema changes.
    """

    # Primary key in root_store.textproto: sha256_hex: "..." or sha256_root_hash: "..."
    _PRIMARY_HASH_RE = re.compile(
        r'(?:sha256_hex|sha256_root_hash|sha256|root_hash)\s*:\s*["\']([0-9a-fA-F]{64})["\']'
    )
    # Block-scoped fallback: inside trust_anchors { ... }
    _TRUST_ANCHOR_BLOCK_RE = re.compile(r"trust_anchors\s*\{([^}]+)\}", re.DOTALL)
    # Generic 64-hex hash fallback
    _HEX_HASH_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")

    @classmethod
    def extract_hashes(cls, text: str) -> List[str]:
        """
        Extracts a deduplicated list of cleaned, lowercase SHA-256 hexadecimal digests.
        """
        # Strategy 1: Match explicit hash key-value pairs
        matches = cls._PRIMARY_HASH_RE.findall(text)
        if matches:
            cleaned = [m.lower().strip() for m in matches]
            # Deduplicate while preserving order
            return list(dict.fromkeys(cleaned))

        # Strategy 2: Match 64-hex hashes scoped inside trust_anchors blocks
        scoped_matches: List[str] = []
        for block in cls._TRUST_ANCHOR_BLOCK_RE.findall(text):
            block_hashes = cls._HEX_HASH_RE.findall(block)
            scoped_matches.extend(block_hashes)
        if scoped_matches:
            cleaned = [m.lower().strip() for m in scoped_matches]
            return list(dict.fromkeys(cleaned))

        # Strategy 3: Global 64-hex string fallback
        generic_matches = cls._HEX_HASH_RE.findall(text)
        if generic_matches:
            logger.warning("Fell back to generic 64-hex pattern matching.")
            cleaned = [m.lower().strip() for m in generic_matches]
            return list(dict.fromkeys(cleaned))

        return []


# ---------------------------------------------------------------------------
# History Mining & Remote Content Client
# ---------------------------------------------------------------------------
class ChromiumHistoryClient:
    """
    Handles lightweight retrieval of Chromium Git commit history and file contents
    without cloning the multi-gigabyte Chromium repository.
    """

    def __init__(
        self,
        github_token: Optional[str] = None,
        cache_dir: Optional[Path] = DEFAULT_CACHE_DIR,
    ):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.cache_dir = cache_dir
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebPKI-RootStore-Researcher/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"Bearer {self.github_token}"
            logger.info("Authenticated GitHub API requests enabled with provided token.")
        else:
            logger.info("Using unauthenticated GitHub API requests (rate limit: 60/hr).")

    def fetch_commit_history(
        self,
        path: str = DEFAULT_TARGET_PATH,
        per_page: int = 10,
    ) -> List[CommitMetadata]:
        """
        Paginates through GitHub commits API for the specified file path.
        Stops when all commits have been collected or end-of-history is reached.
        """
        cache_file = self.cache_dir / "commits_metadata.json" if self.cache_dir else None

        # Check local metadata cache first
        if cache_file and cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                logger.info("Loaded %d commits from local cache (%s).", len(cached_data), cache_file)
                return [CommitMetadata(**c) for c in cached_data]
            except Exception as e:
                logger.warning("Could not read commits cache (%s), fetching fresh: %s", cache_file, e)

        logger.info("Querying GitHub REST API for revision history of '%s'...", path)
        commits: List[CommitMetadata] = []
        page = 1

        while True:
            params = {"path": path, "per_page": per_page, "page": page}
            try:
                resp = self.session.get(GITHUB_API_COMMITS_URL, params=params, timeout=15)
            except requests.RequestException as e:
                logger.error("HTTP request failed on page %d: %s", page, e)
                break

            # Handle rate limiting
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if resp.status_code == 403 or resp.status_code == 429:
                reset_time = resp.headers.get("X-RateLimit-Reset", "unknown")
                logger.error(
                    "GitHub API rate limit exceeded (status %d). Remaining: %s, Reset: %s",
                    resp.status_code,
                    remaining,
                    reset_time,
                )
                break

            # GitHub returns 500 when traversing past the beginning of a file in large repos
            if resp.status_code != 200:
                logger.info(
                    "API returned status %d on page %d (reached end of file history).",
                    resp.status_code,
                    page,
                )
                break

            items = resp.json()
            if not items or not isinstance(items, list):
                logger.info("No further commits returned on page %d.", page)
                break

            for item in items:
                sha = item.get("sha")
                commit_info = item.get("commit", {})
                committer_info = commit_info.get("committer", {}) or commit_info.get("author", {})
                date_iso = committer_info.get("date", "")
                message = commit_info.get("message", "").split("\n")[0]

                if sha and date_iso:
                    commits.append(
                        CommitMetadata(
                            sha=sha,
                            date_iso=date_iso,
                            message=message,
                        )
                    )

            logger.info(
                "Page %d: retrieved %d commits (total: %d, rate limit remaining: %s)",
                page,
                len(items),
                len(commits),
                remaining,
            )

            # End of pagination check
            if len(items) < per_page:
                break

            page += 1
            time.sleep(0.3)  # Gentle polite delay

        logger.info("Completed commit history discovery: %d commits found.", len(commits))

        # Save to cache if available
        if cache_file and commits:
            try:
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump([vars(c) for c in commits], f, indent=2)
                logger.info("Cached commit metadata to: %s", cache_file)
            except Exception as e:
                logger.warning("Failed to write commit cache: %s", e)

        return commits

    def fetch_file_content(
        self,
        commit_sha: str,
        path: str = DEFAULT_TARGET_PATH,
    ) -> Optional[str]:
        """
        Fetches raw file text for a specific commit SHA via raw.githubusercontent.com CDN.
        Uses on-disk file caching to avoid redundant downloads.
        """
        cache_file = self.cache_dir / f"{commit_sha[:12]}_root_store.textproto" if self.cache_dir else None

        if cache_file and cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                logger.debug("Failed reading cached textproto %s: %s", cache_file, e)

        url = RAW_FILE_URL_TEMPLATE.format(sha=commit_sha, path=path)
        try:
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                if cache_file:
                    try:
                        with open(cache_file, "w", encoding="utf-8") as f:
                            f.write(content)
                    except Exception as e:
                        logger.debug("Failed writing textproto cache %s: %s", cache_file, e)
                return content
            elif resp.status_code == 404:
                logger.warning("File '%s' not found at commit %s (HTTP 404).", path, commit_sha[:10])
                return None
            else:
                logger.warning("Unexpected status %d fetching %s at commit %s", resp.status_code, path, commit_sha[:10])
                return None
        except requests.RequestException as e:
            logger.error("Network error fetching raw file for commit %s: %s", commit_sha[:10], e)
            return None


# ---------------------------------------------------------------------------
# Sampling Helper
# ---------------------------------------------------------------------------
def sample_commits(
    commits: Sequence[CommitMetadata],
    strategy: str = "all",
) -> List[CommitMetadata]:
    """
    Subsamples commits chronologically:
    - 'all': every commit.
    - 'quarterly': the latest commit in each (year, quarter).
    - 'yearly': the latest commit in each year.
    """
    # Sort chronologically (oldest to newest)
    sorted_commits = sorted(commits, key=lambda c: c.commit_date)

    if strategy == "all":
        return sorted_commits

    grouped = defaultdict(list)
    for c in sorted_commits:
        dt = c.commit_date
        if strategy == "quarterly":
            quarter = (dt.month - 1) // 3 + 1
            key = (dt.year, quarter)
        elif strategy == "yearly":
            key = dt.year
        else:
            raise ValueError(f"Unsupported sampling strategy: '{strategy}'")
        grouped[key].append(c)

    # Pick the latest commit in each period
    sampled = [commit_list[-1] for _, commit_list in sorted(grouped.items())]
    logger.info(
        "Sampled %d commits using '%s' strategy from %d available commits.",
        len(sampled),
        strategy,
        len(commits),
    )
    return sampled


# ---------------------------------------------------------------------------
# Extraction Pipeline
# ---------------------------------------------------------------------------
def run_extraction(
    target_path: str = DEFAULT_TARGET_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    cache_dir: Optional[Path] = DEFAULT_CACHE_DIR,
    sampling: str = "all",
    github_token: Optional[str] = None,
) -> pd.DataFrame:
    """
    Executes the Google Chrome Root Store extraction pipeline:
    1. Discovers commit history via GitHub API.
    2. Samples commits.
    3. Fetches and parses .textproto files.
    4. Compiles normalized DataFrame matching SCHEMA.md.
    5. Saves output to Parquet.
    """
    client = ChromiumHistoryClient(
        github_token=github_token,
        cache_dir=cache_dir,
    )

    commits = client.fetch_commit_history(path=target_path)
    if not commits:
        logger.error("No commits discovered for '%s'. Extraction aborted.", target_path)
        return pd.DataFrame()

    selected_commits = sample_commits(commits, strategy=sampling)
    total_snapshots = len(selected_commits)
    logger.info("Beginning extraction for %d CRS snapshots...", total_snapshots)

    all_records: List[CertificateRecord] = []

    for idx, commit in enumerate(selected_commits, start=1):
        snapshot_date = commit.commit_date
        sha = commit.sha
        logger.info(
            "[%d/%d] Processing snapshot %s (Commit: %s, Message: %.50s)...",
            idx,
            total_snapshots,
            snapshot_date.isoformat(),
            sha[:10],
            commit.message,
        )

        content = client.fetch_file_content(commit_sha=sha, path=target_path)
        if not content:
            logger.warning("Skipping commit %s: failed to retrieve file content.", sha[:10])
            continue

        hashes = TextprotoParser.extract_hashes(content)
        logger.info("  -> Extracted %d root certificate hashes.", len(hashes))

        for cert_hash in hashes:
            record = CertificateRecord(
                vendor=VENDOR_NAME,
                snapshot_date=snapshot_date,
                sha256_fingerprint=cert_hash,
                subject_dn=None,     # Set to None/NULL per specification
                valid_from=None,     # Set to None/NULL per specification
                valid_until=None,    # Set to None/NULL per specification
                trust_bits=DEFAULT_TRUST_BITS,
                data_source_type=DATA_SOURCE_TYPE,
                provenance_url_or_hash=sha,
            )
            all_records.extend([record])

    logger.info("Total certificate snapshot records extracted: %d", len(all_records))

    df = pd.DataFrame([vars(r) for r in all_records])

    if df.empty:
        logger.warning("No records extracted. Parquet file will not be written.")
        return df

    # Enforce exact column typing and ordering according to SCHEMA.md
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

    # Enforce exact column typing and schema according to SCHEMA.md
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

    # Save to Parquet
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, output_path)
    logger.info("Successfully saved dataset to: %s", output_path.resolve())
    logger.info("Dataset shape: %d rows x %d columns", df.shape[0], df.shape[1])

    return df


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def parse_arguments() -> argparse.Namespace:
    """Parse CLI options for the Google CRS extractor."""
    parser = argparse.ArgumentParser(
        description="Extract historical Google Chrome Root Store snapshots to Parquet."
    )
    parser.add_argument(
        "--target-path",
        default=DEFAULT_TARGET_PATH,
        help=f"Path to root_store.textproto inside Chromium (default: {DEFAULT_TARGET_PATH}).",
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
        help=f"Directory for caching downloaded metadata and textproto files (default: {DEFAULT_CACHE_DIR}).",
    )
    parser.add_argument(
        "--sampling",
        choices=["all", "quarterly", "yearly"],
        default="all",
        help="Commit sampling strategy: all, quarterly, or yearly (default: all).",
    )
    parser.add_argument(
        "--github-token",
        default=None,
        help="Optional GitHub personal access token to increase REST API rate limits.",
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
        target_path=args.target_path,
        output_path=args.output_path,
        cache_dir=cache_dir,
        sampling=args.sampling,
        github_token=args.github_token,
    )


if __name__ == "__main__":
    main()
