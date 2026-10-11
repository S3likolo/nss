#!/usr/bin/env python3
"""
Mozilla NSS Root Store Extractor
================================

This module extracts historical snapshots of Mozilla's Root CA trust store from
the NSS (Network Security Services) Git repository.

Key Workflow:
1. Clones or accesses the NSS repository (https://github.com/nss-dev/nss.git).
2. Traverses the Git revision history of `certdata.txt` (accounting for the
   2013 directory reorganization from `security/nss/lib/ckfw/builtins/certdata.txt`
   to `lib/ckfw/builtins/certdata.txt`).
3. Samples commits chronologically (quarterly, yearly, or all) from a given start year.
4. For each selected commit, parses `certdata.txt`:
   - Decodes multiline octal byte sequences (`CKA_VALUE`) to DER format.
   - Computes SHA-256 fingerprint.
   - Parses X.509 metadata (Subject DN, valid_from, valid_until).
   - Resolves trust flags from `CKO_NSS_TRUST` objects (serverAuth, emailProtection, codeSigning).
5. Compiles snapshots into a Pandas DataFrame conforming to `SCHEMA.md`.
6. Saves the resulting historical dataset to `data/raw/mozilla_history.parquet`.

Author: Data Engineering & Security Research Team
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import shutil
import sys
import tempfile
import warnings
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import git
import pandas as pd
from cryptography import x509
from asn1crypto import x509 as asn1_x509

# Suppress known legacy certificate format warnings from cryptography & asn1crypto
warnings.filterwarnings("ignore", category=UserWarning)
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("extractors.mozilla")

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
DEFAULT_REPO_URL = "https://github.com/nss-dev/nss.git"
DEFAULT_OUTPUT_PATH = Path("data/raw/mozilla_history.parquet")
DEFAULT_START_YEAR = 2010
VENDOR_NAME = "mozilla"
DATA_SOURCE_TYPE = "git_commit"

# Historical paths of certdata.txt in NSS repository
CERTDATA_PATHS = [
    "lib/ckfw/builtins/certdata.txt",
    "security/nss/lib/ckfw/builtins/certdata.txt",
]

# Trust token mapping: NSS attribute -> Standardized Web PKI trust bit
TRUST_FLAG_MAP = {
    "CKA_TRUST_SERVER_AUTH": "serverAuth",
    "CKA_TRUST_EMAIL_PROTECTION": "emailProtection",
    "CKA_TRUST_CODE_SIGNING": "codeSigning",
}
TRUSTED_VAL = "CKT_NSS_TRUSTED_DELEGATOR"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CertificateRecord:
    """Normalized certificate entry matching SCHEMA.md specifications."""

    vendor: str
    snapshot_date: date
    sha256_fingerprint: str
    subject_dn: str
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    trust_bits: str
    data_source_type: str
    provenance_url_or_hash: str


# ---------------------------------------------------------------------------
# Octal Decoder & X.509 Parsing Helpers
# ---------------------------------------------------------------------------
class OctalDecoder:
    """Handles decoding of multiline octal byte representations in certdata.txt."""

    _OCTAL_RE = re.compile(r"\\([0-7]{1,3})")

    @classmethod
    def decode(cls, octal_str: str) -> bytes:
        """Convert a string containing octal escapes (e.g. \\060\\202) into bytes."""
        octets = [int(match, 8) for match in cls._OCTAL_RE.findall(octal_str)]
        return bytes(octets)


class X509MetadataExtractor:
    """Extracts cryptographic and identity metadata from raw DER certificates."""

    @staticmethod
    def extract_metadata(
        der_bytes: bytes,
    ) -> Tuple[str, Optional[datetime], Optional[datetime]]:
        """
        Extracts (subject_dn, valid_from, valid_until) from DER bytes.
        Uses cryptography.x509 first, falling back to asn1crypto for non-conformant
        historical certificates (e.g., negative serial numbers or legacy ASN.1 encodings).
        """
        # Try cryptography.x509 first
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            subject_dn = cert.subject.rfc4514_string()
            
            # Use timezone-aware UTC dates
            valid_from = getattr(cert, "not_valid_before_utc", None)
            if valid_from is None:
                valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
                
            valid_until = getattr(cert, "not_valid_after_utc", None)
            if valid_until is None:
                valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)
                
            return subject_dn, valid_from, valid_until
        except Exception as e_crypto:
            logger.debug("cryptography parser failed (%s), trying asn1crypto fallback", e_crypto)

        # Fallback to asn1crypto
        try:
            asn1_cert = asn1_x509.Certificate.load(der_bytes)
            subject_dn = asn1_cert.subject.human_friendly
            valid_from = asn1_cert.not_valid_before
            if valid_from and valid_from.tzinfo is None:
                valid_from = valid_from.replace(tzinfo=timezone.utc)
            valid_until = asn1_cert.not_valid_after
            if valid_until and valid_until.tzinfo is None:
                valid_until = valid_until.replace(tzinfo=timezone.utc)
            return subject_dn, valid_from, valid_until
        except Exception as e_asn1:
            logger.warning("Failed to parse X.509 certificate metadata: %s", e_asn1)
            return "UNKNOWN_SUBJECT", None, None


# ---------------------------------------------------------------------------
# certdata.txt File Parser
# ---------------------------------------------------------------------------
class CertdataParser:
    """Parses Mozilla NSS certdata.txt contents into structured objects."""

    _LABEL_RE = re.compile(r'CKA_LABEL\s+UTF8\s+"([^"]+)"')
    _OCTAL_BLOCK_RE = re.compile(r"MULTILINE_OCTAL\n(.*?)\nEND", re.DOTALL)
    _VALUE_BLOCK_RE = re.compile(r"CKA_VALUE\s+MULTILINE_OCTAL\n(.*?)\nEND", re.DOTALL)
    _SERIAL_BLOCK_RE = re.compile(r"CKA_SERIAL_NUMBER\s+MULTILINE_OCTAL\n(.*?)\nEND", re.DOTALL)

    def __init__(self, content: str):
        self.content = content

    def parse(
        self,
        snapshot_date: date,
        commit_hash: str,
    ) -> List[CertificateRecord]:
        """
        Parses all certificate objects and resolves their corresponding trust records.
        """
        raw_objects = re.split(r"\n(?=CKA_CLASS\s+)", self.content)

        cert_entries = []
        # Trust maps: by (label, serial_hex) and by label
        trust_map_by_key: Dict[Tuple[str, str], List[str]] = {}
        trust_map_by_label: Dict[str, List[str]] = {}

        for raw_obj in raw_objects:
            if "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE" in raw_obj:
                label_m = self._LABEL_RE.search(raw_obj)
                label = label_m.group(1) if label_m else ""

                val_m = self._VALUE_BLOCK_RE.search(raw_obj)
                if not val_m:
                    continue

                der_bytes = OctalDecoder.decode(val_m.group(1))
                sha256_hex = hashlib.sha256(der_bytes).hexdigest().lower()

                serial_m = self._SERIAL_BLOCK_RE.search(raw_obj)
                serial_hex = OctalDecoder.decode(serial_m.group(1)).hex() if serial_m else ""

                cert_entries.append({
                    "label": label,
                    "serial_hex": serial_hex,
                    "der_bytes": der_bytes,
                    "sha256_fingerprint": sha256_hex,
                })

            elif "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST" in raw_obj:
                label_m = self._LABEL_RE.search(raw_obj)
                label = label_m.group(1) if label_m else ""

                serial_m = self._SERIAL_BLOCK_RE.search(raw_obj)
                serial_hex = OctalDecoder.decode(serial_m.group(1)).hex() if serial_m else ""

                active_trusts = []
                for attr, trust_bit in TRUST_FLAG_MAP.items():
                    pattern = rf"{attr}\s+CK_TRUST\s+{TRUSTED_VAL}"
                    if re.search(pattern, raw_obj):
                        active_trusts.append(trust_bit)

                if label:
                    trust_map_by_key[(label, serial_hex)] = active_trusts
                    trust_map_by_label[label] = active_trusts

        # Build conformed CertificateRecords
        records: List[CertificateRecord] = []
        for c in cert_entries:
            label = c["label"]
            serial_hex = c["serial_hex"]
            der_bytes = c["der_bytes"]
            sha256_fingerprint = c["sha256_fingerprint"]

            # Resolve trust bits (exact (label, serial) match or label match)
            if (label, serial_hex) in trust_map_by_key:
                trust_list = trust_map_by_key[(label, serial_hex)]
            elif label in trust_map_by_label:
                trust_list = trust_map_by_label[label]
            else:
                trust_list = []

            trust_bits = ",".join(sorted(trust_list))

            # Extract Subject DN & validity dates
            subject_dn, valid_from, valid_until = X509MetadataExtractor.extract_metadata(der_bytes)

            record = CertificateRecord(
                vendor=VENDOR_NAME,
                snapshot_date=snapshot_date,
                sha256_fingerprint=sha256_fingerprint,
                subject_dn=subject_dn,
                valid_from=valid_from,
                valid_until=valid_until,
                trust_bits=trust_bits,
                data_source_type=DATA_SOURCE_TYPE,
                provenance_url_or_hash=commit_hash,
            )
            records.append(record)

        return records


# ---------------------------------------------------------------------------
# Git History Sampler & Repository Manager
# ---------------------------------------------------------------------------
class MozillaNSSRepositoryManager:
    """Manages cloning, caching, and tree-traversal of the NSS Git repository."""

    def __init__(
        self,
        repo_url: str = DEFAULT_REPO_URL,
        repo_path: Optional[str | Path] = None,
        temp_dir: Optional[str | Path] = None,
    ):
        self.repo_url = repo_url
        self.repo_path = Path(repo_path) if repo_path else None
        self.temp_dir = Path(temp_dir) if temp_dir else None
        self._temp_dir_obj: Optional[tempfile.TemporaryDirectory] = None
        self.repo: Optional[git.Repo] = None

    def acquire_repository(self) -> git.Repo:
        """
        Provides access to the Git repository. If repo_path is provided,
        uses that path. Otherwise clones repo_url into a temporary directory.
        """
        if self.repo_path and self.repo_path.exists():
            logger.info("Using existing local repository at: %s", self.repo_path)
            self.repo = git.Repo(self.repo_path)
            return self.repo

        # Allocate temporary directory for clone
        if self.temp_dir:
            target_dir = self.temp_dir
            target_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._temp_dir_obj = tempfile.TemporaryDirectory(prefix="mozilla_nss_")
            target_dir = Path(self._temp_dir_obj.name)

        logger.info(
            "Cloning Mozilla NSS repository from %s into temporary folder: %s ...",
            self.repo_url,
            target_dir,
        )
        # Use a bare clone to optimize network transfer and disk utilization
        self.repo = git.Repo.clone_from(
            url=self.repo_url,
            to_path=target_dir,
            bare=True,
        )
        logger.info("Repository clone completed successfully.")
        return self.repo

    def cleanup(self) -> None:
        """Cleans up any allocated temporary directory."""
        if self.repo is not None:
            try:
                self.repo.close()
            except Exception:
                pass
            self.repo = None

        if self._temp_dir_obj:
            logger.info("Cleaning up temporary repository directory: %s", self._temp_dir_obj.name)
            try:
                self._temp_dir_obj.cleanup()
            except Exception as e:
                logger.warning("Failed to clean up temporary directory: %s", e)
            self._temp_dir_obj = None

    def get_certdata_commits(self, start_year: int = DEFAULT_START_YEAR) -> List[git.Commit]:
        """
        Retrieves all commits that modified certdata.txt since start_year,
        sorted chronologically.
        """
        if not self.repo:
            raise RuntimeError("Repository has not been initialized. Call acquire_repository() first.")

        logger.info("Querying Git history for certdata.txt revisions...")
        commits = list(self.repo.iter_commits(paths=CERTDATA_PATHS))
        
        # Filter commits >= start_year and sort chronologically
        filtered = [
            c for c in commits
            if c.committed_datetime.year >= start_year
        ]
        filtered.sort(key=lambda c: c.committed_datetime)
        logger.info(
            "Found %d commits modifying certdata.txt since %d (out of %d total commits).",
            len(filtered),
            start_year,
            len(commits),
        )
        return filtered

    @staticmethod
    def sample_commits(
        commits: Sequence[git.Commit],
        strategy: str = "quarterly",
    ) -> List[git.Commit]:
        """
        Samples commits based on the selected cadence:
        - 'quarterly': picks the latest commit in each quarter.
        - 'yearly': picks the latest commit in each year.
        - 'all': returns all commits without subsampling.
        """
        if strategy == "all":
            return list(commits)

        grouped = defaultdict(list)
        for c in commits:
            dt = c.committed_datetime
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

    def read_certdata_content(self, commit: git.Commit) -> Optional[str]:
        """
        Reads certdata.txt content directly from the commit tree object
        without checking out working tree files.
        """
        for rel_path in CERTDATA_PATHS:
            try:
                tree_node = commit.tree
                for part in rel_path.split("/"):
                    tree_node = tree_node[part]
                blob = tree_node
                content_bytes = blob.data_stream.read()
                return content_bytes.decode("utf-8", errors="ignore")
            except (KeyError, IndexError):
                continue
        return None


# ---------------------------------------------------------------------------
# Pipeline Orchestration
# ---------------------------------------------------------------------------
def run_extraction(
    repo_url: str = DEFAULT_REPO_URL,
    repo_path: Optional[str | Path] = None,
    temp_dir: Optional[str | Path] = None,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    sampling: str = "quarterly",
    start_year: int = DEFAULT_START_YEAR,
    keep_temp: bool = False,
) -> pd.DataFrame:
    """
    Main extraction routine:
    1. Acquires repository.
    2. Identifies and samples commits.
    3. Parses certdata.txt for each snapshot.
    4. Saves results as Parquet.
    """
    manager = MozillaNSSRepositoryManager(
        repo_url=repo_url,
        repo_path=repo_path,
        temp_dir=temp_dir,
    )

    all_records: List[CertificateRecord] = []

    try:
        manager.acquire_repository()
        candidate_commits = manager.get_certdata_commits(start_year=start_year)
        selected_commits = manager.sample_commits(candidate_commits, strategy=sampling)

        total_commits = len(selected_commits)
        logger.info("Beginning extraction for %d commit snapshots...", total_commits)

        for idx, commit in enumerate(selected_commits, start=1):
            commit_dt = commit.committed_datetime
            snapshot_date = commit_dt.date()
            commit_hash = commit.hexsha

            logger.info(
                "[%d/%d] Processing snapshot %s (Commit: %s, Date: %s)...",
                idx,
                total_commits,
                snapshot_date.isoformat(),
                commit_hash[:10],
                commit_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            )

            content = manager.read_certdata_content(commit)
            if not content:
                logger.warning(
                    "Could not find certdata.txt in tree for commit %s. Skipping.",
                    commit_hash[:10],
                )
                continue

            parser = CertdataParser(content)
            records = parser.parse(
                snapshot_date=snapshot_date,
                commit_hash=commit_hash,
            )

            logger.info(
                "  -> Extracted %d certificates (e.g. trusted serverAuth: %d)",
                len(records),
                sum(1 for r in records if "serverAuth" in r.trust_bits),
            )
            all_records.extend(records)

    finally:
        if not keep_temp and not repo_path:
            manager.cleanup()

    logger.info("Total certificate snapshot records extracted: %d", len(all_records))

    # Convert records to Pandas DataFrame
    df = pd.DataFrame([vars(r) for r in all_records])

    if df.empty:
        logger.warning("No records extracted. Parquet file will not be created.")
        return df

    # Enforce exact column typing according to SCHEMA.md
    df["snapshot_date"] = pd.to_datetime(df["snapshot_date"]).dt.date
    df["valid_from"] = pd.to_datetime(df["valid_from"], utc=True)
    df["valid_until"] = pd.to_datetime(df["valid_until"], utc=True)

    # Reorder columns to match SCHEMA.md exactly
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

    # Ensure output directory exists and save to Parquet
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, engine="pyarrow", index=False)
    logger.info("Successfully saved dataset to: %s", output_path.resolve())
    logger.info("Dataset shape: %d rows x %d columns", df.shape[0], df.shape[1])

    return df


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def parse_arguments() -> argparse.Namespace:
    """Parse CLI options for the extractor."""
    parser = argparse.ArgumentParser(
        description="Extract historical Mozilla NSS root store snapshots to Parquet."
    )
    parser.add_argument(
        "--repo-url",
        default=DEFAULT_REPO_URL,
        help=f"Remote URL of Mozilla NSS Git repository (default: {DEFAULT_REPO_URL}).",
    )
    parser.add_argument(
        "--repo-path",
        default=None,
        help="Path to an existing local NSS repository to bypass cloning.",
    )
    parser.add_argument(
        "--temp-dir",
        default=None,
        help="Custom directory path to use for cloning.",
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Target Parquet output file path (default: {DEFAULT_OUTPUT_PATH}).",
    )
    parser.add_argument(
        "--sampling",
        choices=["quarterly", "yearly", "all"],
        default="quarterly",
        help="Snapshot sampling frequency: quarterly, yearly, or all (default: quarterly).",
    )
    parser.add_argument(
        "--start-year",
        type=int,
        default=DEFAULT_START_YEAR,
        help=f"Historical starting year for commits (default: {DEFAULT_START_YEAR}).",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Retain cloned repository temporary directory after completion.",
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

    run_extraction(
        repo_url=args.repo_url,
        repo_path=args.repo_path,
        temp_dir=args.temp_dir,
        output_path=args.output_path,
        sampling=args.sampling,
        start_year=args.start_year,
        keep_temp=args.keep_temp,
    )


if __name__ == "__main__":
    main()
