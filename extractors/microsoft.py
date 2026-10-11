#!/usr/bin/env python3
"""
Microsoft Root Store (CTL / authroot.stl) Extractor
===================================================

This module extracts historical snapshots of Microsoft's Trusted Root
Certification Authorities list from binary Certificate Trust Lists (CTL).

Microsoft distributes its root trust store dynamically via Windows Update
in the form of `authrootstl.cab`, which contains a signed PKCS#7 / CTL
file named `authroot.stl`.

Key Workflow:
1. Retrieval via Internet Archive Wayback Machine:
   Queries the CDX API for historical snapshots of Microsoft's official
   Windows Update CAB URL:
   `http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab`
2. Binary Extraction:
   Downloads CAB archives and unpacks `authroot.stl` using `cabarchive`
   (with subprocess fallback to `expand` on Windows / `cabextract` on Unix).
   Implements on-disk caching to skip repeat downloads and CAB unpacks.
3. ASN.1 / PKCS#7 & CTL Parsing:
   - Uses `asn1crypto.cms.ContentInfo` to parse the SignedData envelope.
   - Decodes the encapsulated CTL (`1.3.6.1.4.1.311.10.1`) structure.
   - Iterates through `trustedSubjects` to extract:
     * Primary `subject_identifier` (historically SHA-1 thumbprint).
     * Extended attribute `1.3.6.1.4.1.311.10.11.98` (32-byte SHA-256 hash).
     * Extended attribute `1.3.6.1.4.1.311.10.11.11` (UTF-16LE Friendly Name).
     * Extended attribute `1.3.6.1.4.1.311.10.11.9` (EKUs / Trust Bits).
4. Schema Conformance & Storage:
   Maps data to `SCHEMA.md` and writes to `data/raw/microsoft_history.parquet`.

Author: Data Engineering & Security Research Team
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
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
from asn1crypto import cms, core

try:
    import cabarchive
    HAS_CABARCHIVE = True
except ImportError:
    HAS_CABARCHIVE = False

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("extractors.microsoft")

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
DEFAULT_CAB_URL = (
    "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
)
WAYBACK_CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_REPLAY_URL_TEMPLATE = "https://web.archive.org/web/{timestamp}id_/{original}"
WAYBACK_VIEW_URL_TEMPLATE = "https://web.archive.org/web/{timestamp}/{original}"

DEFAULT_OUTPUT_PATH = Path("data/raw/microsoft_history.parquet")
DEFAULT_CACHE_DIR = Path("data/raw/.microsoft_cache")
VENDOR_NAME = "microsoft"
DATA_SOURCE_TYPE = "stl_binary"
DEFAULT_SLEEP_SECONDS = 3.0

# Standard EKU OID mapping to Web PKI trust purposes
EKU_OID_MAP = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.4.1.311.10.3.3": "serverGatedCrypto",
    "1.3.6.1.4.1.311.10.3.1": "trustListSigning",
}

# Pre-indexed annual anchor snapshots from Wayback Machine (used for resilience)
FALLBACK_SNAPSHOT_TIMESTAMPS = [
    "20110718062945",  # 2011-07-18
    "20120114174127",  # 2012-01-14
    "20130327191002",  # 2013-03-27
    "20131205121416",  # 2013-12-05 (2014 anchor)
    "20150106162530",  # 2015-01-06
    "20151106121053",  # 2015-11-06 (2016 anchor)
    "20161202020617",  # 2016-12-02 (2017 anchor)
    "20180327074438",  # 2018-03-27
    "20190101032201",  # 2019-01-01
    "20191108083049",  # 2019-11-08 (2020 anchor)
    "20210118185348",  # 2021-01-18
    "20220103190520",  # 2022-01-03
    "20230221021633",  # 2023-02-21
    "20240129100813",  # 2024-01-29
    "20250108134232",  # 2025-01-08
]


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class WaybackSnapshotMetadata:
    """Metadata for an archived snapshot of authrootstl.cab."""

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
        """Constructs raw identity Wayback replay URL for binary download."""
        return WAYBACK_REPLAY_URL_TEMPLATE.format(
            timestamp=self.timestamp,
            original=self.original_url,
        )

    @property
    def provenance_url(self) -> str:
        """Constructs human-viewable Wayback replay URL for provenance tracking."""
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
# TLV Helper for DER Decoding
# ---------------------------------------------------------------------------
def decode_der_tlv(data: bytes, offset: int = 0) -> Tuple[int, int, bytes, int]:
    """
    Decodes an ASN.1 DER Tag-Length-Value (TLV) element from raw bytes.
    Returns: (tag, length, value_bytes, next_offset)
    """
    if offset >= len(data):
        raise ValueError("Offset exceeds data length")

    tag = data[offset]
    offset += 1
    len_byte = data[offset]
    offset += 1

    if len_byte & 0x80:
        num_octets = len_byte & 0x7F
        length = int.from_bytes(data[offset : offset + num_octets], "big")
        offset += num_octets
    else:
        length = len_byte

    val = data[offset : offset + length]
    return tag, length, val, offset + length


# ---------------------------------------------------------------------------
# ASN.1 CTL Parser
# ---------------------------------------------------------------------------
class MicrosoftCTLParser:
    """
    Parses a signed Microsoft Certificate Trust List (authroot.stl).
    Extracts Root CA fingerprints, friendly names, and EKU trust purposes.
    """

    @classmethod
    def parse_stl(
        cls,
        stl_bytes: bytes,
        snapshot_date: date,
        provenance_url: str,
    ) -> List[CertificateRecord]:
        """
        Parses PKCS#7 envelope and encapsulated CTL entries.
        """
        try:
            info = cms.ContentInfo.load(stl_bytes)
            encap = info["content"]["encap_content_info"]
            content_type = encap["content_type"].native
            if content_type != "1.3.6.1.4.1.311.10.1":
                logger.warning("Unexpected encapsulated content type: %s", content_type)

            raw_ctl = encap["content"].untag().contents
        except Exception as e:
            logger.error("Failed to parse CMS ContentInfo from STL: %s", e)
            return []

        # Traverse top-level CTL TLVs:
        # TLV 0: subjectUsage (Sequence)
        # TLV 1: listIdentifier or sequenceNumber (Integer)
        # TLV 2: ctlIssueTime (UTCTime or Choice)
        # TLV 3: subjectAlgorithm (Sequence)
        # TLV 4: trustedSubjects (Sequence of TrustedSubject)
        try:
            off = 0
            top_tlvs = []
            while off < len(raw_ctl):
                tag, length, val, off = decode_der_tlv(raw_ctl, off)
                top_tlvs.append((tag, val))

            if len(top_tlvs) < 5:
                logger.error("CTL structure has fewer than 5 TLVs (%d found).", len(top_tlvs))
                return []

            # Locate the trustedSubjects sequence (typically TLV index 4, tag 0x30 / 48 or 0x10 / 16)
            subjects_data = None
            for idx in range(4, len(top_tlvs)):
                if top_tlvs[idx][0] in (16, 48, 0x30):  # SEQUENCE tag
                    subjects_data = top_tlvs[idx][1]
                    break

            if subjects_data is None:
                logger.error("Could not find trustedSubjects sequence in CTL.")
                return []

        except Exception as e:
            logger.error("Error traversing top-level CTL structure: %s", e)
            return []

        # Parse each TrustedSubject entry
        records: List[CertificateRecord] = []
        sub_off = 0

        while sub_off < len(subjects_data):
            try:
                _, _, s_val, sub_off = decode_der_tlv(subjects_data, sub_off)
                
                # Each subject:
                # 1. subject_identifier (OctetString)
                # 2. attributes (Set of Attribute)
                p_off = 0
                _, _, id_val, p_off = decode_der_tlv(s_val, p_off)
                sha1_thumbprint = id_val.hex().lower()
                sha256_hash: Optional[str] = None
                friendly_name: Optional[str] = None
                ekus: List[str] = []

                if p_off < len(s_val):
                    _, _, a_val, _ = decode_der_tlv(s_val, p_off)
                    attr_off = 0
                    while attr_off < len(a_val):
                        _, _, single_attr, attr_off = decode_der_tlv(a_val, attr_off)
                        at_off = 0
                        _, _, oid_bytes, at_off = decode_der_tlv(single_attr, at_off)
                        
                        # Parse OID
                        oid = core.ObjectIdentifier.load(
                            b"\x06" + bytes([len(oid_bytes)]) + oid_bytes
                        ).native
                        
                        _, _, set_bytes, _ = decode_der_tlv(single_attr, at_off)
                        _, _, val_payload, _ = decode_der_tlv(set_bytes, 0)

                        # OID 1.3.6.1.4.1.311.10.11.98: SHA-256 Hash property
                        if oid == "1.3.6.1.4.1.311.10.11.98":
                            if len(val_payload) == 32:
                                sha256_hash = val_payload.hex().lower()
                            elif len(val_payload) > 32 and val_payload[0] == 0x04:
                                _, _, inner_h, _ = decode_der_tlv(val_payload, 0)
                                sha256_hash = inner_h.hex().lower()

                        # OID 1.3.6.1.4.1.311.10.11.11: Friendly Name property (UTF-16LE)
                        elif oid == "1.3.6.1.4.1.311.10.11.11":
                            try:
                                friendly_name = val_payload.decode("utf-16le").rstrip("\x00")
                            except Exception:
                                pass

                        # OID 1.3.6.1.4.1.311.10.11.9: Enhanced Key Usage (EKU) Sequence
                        elif oid == "1.3.6.1.4.1.311.10.11.9":
                            if val_payload and val_payload[0] in (16, 48, 0x30):
                                _, _, seq_payload, _ = decode_der_tlv(val_payload, 0)
                                v_off = 0
                                while v_off < len(seq_payload):
                                    _, _, eku_bytes, v_off = decode_der_tlv(seq_payload, v_off)
                                    eku_oid = core.ObjectIdentifier.load(
                                        b"\x06" + bytes([len(eku_bytes)]) + eku_bytes
                                    ).native
                                    mapped_eku = EKU_OID_MAP.get(eku_oid, eku_oid)
                                    if mapped_eku not in ekus:
                                        ekus.append(mapped_eku)

                # Prioritize SHA-256; fallback to SHA-1 thumbprint if not available
                fingerprint = sha256_hash if sha256_hash else sha1_thumbprint
                trust_bits = ",".join(sorted(ekus)) if ekus else "serverAuth"

                record = CertificateRecord(
                    vendor=VENDOR_NAME,
                    snapshot_date=snapshot_date,
                    sha256_fingerprint=fingerprint,
                    subject_dn=friendly_name,
                    valid_from=None,
                    valid_until=None,
                    trust_bits=trust_bits,
                    data_source_type=DATA_SOURCE_TYPE,
                    provenance_url_or_hash=provenance_url,
                )
                records.append(record)

            except Exception as e:
                logger.debug("Error parsing single TrustedSubject: %s", e)
                continue

        return records


# ---------------------------------------------------------------------------
# CAB Archive Unpacker
# ---------------------------------------------------------------------------
class CabExtractor:
    """
    Unpacks authroot.stl from authrootstl.cab using cabarchive or native CLI tools.
    """

    @classmethod
    def extract_stl_bytes(cls, cab_bytes: bytes) -> Optional[bytes]:
        """
        Extracts authroot.stl content bytes from raw CAB bytes.
        """
        # Primary: pure-Python cabarchive
        if HAS_CABARCHIVE:
            try:
                cab = cabarchive.CabArchive(cab_bytes)
                for name in ["authroot.stl", "AUTHROOT.STL"]:
                    if name in cab:
                        return cab[name].buf
                # If exact name not found, search case-insensitively
                for name, item in cab.items():
                    if name.lower().endswith(".stl"):
                        return item.buf
            except Exception as e:
                logger.debug("cabarchive in-memory extraction failed (%s), trying CLI fallback", e)

        # Subprocess fallback: write temp CAB and extract via system utility
        with tempfile.TemporaryDirectory(prefix="ms_cab_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            cab_file = tmp_path / "temp.cab"
            cab_file.write_bytes(cab_bytes)
            dest_stl = tmp_path / "authroot.stl"

            # Windows native: expand.exe
            if sys.platform == "win32":
                try:
                    subprocess.run(
                        ["expand", str(cab_file), str(dest_stl)],
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    if dest_stl.exists():
                        return dest_stl.read_bytes()
                except Exception as e:
                    logger.debug("expand.exe fallback failed: %s", e)

            # Unix: cabextract
            cabextract_bin = shutil.which("cabextract")
            if cabextract_bin:
                try:
                    subprocess.run(
                        [cabextract_bin, "-d", str(tmp_path), str(cab_file)],
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    for f in tmp_path.glob("*.stl"):
                        return f.read_bytes()
                except Exception as e:
                    logger.debug("cabextract fallback failed: %s", e)

        logger.error("Failed to extract authroot.stl from CAB archive.")
        return None


# ---------------------------------------------------------------------------
# Wayback Client & Caching Manager
# ---------------------------------------------------------------------------
class MicrosoftWaybackClient:
    """
    Manages CDX query discovery and retrieval of historical authrootstl.cab files.
    """

    def __init__(
        self,
        cab_url: str = DEFAULT_CAB_URL,
        cache_dir: Optional[Path] = DEFAULT_CACHE_DIR,
        sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
        max_retries: int = 3,
    ):
        self.cab_url = cab_url
        self.cache_dir = cache_dir
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.sleep_seconds = sleep_seconds
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebPKI-Research-Bot/1.0 (academic research; root store analysis; python-requests)",
        })

    def fetch_snapshot_list(self) -> List[WaybackSnapshotMetadata]:
        """
        Discovers historical snapshots from Wayback CDX API.
        Falls back to curated anchor timestamps if CDX is rate-limited.
        """
        cache_file = self.cache_dir / "cdx_snapshots.json" if self.cache_dir else None

        if cache_file and cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                logger.info("Loaded %d snapshots from CDX cache.", len(cached_data))
                return [WaybackSnapshotMetadata(**r) for r in cached_data]
            except Exception as e:
                logger.warning("Could not read CDX cache: %s", e)

        logger.info("Querying Wayback CDX API for: %s ...", self.cab_url)
        params = {
            "url": self.cab_url,
            "output": "json",
            "fl": "timestamp,original,statuscode",
            "filter": "statuscode:200",
            "limit": 50,
        }

        snapshots: List[WaybackSnapshotMetadata] = []
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(WAYBACK_CDX_API_URL, params=params, timeout=25)
                if resp.status_code == 200:
                    data = resp.json()
                    if len(data) > 1:
                        for row in data[1:]:
                            if len(row) >= 2 and len(row[0]) >= 8:
                                snapshots.append(
                                    WaybackSnapshotMetadata(
                                        timestamp=row[0],
                                        original_url=row[1],
                                        status_code=row[2] if len(row) > 2 else "200",
                                    )
                                )
                    logger.info("CDX API returned %d snapshots.", len(snapshots))
                    break
                else:
                    logger.warning("CDX API returned HTTP %d on attempt %d", resp.status_code, attempt)
                    time.sleep(3 * attempt)
            except requests.RequestException as e:
                logger.warning("CDX attempt %d failed: %s", attempt, e)
                time.sleep(3 * attempt)

        # If CDX is temporarily down/rate-limited, seed with curated annual anchors
        if not snapshots:
            logger.info("CDX unavailable; using %d pre-indexed annual anchor snapshots.", len(FALLBACK_SNAPSHOT_TIMESTAMPS))
            snapshots = [
                WaybackSnapshotMetadata(
                    timestamp=ts,
                    original_url=self.cab_url,
                    status_code="200",
                )
                for ts in FALLBACK_SNAPSHOT_TIMESTAMPS
            ]

        if cache_file and snapshots:
            try:
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump([vars(s) for s in snapshots], f, indent=2)
            except Exception as e:
                logger.debug("Failed saving CDX cache: %s", e)

        return snapshots

    def get_stl_bytes(self, snapshot: WaybackSnapshotMetadata) -> Optional[bytes]:
        """
        Retrieves authroot.stl bytes for a snapshot.
        Strict caching: if authroot_<timestamp>.stl exists on disk, reads directly
        and skips download and extraction entirely.
        """
        stl_cache = self.cache_dir / f"authroot_{snapshot.timestamp}.stl" if self.cache_dir else None
        cab_cache = self.cache_dir / f"authroot_{snapshot.timestamp}.cab" if self.cache_dir else None

        # 1. Check cached STL file
        if stl_cache and stl_cache.exists():
            logger.debug("Loaded authroot.stl from local cache: %s", stl_cache.name)
            try:
                return stl_cache.read_bytes()
            except Exception as e:
                logger.debug("Failed reading cached STL %s: %s", stl_cache, e)

        # 2. Check cached CAB file
        cab_bytes: Optional[bytes] = None
        if cab_cache and cab_cache.exists():
            try:
                cab_bytes = cab_cache.read_bytes()
            except Exception as e:
                logger.debug("Failed reading cached CAB: %s", e)

        # 3. Download CAB if not cached
        if not cab_bytes:
            replay_url = snapshot.replay_url
            logger.info("Downloading CAB archive from Wayback: %s ...", replay_url)
            for attempt in range(1, self.max_retries + 1):
                try:
                    resp = self.session.get(replay_url, timeout=30)
                    if resp.status_code == 200:
                        cab_bytes = resp.content
                        if cab_cache:
                            try:
                                cab_cache.write_bytes(cab_bytes)
                            except Exception as e:
                                logger.debug("Failed saving CAB cache: %s", e)
                        break
                    elif resp.status_code in (429, 503):
                        wait = max(15, 12 * attempt)
                        logger.warning("Wayback rate-limited (HTTP %d). Backing off %ds...", resp.status_code, wait)
                        time.sleep(wait)
                    else:
                        logger.warning("Wayback returned HTTP %d for %s", resp.status_code, replay_url)
                        break
                except requests.RequestException as e:
                    logger.warning("Download attempt %d failed: %s", attempt, e)
                    if attempt < self.max_retries:
                        time.sleep(max(15, 10 * attempt))

            # Enforce polite rate limiting between HTTP requests
            time.sleep(self.sleep_seconds)

        if not cab_bytes:
            logger.warning("Could not obtain CAB bytes for snapshot %s.", snapshot.timestamp)
            return None

        # Extract STL
        stl_bytes = CabExtractor.extract_stl_bytes(cab_bytes)
        if stl_bytes and stl_cache:
            try:
                stl_cache.write_bytes(stl_bytes)
                logger.debug("Saved extracted STL to cache: %s", stl_cache.name)
            except Exception as e:
                logger.debug("Failed saving STL cache: %s", e)

        return stl_bytes

    def get_live_stl_bytes(self) -> Optional[Tuple[bytes, date, str]]:
        """
        Retrieves the current live authrootstl.cab directly from Microsoft's Windows Update CDN.
        """
        today_iso = date.today().isoformat()
        cache_stl = self.cache_dir / f"authroot_live_{today_iso}.stl" if self.cache_dir else None

        if cache_stl and cache_stl.exists():
            logger.info("Loaded live authroot.stl from local cache: %s", cache_stl.name)
            return cache_stl.read_bytes(), date.today(), self.cab_url

        logger.info("Fetching current live CAB from Microsoft Windows Update CDN: %s ...", self.cab_url)
        try:
            resp = self.session.get(self.cab_url, timeout=25)
            if resp.status_code == 200:
                stl_bytes = CabExtractor.extract_stl_bytes(resp.content)
                if stl_bytes and cache_stl:
                    cache_stl.write_bytes(stl_bytes)
                return stl_bytes, date.today(), self.cab_url
            else:
                logger.warning("Live CAB request returned HTTP %d", resp.status_code)
        except Exception as e:
            logger.warning("Failed downloading live CAB: %s", e)
        return None


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
        step = len(selected) / max_count
        selected = [selected[int(i * step)] for i in range(max_count)]

    return selected


# ---------------------------------------------------------------------------
# Pipeline Orchestration
# ---------------------------------------------------------------------------
def run_extraction(
    cab_url: str = DEFAULT_CAB_URL,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    cache_dir: Optional[Path] = DEFAULT_CACHE_DIR,
    sampling: str = "yearly",
    max_snapshots: Optional[int] = None,
    sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
    include_live: bool = True,
) -> pd.DataFrame:
    """
    Executes the Microsoft CTL extraction pipeline:
    1. Queries CDX API for CAB snapshots.
    2. Subsamples snapshots (yearly, quarterly, etc.).
    3. Downloads and extracts authroot.stl with strict on-disk caching.
    4. Parses PKCS#7 / CTL binary entries with asn1crypto.
    5. Saves conformed records to Parquet adhering to SCHEMA.md.
    """
    client = MicrosoftWaybackClient(
        cab_url=cab_url,
        cache_dir=cache_dir,
        sleep_seconds=sleep_seconds,
    )

    snapshots = client.fetch_snapshot_list()
    if not snapshots:
        logger.error("No snapshots found for Microsoft CTL. Aborting.")
        return pd.DataFrame()

    selected_snaps = sample_snapshots(
        snapshots,
        strategy=sampling,
        max_count=max_snapshots,
    )
    total_snaps = len(selected_snaps)
    logger.info("Selected %d snapshots using '%s' strategy for extraction.", total_snaps, sampling)

    all_records: List[CertificateRecord] = []

    for idx, snapshot in enumerate(selected_snaps, start=1):
        snapshot_date = snapshot.snapshot_date
        logger.info(
            "[%d/%d] Processing snapshot %s (%s)...",
            idx,
            total_snaps,
            snapshot_date.isoformat(),
            snapshot.timestamp,
        )

        stl_bytes = client.get_stl_bytes(snapshot)
        if not stl_bytes:
            logger.warning("Failed to obtain authroot.stl for snapshot %s. Skipping.", snapshot.timestamp)
            continue

        records = MicrosoftCTLParser.parse_stl(
            stl_bytes=stl_bytes,
            snapshot_date=snapshot_date,
            provenance_url=snapshot.provenance_url,
        )

        logger.info(
            "  -> Extracted %d root certificates (e.g. serverAuth: %d)",
            len(records),
            sum(1 for r in records if "serverAuth" in r.trust_bits),
        )
        all_records.extend(records)

    # Optional: also extract current live Microsoft root store snapshot
    if include_live:
        live_res = client.get_live_stl_bytes()
        if live_res:
            live_stl, live_date, live_url = live_res
            live_records = MicrosoftCTLParser.parse_stl(
                stl_bytes=live_stl,
                snapshot_date=live_date,
                provenance_url=live_url,
            )
            logger.info(
                "Extracted %d root certificates from current live Microsoft CDN snapshot (%s).",
                len(live_records),
                live_date.isoformat(),
            )
            all_records.extend(live_records)

    logger.info("Total certificate snapshot records extracted for Microsoft: %d", len(all_records))

    new_df = pd.DataFrame([vars(r) for r in all_records])

    # Incremental checkpointing: merge with existing parquet dataset if present
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

    # Deduplicate within same snapshot if multiple entries or repeated runs occurred
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
    """Parse CLI options for the Microsoft CTL extractor."""
    parser = argparse.ArgumentParser(
        description="Extract historical Microsoft Root Store CTL snapshots to Parquet."
    )
    parser.add_argument(
        "--cab-url",
        default=DEFAULT_CAB_URL,
        help=f"Target Microsoft Windows Update CAB URL (default: {DEFAULT_CAB_URL}).",
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
        help=f"Directory for caching downloaded CAB and STL files (default: {DEFAULT_CACHE_DIR}).",
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
        help="Maximum snapshots to process.",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=DEFAULT_SLEEP_SECONDS,
        help=f"Pause duration between live HTTP requests in seconds (default: {DEFAULT_SLEEP_SECONDS}).",
    )
    parser.add_argument(
        "--no-live",
        action="store_true",
        help="Skip extracting the current live Microsoft root store from Windows Update CDN.",
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
        cab_url=args.cab_url,
        output_path=args.output_path,
        cache_dir=cache_dir,
        sampling=args.sampling,
        max_snapshots=args.max_snapshots,
        sleep_seconds=args.sleep_seconds,
        include_live=not args.no_live,
    )


if __name__ == "__main__":
    main()
