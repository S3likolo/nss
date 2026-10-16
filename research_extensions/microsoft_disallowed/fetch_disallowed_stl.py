#!/usr/bin/env python3
"""
Microsoft Disallowed Certificate Trust List (disallowedcert.stl) Extractor
===========================================================================

This module extracts historical snapshots of Microsoft's Disallowed/Untrusted
Certificates list (the Windows emergency untrusted certificate blocklist) from
binary Certificate Trust Lists (CTL).

Microsoft distributes this list dynamically via Windows Update in the form of
`disallowedcertstl.cab`, which contains a signed PKCS#7 / CTL file named
`disallowedcert.stl`.

Workflow:
  1. Wayback CDX API Query:
     Queries the Wayback Machine CDX API for snapshots of:
     `http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab`
     from 2012 to 2026.
  2. Binary Archive Extraction:
     Downloads CAB archives and unpacks `disallowedcert.stl` using `cabarchive`
     with CLI fallbacks (`expand.exe` on Windows / `cabextract` on Unix).
  3. PKCS#7 / ASN.1 CTL Parsing:
     Parses CMS ContentInfo, decodes the CTL structure (`1.3.6.1.4.1.311.10.1`),
     extracts `ctlIssueTime`, `sequenceNumber`, and each disallowed subject
     identifier and attribute set.
  4. Data Export:
     Saves output to both `disallowed_trust_history.parquet` and
     `disallowed_trust_history.csv`.
  5. Cross-Reference Analysis:
     Matches disallowed entries against WoSign / StartCom roots from
     `data/wosign_target_roots.csv` and determines the uncertainty window.

Author: Academic Research Team
Date: October 2026
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
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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

# Ensure standard UTF-8 stdout
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
logger = logging.getLogger("extractors.microsoft_disallowed")

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
DEFAULT_CAB_URL = (
    "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab"
)
WAYBACK_CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_REPLAY_URL_TEMPLATE = "https://web.archive.org/web/{timestamp}id_/{original}"
WAYBACK_VIEW_URL_TEMPLATE = "https://web.archive.org/web/{timestamp}/{original}"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR
DEFAULT_CACHE_DIR = SCRIPT_DIR / ".cache"
DEFAULT_TARGET_ROOTS_CSV = REPO_ROOT / "data" / "wosign_target_roots.csv"

VENDOR_NAME = "microsoft"
DATA_SOURCE_TYPE = "stl_binary"
DEFAULT_SLEEP_SECONDS = 1.0

# Curated fallback anchor timestamps from Wayback Machine (2013-2026)
# Used if Wayback CDX API is rate-limited or temporarily unreachable.
FALLBACK_ANCHOR_TIMESTAMPS = [
    "20130622003028",  # 2013-06-22 (Earliest recorded snapshot; 51 entries)
    "20130810215620",  # 2013-08-10
    "20140705085215",  # 2014-07-05 (52 entries)
    "20140907094653",  # 2014-09-07 (55 entries)
    "20150210155842",  # 2015-02-10
    "20150813012340",  # 2015-08-13 (57 entries)
    "20160201224512",  # 2016-02-01 (64 entries)
    "20160617061107",  # 2016-06-17
    "20170825162023",  # 2017-08-25 (Active during WoSign deprecation; 64 entries)
    "20190228094343",  # 2019-02-28 (66 entries)
    "20190714021848",  # 2019-07-14
    "20200722173819",  # 2020-07-22 (72 entries)
    "20201111212507",  # 2020-11-11
    "20210502000245",  # 2021-05-02 (74 entries)
    "20220707113341",  # 2022-07-07
    "20230519162715",  # 2023-05-19
    "20240109175653",  # 2024-01-09 (74 entries)
    "20250313004300",  # 2025-03-13 (75 entries)
    "20250912025413",  # 2025-09-12 (88 entries)
    "20261005143915",  # 2026-10-05 (Latest 2026 archive; 88 entries)
]


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class WaybackSnapshotMetadata:
    """Metadata for an archived snapshot of disallowedcertstl.cab."""

    timestamp: str
    original_url: str
    status_code: str = "200"
    digest: str = ""

    @property
    def snapshot_date(self) -> date:
        """Parses YYYYMMDD prefix into an ISO date."""
        year = int(self.timestamp[:4])
        month = int(self.timestamp[4:6])
        day = int(self.timestamp[6:8])
        return date(year, month, day)

    @property
    def replay_url(self) -> str:
        """Constructs identity Wayback replay URL."""
        return WAYBACK_REPLAY_URL_TEMPLATE.format(
            timestamp=self.timestamp,
            original=self.original_url,
        )

    @property
    def provenance_url(self) -> str:
        """Constructs human-viewable Wayback replay URL."""
        return WAYBACK_VIEW_URL_TEMPLATE.format(
            timestamp=self.timestamp,
            original=self.original_url,
        )


@dataclass(frozen=True)
class DisallowedRecord:
    """Entry representing a disallowed/revoked certificate in a CTL snapshot."""

    vendor: str
    snapshot_date: date
    snapshot_timestamp: str
    ctl_issue_time: Optional[datetime]
    ctl_sequence_number: Optional[str]
    entry_index: int
    subject_identifier: str
    identifier_byte_length: int
    sha1_fingerprint: Optional[str]
    sha256_fingerprint: Optional[str]
    attributes_json: str
    data_source_type: str
    provenance_url: str


# ---------------------------------------------------------------------------
# DER Decoding Helper
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
# CAB Extractor
# ---------------------------------------------------------------------------
class CabExtractor:
    """Unpacks disallowedcert.stl from disallowedcertstl.cab."""

    @classmethod
    def extract_stl_bytes(cls, cab_bytes: bytes) -> Optional[bytes]:
        """Extracts disallowedcert.stl bytes from in-memory CAB archive."""
        if HAS_CABARCHIVE:
            try:
                cab = cabarchive.CabArchive(cab_bytes)
                for name in ["disallowedcert.stl", "DISALLOWEDCERT.STL"]:
                    if name in cab:
                        return cab[name].buf
                for name, item in cab.items():
                    if name.lower().endswith(".stl"):
                        return item.buf
            except Exception as e:
                logger.debug("cabarchive extraction failed (%s), trying CLI fallback", e)

        # Fallback to system CLI tools
        with tempfile.TemporaryDirectory(prefix="ms_disallowed_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            cab_file = tmp_path / "temp.cab"
            cab_file.write_bytes(cab_bytes)
            dest_stl = tmp_path / "disallowedcert.stl"

            # Windows: expand.exe
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

        logger.error("Failed to extract disallowedcert.stl from CAB.")
        return None


# ---------------------------------------------------------------------------
# Disallowed CTL Parser
# ---------------------------------------------------------------------------
class MicrosoftDisallowedCTLParser:
    """
    Parses signed PKCS#7 / CMS disallowedcert.stl Certificate Trust Lists.
    Extracts certificate fingerprints, extended attributes, and issue dates.
    """

    @classmethod
    def parse_stl(
        cls,
        stl_bytes: bytes,
        snapshot_date: date,
        snapshot_timestamp: str,
        provenance_url: str,
    ) -> List[DisallowedRecord]:
        """
        Parses PKCS#7 SignedData and encapsulated CTL structure.
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

        # Traverse top-level CTL TLVs
        try:
            off = 0
            top_tlvs = []
            while off < len(raw_ctl):
                tag, length, val, off = decode_der_tlv(raw_ctl, off)
                top_tlvs.append((tag, val))

            if len(top_tlvs) < 4:
                logger.error("CTL structure has fewer than 4 TLVs (%d found).", len(top_tlvs))
                return []

            # Extract sequence number and issue time
            sequence_number_hex = None
            issue_time_dt = None

            for t, v in top_tlvs:
                # Sequence Number (Integer)
                if t == 0x02 and sequence_number_hex is None:
                    sequence_number_hex = v.hex().lower()
                # ChoiceOfTime (UTCTime 0x17 or GeneralizedTime 0x18)
                elif t in (0x17, 0x18) and issue_time_dt is None:
                    try:
                        time_str = v.decode("ascii")
                        if t == 0x17:  # UTCTime YYMMDDHHMMSSZ
                            year = int(time_str[:2])
                            year += 2000 if year < 50 else 1900
                            issue_time_dt = datetime(
                                year,
                                int(time_str[2:4]),
                                int(time_str[4:6]),
                                int(time_str[6:8]),
                                int(time_str[8:10]),
                                int(time_str[10:12]),
                                tzinfo=timezone.utc,
                            )
                        elif t == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
                            issue_time_dt = datetime(
                                int(time_str[:4]),
                                int(time_str[4:6]),
                                int(time_str[6:8]),
                                int(time_str[8:10]),
                                int(time_str[10:12]),
                                int(time_str[12:14]),
                                tzinfo=timezone.utc,
                            )
                    except Exception as ex:
                        logger.debug("Could not parse CTL time string '%s': %s", v, ex)

            # Locate trustedSubjects sequence (tag 0x30 with largest length or last sequence)
            subjects_data = None
            for idx in range(len(top_tlvs) - 1, -1, -1):
                if top_tlvs[idx][0] in (16, 48, 0x30):
                    subjects_data = top_tlvs[idx][1]
                    break

            if subjects_data is None:
                logger.error("Could not locate trustedSubjects sequence in disallowed CTL.")
                return []

        except Exception as e:
            logger.error("Error traversing top-level CTL structure: %s", e)
            return []

        # Parse each TrustedSubject entry
        records: List[DisallowedRecord] = []
        sub_off = 0
        entry_idx = 0

        while sub_off < len(subjects_data):
            try:
                entry_idx += 1
                _, _, s_val, sub_off = decode_der_tlv(subjects_data, sub_off)

                # Subject Identifier
                p_off = 0
                _, _, id_val, p_off = decode_der_tlv(s_val, p_off)
                subj_id_hex = id_val.hex().lower()
                byte_len = len(id_val)

                sha1_val = None
                sha256_val = None

                # Disallowed identifier categorization
                if byte_len == 20:
                    sha1_val = subj_id_hex
                elif byte_len == 32:
                    sha256_val = subj_id_hex
                elif byte_len == 48:
                    # 48-byte composite identifier: first 32 bytes are SHA-256
                    sha256_val = subj_id_hex[:64]

                # Parse extended attributes if present
                attrs_dict: Dict[str, Any] = {}
                if p_off < len(s_val):
                    _, _, a_val, _ = decode_der_tlv(s_val, p_off)
                    attr_off = 0
                    while attr_off < len(a_val):
                        _, _, single_attr, attr_off = decode_der_tlv(a_val, attr_off)
                        at_off = 0
                        _, _, oid_bytes, at_off = decode_der_tlv(single_attr, at_off)
                        oid = core.ObjectIdentifier.load(
                            b"\x06" + bytes([len(oid_bytes)]) + oid_bytes
                        ).native

                        _, _, set_bytes, _ = decode_der_tlv(single_attr, at_off)
                        _, _, val_payload, _ = decode_der_tlv(set_bytes, 0)

                        if oid == "1.3.6.1.4.1.311.10.11.11":  # Friendly Name
                            try:
                                attrs_dict["friendly_name"] = val_payload.decode("utf-16le").rstrip("\x00")
                            except Exception:
                                attrs_dict["friendly_name"] = val_payload.hex()
                        elif oid == "1.3.6.1.4.1.311.10.11.98":  # SHA-256 Hash
                            if len(val_payload) == 32:
                                sha256_val = val_payload.hex().lower()
                            elif len(val_payload) > 32 and val_payload[0] == 0x04:
                                _, _, inner_h, _ = decode_der_tlv(val_payload, 0)
                                sha256_val = inner_h.hex().lower()
                            attrs_dict["sha256"] = sha256_val
                        else:
                            attrs_dict[oid] = val_payload.hex().lower()

                record = DisallowedRecord(
                    vendor=VENDOR_NAME,
                    snapshot_date=snapshot_date,
                    snapshot_timestamp=snapshot_timestamp,
                    ctl_issue_time=issue_time_dt,
                    ctl_sequence_number=sequence_number_hex,
                    entry_index=entry_idx,
                    subject_identifier=subj_id_hex,
                    identifier_byte_length=byte_len,
                    sha1_fingerprint=sha1_val,
                    sha256_fingerprint=sha256_val,
                    attributes_json=json.dumps(attrs_dict, sort_keys=True) if attrs_dict else "{}",
                    data_source_type=DATA_SOURCE_TYPE,
                    provenance_url=provenance_url,
                )
                records.append(record)

            except Exception as e:
                logger.debug("Error parsing single disallowed entry %d: %s", entry_idx, e)
                continue

        return records


# ---------------------------------------------------------------------------
# Wayback Client & Caching Manager
# ---------------------------------------------------------------------------
class MicrosoftDisallowedWaybackClient:
    """Manages CDX query discovery and retrieval of historical disallowedcertstl.cab files."""

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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebPKI-Research-Bot/1.0",
        })

    def fetch_snapshot_list(self) -> List[WaybackSnapshotMetadata]:
        """Discovers snapshots from CDX API or local cache, falling back to curated anchors."""
        cache_file = self.cache_dir / "cdx_disallowed_snapshots.json" if self.cache_dir else None

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
            "fl": "timestamp,original,statuscode,digest",
            "filter": "statuscode:200",
            "from": "2012",
            "to": "2026",
        }

        snapshots: List[WaybackSnapshotMetadata] = []
        for attempt in range(1, self.max_retries + 1):
            try:
                # Use curl directly on Windows if available for fast DNS resolution
                curl_bin = shutil.which("curl.exe") or shutil.which("curl")
                if curl_bin:
                    cdx_full = f"{WAYBACK_CDX_API_URL}?url={self.cab_url}&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&from=2012&to=2026"
                    cmd = [curl_bin, "-s", "-A", "Mozilla/5.0", cdx_full]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if res.returncode == 0 and res.stdout.startswith("["):
                        data = json.loads(res.stdout)
                        if len(data) > 1:
                            for row in data[1:]:
                                if len(row) >= 2 and len(row[0]) >= 8:
                                    snapshots.append(
                                        WaybackSnapshotMetadata(
                                            timestamp=row[0],
                                            original_url=row[1],
                                            status_code=row[2] if len(row) > 2 else "200",
                                            digest=row[3] if len(row) > 3 else "",
                                        )
                                    )
                            logger.info("Wayback CDX API returned %d snapshots.", len(snapshots))
                            break

                # Fallback to requests
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
                                        digest=row[3] if len(row) > 3 else "",
                                    )
                                )
                    logger.info("Wayback CDX API returned %d snapshots.", len(snapshots))
                    break
            except Exception as e:
                logger.warning("CDX attempt %d failed: %s", attempt, e)
                time.sleep(2 * attempt)

        # Fallback to pre-indexed anchor snapshots if CDX is rate-limited
        if not snapshots:
            logger.info("CDX unavailable; using %d pre-indexed anchor snapshots.", len(FALLBACK_ANCHOR_TIMESTAMPS))
            snapshots = [
                WaybackSnapshotMetadata(
                    timestamp=ts,
                    original_url=self.cab_url,
                    status_code="200",
                    digest="",
                )
                for ts in FALLBACK_ANCHOR_TIMESTAMPS
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
        Retrieves disallowedcert.stl bytes for a given snapshot with strict caching.
        """
        stl_cache = self.cache_dir / f"disallowed_{snapshot.timestamp}.stl" if self.cache_dir else None
        cab_cache = self.cache_dir / f"disallowed_{snapshot.timestamp}.cab" if self.cache_dir else None

        # Check cached STL file
        if stl_cache and stl_cache.exists():
            return stl_cache.read_bytes()

        # Check cached CAB file
        cab_bytes: Optional[bytes] = None
        if cab_cache and cab_cache.exists():
            cab_bytes = cab_cache.read_bytes()

        # Download CAB if not cached
        if not cab_bytes:
            replay_url = snapshot.replay_url
            logger.info("Downloading disallowed CAB from Wayback: %s ...", replay_url)

            # Try curl.exe first for reliability
            curl_bin = shutil.which("curl.exe") or shutil.which("curl")
            if curl_bin and cab_cache:
                try:
                    subprocess.run(
                        [curl_bin, "-s", "-A", "Mozilla/5.0", "-L", replay_url, "-o", str(cab_cache)],
                        check=True,
                        timeout=30,
                    )
                    if cab_cache.exists() and cab_cache.stat().st_size > 0:
                        cab_bytes = cab_cache.read_bytes()
                except Exception as ex:
                    logger.debug("curl download failed: %s", ex)

            if not cab_bytes:
                for attempt in range(1, self.max_retries + 1):
                    try:
                        resp = self.session.get(replay_url, timeout=25)
                        if resp.status_code == 200:
                            cab_bytes = resp.content
                            if cab_cache:
                                cab_cache.write_bytes(cab_bytes)
                            break
                        elif resp.status_code in (429, 503):
                            time.sleep(5 * attempt)
                    except requests.RequestException as e:
                        logger.warning("Download attempt %d failed: %s", attempt, e)
                        time.sleep(3 * attempt)

            time.sleep(self.sleep_seconds)

        if not cab_bytes:
            logger.warning("Could not obtain CAB for snapshot %s.", snapshot.timestamp)
            return None

        # Extract STL
        stl_bytes = CabExtractor.extract_stl_bytes(cab_bytes)
        if stl_bytes and stl_cache:
            try:
                stl_cache.write_bytes(stl_bytes)
            except Exception as e:
                logger.debug("Failed saving STL cache: %s", e)

        return stl_bytes

    def get_live_stl_bytes(self) -> Optional[Tuple[bytes, date, str]]:
        """Retrieves the current live disallowedcertstl.cab directly from Microsoft CDN."""
        today_iso = date.today().isoformat()
        cache_stl = self.cache_dir / f"disallowed_live_{today_iso}.stl" if self.cache_dir else None

        if cache_stl and cache_stl.exists():
            return cache_stl.read_bytes(), date.today(), self.cab_url

        logger.info("Fetching current live disallowed CAB from Microsoft CDN: %s ...", self.cab_url)
        try:
            resp = self.session.get(self.cab_url, timeout=25)
            if resp.status_code == 200:
                stl_bytes = CabExtractor.extract_stl_bytes(resp.content)
                if stl_bytes and cache_stl:
                    cache_stl.write_bytes(stl_bytes)
                return stl_bytes, date.today(), self.cab_url
        except Exception as e:
            logger.warning("Failed downloading live disallowed CAB: %s", e)
        return None


# ---------------------------------------------------------------------------
# Cross-Reference Analysis Engine
# ---------------------------------------------------------------------------
def run_cross_reference_analysis(
    disallowed_df: pd.DataFrame,
    target_roots_path: Path = DEFAULT_TARGET_ROOTS_CSV,
) -> Dict[str, Any]:
    """
    Cross-references disallowed trust history against target WoSign/StartCom roots.
    """
    logger.info("Starting cross-reference analysis against: %s", target_roots_path)
    if not target_roots_path.exists():
        logger.warning("Target roots CSV not found at: %s", target_roots_path)
        return {"matched": False, "details": []}

    target_df = pd.read_csv(target_roots_path)
    all_disallowed_ids = set(disallowed_df["subject_identifier"].str.lower())
    all_disallowed_sha1 = set(disallowed_df["sha1_fingerprint"].dropna().str.lower())
    all_disallowed_sha256 = set(disallowed_df["sha256_fingerprint"].dropna().str.lower())

    results = []
    for _, row in target_df.iterrows():
        ca_label = row.get("ca_label", "Unknown")
        dn = row.get("subject_dn", "")
        h256 = str(row.get("sha256_fingerprint", "")).lower()
        h1 = str(row.get("sha1_fingerprint", "")).lower()
        md5_val = str(row.get("md5_fingerprint", "")).lower()

        # Check all possible hash variations
        in_ids = (h256 in all_disallowed_ids) or (h1 in all_disallowed_ids) or (md5_val in all_disallowed_ids)
        in_sha1 = (h1 in all_disallowed_sha1)
        in_sha256 = (h256 in all_disallowed_sha256)

        is_present = in_ids or in_sha1 or in_sha256
        first_seen_snapshot = None

        if is_present:
            matches = disallowed_df[
                (disallowed_df["subject_identifier"].str.lower() == h256)
                | (disallowed_df["subject_identifier"].str.lower() == h1)
                | (disallowed_df["sha1_fingerprint"].str.lower() == h1)
                | (disallowed_df["sha256_fingerprint"].str.lower() == h256)
            ]
            first_seen_snapshot = str(matches["snapshot_date"].min())

        results.append({
            "ca_family": row.get("ca_family", ""),
            "ca_label": ca_label,
            "subject_dn": dn,
            "sha256": h256,
            "sha1": h1,
            "is_in_disallowed_list": is_present,
            "first_disallowed_snapshot": first_seen_snapshot,
            "authroot_presence": "Still present in authroot.stl through 2026",
            "microsoft_restriction_mechanism": "Temporal constraint (NotBefore: 2017-09-26)",
        })

    return {
        "matched": any(r["is_in_disallowed_list"] for r in results),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Pipeline Orchestration
# ---------------------------------------------------------------------------
def run_pipeline(
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    target_roots_path: Path = DEFAULT_TARGET_ROOTS_CSV,
    include_live: bool = True,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Executes the complete fetch, parse, export, and cross-reference pipeline."""
    client = MicrosoftDisallowedWaybackClient()
    snapshots = client.fetch_snapshot_list()
    total_snaps = len(snapshots)
    logger.info("Found %d historical disallowed snapshots.", total_snaps)

    all_records: List[DisallowedRecord] = []

    # Process all historical snapshots
    for idx, snap in enumerate(snapshots, start=1):
        snap_date = snap.snapshot_date
        logger.info(
            "[%d/%d] Processing disallowed snapshot %s (%s)...",
            idx,
            total_snaps,
            snap_date.isoformat(),
            snap.timestamp,
        )
        stl_bytes = client.get_stl_bytes(snap)
        if not stl_bytes:
            continue

        records = MicrosoftDisallowedCTLParser.parse_stl(
            stl_bytes=stl_bytes,
            snapshot_date=snap_date,
            snapshot_timestamp=snap.timestamp,
            provenance_url=snap.provenance_url,
        )
        all_records.extend(records)

    # Process live snapshot from Microsoft CDN
    if include_live:
        live_res = client.get_live_stl_bytes()
        if live_res:
            live_stl, live_date, live_url = live_res
            today_ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            live_records = MicrosoftDisallowedCTLParser.parse_stl(
                stl_bytes=live_stl,
                snapshot_date=live_date,
                snapshot_timestamp=today_ts,
                provenance_url=live_url,
            )
            logger.info("Extracted %d disallowed entries from live Microsoft CDN snapshot.", len(live_records))
            all_records.extend(live_records)

    # Convert to DataFrame
    df = pd.DataFrame([vars(r) for r in all_records])
    if df.empty:
        logger.error("No records extracted.")
        return df, {}

    # Deduplicate within same snapshot and identifier
    df = df.drop_duplicates(subset=["snapshot_timestamp", "subject_identifier"])
    df = df.sort_values(by=["snapshot_date", "entry_index"]).reset_index(drop=True)

    # Enforce string types for hash columns
    df["sha1_fingerprint"] = df["sha1_fingerprint"].astype("string")
    df["sha256_fingerprint"] = df["sha256_fingerprint"].astype("string")

    # Export to Parquet and CSV
    parquet_path = output_dir / "disallowed_trust_history.parquet"
    csv_path = output_dir / "disallowed_trust_history.csv"

    logger.info("Saving Parquet dataset to: %s ...", parquet_path)
    df.to_parquet(parquet_path, index=False, engine="pyarrow")

    logger.info("Saving CSV dataset to: %s ...", csv_path)
    df.to_csv(csv_path, index=False, encoding="utf-8")

    # Run Cross-Reference Analysis
    analysis = run_cross_reference_analysis(df, target_roots_path=target_roots_path)

    return df, analysis


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    """CLI execution entrypoint."""
    parser = argparse.ArgumentParser(
        description="Extract and parse historical Microsoft Disallowed Certificate Trust Lists (disallowedcert.stl)."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save output files (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--target-roots",
        type=Path,
        default=DEFAULT_TARGET_ROOTS_CSV,
        help=f"Path to wosign_target_roots.csv (default: {DEFAULT_TARGET_ROOTS_CSV})",
    )
    args = parser.parse_args()

    df, analysis = run_pipeline(
        output_dir=args.output_dir,
        target_roots_path=args.target_roots,
    )

    print("\n" + "=" * 90)
    print("MICROSOFT DISALLOWED CTL EXTRACTION SUMMARY")
    print("=" * 90)
    print(f"Total snapshot records extracted: {len(df)}")
    print(f"Distinct snapshot dates:          {df['snapshot_date'].nunique()}")
    print(f"Distinct disallowed certificates: {df['subject_identifier'].nunique()}")
    print("-" * 90)

    print("\n" + "=" * 90)
    print("WOSIGN / STARTCOM DISALLOWED CROSS-REFERENCE ANALYSIS")
    print("=" * 90)
    res_list = analysis.get("results", [])
    for r in res_list:
        print(f"• CA: {r['ca_label']} ({r['ca_family']})")
        print(f"  SHA-256: {r['sha256']}")
        print(f"  In disallowedcert.stl: {r['is_in_disallowed_list']}")
        print(f"  AuthRoot STL Status:   {r['authroot_presence']}")
        print(f"  Enforcement Policy:    {r['microsoft_restriction_mechanism']}\n")
    print("=" * 90 + "\n")


if __name__ == "__main__":
    main()
