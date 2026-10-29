#!/usr/bin/env python3
"""
Mozilla NSS Bugzilla Context & Distrust Metadata Mining
======================================================

Extracts historical commits to `certdata.txt` in the NSS repository,
correlates them with Mozilla Bugzilla tickets via the REST API,
and produces enriched metadata for root trust additions, removals,
and explicit distrust decisions (with special focus on WoSign/StartCom
and SHA-1 deprecation).

Outputs:
  - research_extensions/mozilla_bugzilla/mozilla_bug_metadata.parquet
  - research_extensions/mozilla_bugzilla/mozilla_bug_metadata.csv
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import git
import pandas as pd
import requests

# Set stdout to UTF-8
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mozilla_bugzilla_miner")

# ---------------------------------------------------------------------------
# Paths and Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
CACHE_DIR = SCRIPT_DIR / ".cache"
OUTPUT_PARQUET = SCRIPT_DIR / "mozilla_bug_metadata.parquet"
OUTPUT_CSV = SCRIPT_DIR / "mozilla_bug_metadata.csv"

BUGZILLA_API_BASE = "https://bugzilla.mozilla.org/rest/bug"
CERTDATA_PATHS = [
    "lib/ckfw/builtins/certdata.txt",
    "security/nss/lib/ckfw/builtins/certdata.txt",
]

# Targeted incident bugs of interest for deep-dive analysis
KEY_INCIDENT_BUGS = {
    # WoSign & StartCom distrust trajectory
    1309707: "WoSign/StartCom Policy Action - Distrust new certs",
    1309923: "WoSign backdated SHA-1 blocklist entries",
    1311832: "StartCom: Action Items (Policy Tracking)",
    1311995: "NSS code-level date-based distrust for WoSign/StartCom",
    1387260: "Remove old WoSign root certificates",
    1392849: "Remove old StartCom root certificates",
    1408080: "October 2017 batch of root CA changes (WoSign/StartCom removal)",
    # SHA-1 Phasing & Deprecation
    942835: "Phase out certificates with SHA-1 based signature algorithms",
    1006540: "Add mechanism to distrust SHA-1 certs issued after cutoff",
    1079858: "Deprecation of SHA-1 Authenticode signatures",
    1118377: "Reject SHA-1 Code Signing Certs after Jan 1, 2016",
    1268219: "Remove SHA-1 ApplicationCA Japanese Government root",
    1302140: "Add policy mode to completely disallow SHA-1",
    1336616: "Deprecate SHA-1 to 50% beta users",
    1338228: "Deprecate SHA-1 to 100% beta and 25% release",
    1339662: "Deprecate SHA-1 to 100% of beta and release users",
    1766687: "Remove support for SHA-1 signatures in all certificates",
    1767489: "Disable SHA-1 in certificate signatures by default",
    # Notable Major Distrust Incidents
    683449: "DigiNotar compromise & immediate distrust",
    1146026: "Distrust MSCHOLDING intermediate certificate",
    1465613: "Create CKA_NSS_SERVER_DISTRUST_AFTER and CKA_NSS_EMAIL_DISTRUST_AFTER fields",
    1618402: "Remove Symantec and VeriSign roots",
    1618404: "Set CKA_NSS_SERVER_DISTRUST_AFTER for Symantec roots",
    1618407: "Set CKA_NSS_EMAIL_DISTRUST_AFTER for Symantec roots",
    1692094: "Set email distrust after for Camerfirma roots",
    1803453: "Distrust TrustCor Root Certificates",
    1901080: "GLOBALTRUST 2020 Distrust After",
    1922387: "Entrust Roots Distrust After TLS",
    1974299: "Chunghwa Telecom ePKI Root distrust after",
    2017322: "Izenpe.com CKA_NSS_SERVER_DISTRUST_AFTER",
}


# ---------------------------------------------------------------------------
# Commit Mining
# ---------------------------------------------------------------------------
def extract_bugs_from_message(msg: str) -> List[int]:
    """
    Extracts all numeric Bugzilla bug IDs from a git commit message.
    Handles various historical phrasing conventions:
      - 'Bug 123456'
      - 'bug 123456, 789012'
      - 'Bugzilla Bug 123456'
      - 'b=123456'
      - 'Fix for 123456'
      - '1418678, Add Certum...'
    """
    found: Set[int] = set()

    # Pattern 1: Explicit bug / bugzilla / b= prefix followed by numbers
    for m in re.finditer(
        r"(?:bugs?|bugzilla(?:\s+bug)?|b=|fix(?:es)?\s+for)\s*[:#]?\s*([0-9]{4,8}(?:(?:\s*,\s*|\s+and\s+)[0-9]{4,8})*)",
        msg,
        re.IGNORECASE,
    ):
        for num in re.findall(r"[0-9]{4,8}", m.group(1)):
            bug_val = int(num)
            if 1000 <= bug_val <= 3000000:
                found.add(bug_val)

    # Pattern 2: Leading bug number at start of commit title
    m_lead = re.match(r"^\s*([0-9]{5,8})[,:\s\-]", msg)
    if m_lead:
        bug_val = int(m_lead.group(1))
        if 1000 <= bug_val <= 3000000:
            found.add(bug_val)

    return sorted(list(found))


def mine_certdata_commits(repo_path: Path) -> List[Dict[str, Any]]:
    """
    Traverses git commits modifying `certdata.txt` and extracts metadata.
    """
    logger.info("Opening git repository at %s", repo_path)
    repo = git.Repo(repo_path)

    # We iterate across both modern and legacy certdata paths
    commits = list(repo.iter_commits(paths=CERTDATA_PATHS))
    logger.info("Found %d commits modifying certdata.txt", len(commits))

    results = []
    for c in commits:
        commit_dt = c.authored_datetime.astimezone(timezone.utc)
        subject = c.message.strip().splitlines()[0] if c.message else ""
        bug_ids = extract_bugs_from_message(c.message)

        results.append({
            "commit_hash": c.hexsha,
            "commit_short": c.hexsha[:10],
            "commit_date": commit_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "commit_date_iso": commit_dt.date().isoformat(),
            "commit_author_name": c.author.name,
            "commit_author_email": c.author.email,
            "commit_subject": subject,
            "commit_message": c.message.strip(),
            "bug_ids": bug_ids,
            "bug_count": len(bug_ids),
        })

    return results


# ---------------------------------------------------------------------------
# Bugzilla REST API Client with Local Caching
# ---------------------------------------------------------------------------
class BugzillaClient:
    """
    Queries Mozilla's Bugzilla REST API with disk-based persistent caching.
    """

    def __init__(self, cache_dir: Path = CACHE_DIR) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "bugzilla_cache.json"
        self.cache: Dict[str, Dict[str, Any]] = self._load_cache()

    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logger.info("Loaded %d cached bug records from %s", len(data), self.cache_file)
                    return data
            except Exception as e:
                logger.warning("Failed to load cache: %s. Starting fresh.", e)
        return {}

    def _save_cache(self) -> None:
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
            logger.info("Saved %d bug records to cache file %s", len(self.cache), self.cache_file)
        except Exception as e:
            logger.error("Failed to save cache: %s", e)

    def fetch_bugs(self, bug_ids: Sequence[int], batch_size: int = 30) -> Dict[int, Dict[str, Any]]:
        """
        Fetches metadata for a list of bug IDs in batches, leveraging cached data.
        """
        results: Dict[int, Dict[str, Any]] = {}
        missing_ids: List[int] = []

        for b_id in bug_ids:
            s_id = str(b_id)
            if s_id in self.cache:
                results[b_id] = self.cache[s_id]
            else:
                missing_ids.append(b_id)

        if not missing_ids:
            logger.info("All %d requested bugs found in cache.", len(bug_ids))
            return results

        logger.info(
            "Fetching %d missing bugs from Bugzilla REST API (%d already cached)...",
            len(missing_ids),
            len(results),
        )

        headers = {
            "User-Agent": "ResearchStudy-MozillaTrustStoreMining/1.0 (academic-research)",
            "Accept": "application/json",
        }

        # Query in batches to keep URLs well within HTTP limits
        for i in range(0, len(missing_ids), batch_size):
            chunk = missing_ids[i : i + batch_size]
            chunk_str = ",".join(str(x) for x in chunk)
            url = (
                f"{BUGZILLA_API_BASE}?id={chunk_str}"
                f"&include_fields=id,summary,status,resolution,creation_time,"
                f"last_change_time,cf_last_resolved,keywords,whiteboard,"
                f"product,component,blocks,depends_on,see_also"
            )

            try:
                resp = requests.get(url, headers=headers, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    bugs = data.get("bugs", [])
                    for bug in bugs:
                        b_id = bug["id"]
                        self.cache[str(b_id)] = bug
                        results[b_id] = bug
                    logger.info("Fetched batch %d/%d (%d bugs)", i // batch_size + 1, (len(missing_ids) + batch_size - 1) // batch_size, len(bugs))
                else:
                    logger.warning("Bugzilla API returned HTTP %d for chunk: %s", resp.status_code, chunk_str[:40])
                time.sleep(0.3)  # Gentle rate limiting
            except Exception as e:
                logger.error("Error querying Bugzilla API for batch: %s", e)

        self._save_cache()
        return results


# ---------------------------------------------------------------------------
# Metadata Classification & Action Inference
# ---------------------------------------------------------------------------
def classify_action_and_incident(
    summary: str,
    commit_msg: str,
    keywords: List[str],
    bug_id: int,
) -> Tuple[str, List[str], Optional[str]]:
    """
    Infers the high-level trust store action type, relevant security incident tags,
    and target CA name from the bug summary, commit message, and keywords.
    """
    text = f"{summary} {commit_msg}".lower()

    # 1. Action Type Classification
    action_type = "MAINTENANCE"
    if any(k in text for k in ["distrust", "distrust_after", "disallow", "sunset", "blocklist"]):
        action_type = "DISTRUST"
    elif any(k in text for k in ["remove", "removal", "delete", "purge"]):
        action_type = "REMOVAL"
    elif any(k in text for k in ["add", "inclusion", "include", "import"]):
        action_type = "ADD"
    elif any(k in text for k in ["trust bit", "enable", "disable", "modify", "revert", "change", "update", "eku"]):
        action_type = "MODIFY"

    # 2. Incident & Thematic Tags
    tags: List[str] = []
    if any(k in text for k in ["wosign", "startcom", "1311832", "1311995", "1387260", "1392849"]):
        tags.append("wosign_startcom")
    if any(k in text for k in ["sha-1", "sha1", "sha 1", "942835", "1006540", "1268219"]):
        tags.append("sha1_phasing")
    if any(k in text for k in ["1024", "1024-bit", "936304", "1155279"]):
        tags.append("weak_rsa_1024")
    if any(k in text for k in ["symantec", "geotrust", "thawte", "verisign", "1618402", "1618404", "1618407"]):
        tags.append("symantec_distrust")
    if any(k in text for k in ["diginotar", "683449"]):
        tags.append("diginotar")
    if any(k in text for k in ["trustcor", "1803453"]):
        tags.append("trustcor")
    if any(k in text for k in ["entrust", "1922387", "2032223"]):
        tags.append("entrust")
    if any(k in text for k in ["camerfirma", "1692094"]):
        tags.append("camerfirma")
    if any(k in text for k in ["izenpe", "2017322"]):
        tags.append("izenpe")
    if any(k in text for k in ["globaltrust", "1901080"]):
        tags.append("globaltrust")
    if any(k in text for k in ["chunghwa", "1974299"]):
        tags.append("chunghwa_telecom")

    # 3. Target CA Extraction (approximate heuristic)
    target_ca = None
    ca_match = re.search(
        r"(?:for|from|add|remove|distrust|disable)\s+['\"]?([A-Z0-9][A-Za-z0-9\.\-\s_]{2,35}(?:CA|Root|Authority|Trust|Sign|com))",
        summary,
        re.IGNORECASE,
    )
    if ca_match:
        target_ca = ca_match.group(1).strip()

    return action_type, tags, target_ca


# ---------------------------------------------------------------------------
# Main Mining & Enrichment Pipeline
# ---------------------------------------------------------------------------
def run_mining_pipeline() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Executes the entire mining, Bugzilla linking, and analytical enrichment process.
    """
    logger.info("Starting Mozilla Bugzilla Context & Distrust Mining Pipeline...")

    # Step 1: Mine git commits
    commits = mine_certdata_commits(REPO_ROOT)

    # Collect all bug IDs from commits
    all_commit_bug_ids: Set[int] = set()
    for c in commits:
        all_commit_bug_ids.update(c["bug_ids"])

    logger.info("Identified %d unique bug IDs across %d commits", len(all_commit_bug_ids), len(commits))

    # Add key incident bugs to ensure complete analysis even if tracked as policy bugs
    all_query_ids = set(all_commit_bug_ids)
    all_query_ids.update(KEY_INCIDENT_BUGS.keys())

    # Step 2: Fetch Bugzilla metadata
    bz_client = BugzillaClient(CACHE_DIR)
    bug_records = bz_client.fetch_bugs(sorted(list(all_query_ids)))

    # Also resolve child bugs from batch tickets (blocks / depends_on)
    child_bug_ids: Set[int] = set()
    for b_id, b_data in bug_records.items():
        summary = b_data.get("summary", "").lower()
        if "batch" in summary or b_id in [1408080, 1618402, 1641716, 1645199, 1639987]:
            for blk in b_data.get("blocks", []):
                if isinstance(blk, int) and blk not in bug_records:
                    child_bug_ids.add(blk)

    if child_bug_ids:
        logger.info("Resolving %d child bugs blocked by root CA batch tickets...", len(child_bug_ids))
        child_records = bz_client.fetch_bugs(sorted(list(child_bug_ids)))
        bug_records.update(child_records)

    # Step 3: Align Commits with Bug Metadata
    enriched_rows: List[Dict[str, Any]] = []

    for c in commits:
        c_hash = c["commit_hash"]
        c_short = c["commit_short"]
        c_dt_str = c["commit_date"]
        c_date_iso = c["commit_date_iso"]
        c_dt = datetime.strptime(c_date_iso, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        c_author = c["commit_author_name"]
        c_email = c["commit_author_email"]
        c_subj = c["commit_subject"]
        c_msg = c["commit_message"]
        bugs = c["bug_ids"]

        if not bugs:
            # Commit without recognized bug number
            action_type, tags, target_ca = classify_action_and_incident(c_subj, c_msg, [], 0)
            enriched_rows.append({
                "commit_hash": c_hash,
                "commit_short": c_short,
                "commit_date": c_dt_str,
                "commit_date_iso": c_date_iso,
                "commit_author": c_author,
                "commit_email": c_email,
                "commit_subject": c_subj,
                "bug_id": None,
                "bug_summary": None,
                "bug_status": None,
                "bug_resolution": None,
                "bug_creation_time": None,
                "bug_creation_date": None,
                "bug_resolved_time": None,
                "bug_resolved_date": None,
                "bug_component": None,
                "bug_product": None,
                "bug_keywords": None,
                "action_type": action_type,
                "incident_tags": ",".join(tags) if tags else "none",
                "target_ca": target_ca,
                "lead_time_days": None,
                "resolution_lag_days": None,
                "is_batch_ticket": False,
            })
            continue

        for b_id in bugs:
            b_info = bug_records.get(b_id, {})
            b_summary = b_info.get("summary")
            b_status = b_info.get("status")
            b_resolution = b_info.get("resolution")
            b_creation = b_info.get("creation_time")
            b_resolved = b_info.get("cf_last_resolved") or b_info.get("last_change_time") if b_status in ["RESOLVED", "VERIFIED", "CLOSED"] else None
            b_comp = b_info.get("component")
            b_prod = b_info.get("product")
            b_keywords = b_info.get("keywords", [])

            # Compute temporal lead times
            lead_time_days = None
            b_creation_date = None
            if b_creation:
                try:
                    c_time_clean = b_creation.replace("Z", "+00:00")
                    b_create_dt = datetime.fromisoformat(c_time_clean)
                    b_creation_date = b_create_dt.date().isoformat()
                    lead_time_days = (c_dt - datetime(b_create_dt.year, b_create_dt.month, b_create_dt.day, tzinfo=timezone.utc)).days
                except Exception:
                    pass

            resolution_lag_days = None
            b_resolved_date = None
            if b_resolved:
                try:
                    r_time_clean = b_resolved.replace("Z", "+00:00")
                    b_res_dt = datetime.fromisoformat(r_time_clean)
                    b_resolved_date = b_res_dt.date().isoformat()
                    resolution_lag_days = (c_dt - datetime(b_res_dt.year, b_res_dt.month, b_res_dt.day, tzinfo=timezone.utc)).days
                except Exception:
                    pass

            action_type, tags, target_ca = classify_action_and_incident(
                b_summary or c_subj,
                c_msg,
                b_keywords,
                b_id,
            )

            is_batch = "batch" in (b_summary or "").lower() or len(b_info.get("blocks", [])) > 2

            enriched_rows.append({
                "commit_hash": c_hash,
                "commit_short": c_short,
                "commit_date": c_dt_str,
                "commit_date_iso": c_date_iso,
                "commit_author": c_author,
                "commit_email": c_email,
                "commit_subject": c_subj,
                "bug_id": b_id,
                "bug_summary": b_summary,
                "bug_status": b_status,
                "bug_resolution": b_resolution,
                "bug_creation_time": b_creation,
                "bug_creation_date": b_creation_date,
                "bug_resolved_time": b_resolved,
                "bug_resolved_date": b_resolved_date,
                "bug_component": b_comp,
                "bug_product": b_prod,
                "bug_keywords": ",".join(b_keywords) if b_keywords else "",
                "action_type": action_type,
                "incident_tags": ",".join(tags) if tags else "none",
                "target_ca": target_ca,
                "lead_time_days": lead_time_days,
                "resolution_lag_days": resolution_lag_days,
                "is_batch_ticket": is_batch,
            })

    # Step 4: Standalone Bug Catalog (including Policy bugs not directly in certdata commit message)
    bug_catalog_rows: List[Dict[str, Any]] = []
    for b_id, b_info in bug_records.items():
        b_summary = b_info.get("summary", "")
        b_status = b_info.get("status")
        b_resolution = b_info.get("resolution")
        b_creation = b_info.get("creation_time")
        b_resolved = b_info.get("cf_last_resolved") or b_info.get("last_change_time")
        b_comp = b_info.get("component")
        b_prod = b_info.get("product")
        b_keywords = b_info.get("keywords", [])

        action_type, tags, target_ca = classify_action_and_incident(b_summary, "", b_keywords, b_id)

        # Check if linked to any certdata commit
        matching_commits = [c["commit_short"] for c in commits if b_id in c["bug_ids"]]

        bug_catalog_rows.append({
            "bug_id": b_id,
            "summary": b_summary,
            "status": b_status,
            "resolution": b_resolution,
            "creation_time": b_creation,
            "resolved_time": b_resolved,
            "product": b_prod,
            "component": b_comp,
            "action_type": action_type,
            "incident_tags": ",".join(tags) if tags else "none",
            "linked_commit_count": len(matching_commits),
            "linked_commits": ",".join(matching_commits),
            "is_key_incident": b_id in KEY_INCIDENT_BUGS,
            "incident_note": KEY_INCIDENT_BUGS.get(b_id, ""),
        })

    df_commits = pd.DataFrame(enriched_rows)
    df_bugs = pd.DataFrame(bug_catalog_rows)

    logger.info("Compiled %d enriched commit-bug mappings and %d cataloged bugs.", len(df_commits), len(df_bugs))

    # Save to Parquet and CSV
    OUTPUT_PARQUET.parent.mkdir(parents=True, exist_ok=True)
    df_commits.to_parquet(OUTPUT_PARQUET, index=False)
    df_commits.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
    logger.info("Exported enriched dataset to %s and %s", OUTPUT_PARQUET, OUTPUT_CSV)

    # Also save standalone bugs catalog for comprehensive analysis
    catalog_parquet = SCRIPT_DIR / "bugzilla_bugs_catalog.parquet"
    catalog_csv = SCRIPT_DIR / "bugzilla_bugs_catalog.csv"
    df_bugs.to_parquet(catalog_parquet, index=False)
    df_bugs.to_csv(catalog_csv, index=False, encoding="utf-8")
    logger.info("Exported bug catalog to %s and %s", catalog_parquet, catalog_csv)

    return df_commits, df_bugs


if __name__ == "__main__":
    run_mining_pipeline()
