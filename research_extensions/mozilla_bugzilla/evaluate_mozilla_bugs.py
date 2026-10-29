#!/usr/bin/env python3
"""
Mozilla NSS Bugzilla Metadata Evaluator & Case Study Analysis
============================================================

Performs rigorous statistical analysis and case study evaluations of:
1. WoSign / StartCom Distrust Decision Timeline (Ticket vs. Code vs. certdata.txt)
2. SHA-1 Phasing & Deprecation Progression (2013–2022)
3. Action Type Distributions & Policy-to-Deployment Lead Times

Outputs:
  - Evaluation summaries printed to console and formatted for MOZILLA_BUGZILLA_STUDY.md
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

# Set stdout to UTF-8
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_PARQUET = SCRIPT_DIR / "mozilla_bug_metadata.parquet"
OUTPUT_CSV = SCRIPT_DIR / "mozilla_bug_metadata.csv"
CATALOG_PARQUET = SCRIPT_DIR / "bugzilla_bugs_catalog.parquet"
CACHE_FILE = SCRIPT_DIR / ".cache" / "bugzilla_cache.json"


def load_datasets() -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    df_commits = pd.read_parquet(OUTPUT_PARQUET)
    df_bugs = pd.read_parquet(CATALOG_PARQUET)
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        cache = json.load(f)
    return df_commits, df_bugs, cache


def analyze_general_stats(df_commits: pd.DataFrame, df_bugs: pd.DataFrame) -> Dict[str, Any]:
    total_commits = len(df_commits["commit_hash"].unique())
    commits_with_bugs = len(df_commits.dropna(subset=["bug_id"])["commit_hash"].unique())
    total_bugs = len(df_bugs)
    unique_commit_bugs = len(df_commits.dropna(subset=["bug_id"])["bug_id"].unique())

    action_counts = df_commits["action_type"].value_counts().to_dict()

    # Lead time statistics
    valid_lead = df_commits.dropna(subset=["lead_time_days"])["lead_time_days"]
    lead_mean = valid_lead.mean()
    lead_median = valid_lead.median()
    lead_q25 = valid_lead.quantile(0.25)
    lead_q75 = valid_lead.quantile(0.75)

    stats = {
        "total_commits": total_commits,
        "commits_with_bugs": commits_with_bugs,
        "commit_coverage_pct": (commits_with_bugs / total_commits) * 100,
        "total_bugs_cataloged": total_bugs,
        "unique_commit_bugs": unique_commit_bugs,
        "action_counts": action_counts,
        "lead_mean": lead_mean,
        "lead_median": lead_median,
        "lead_q25": lead_q25,
        "lead_q75": lead_q75,
    }
    return stats


def analyze_wosign_timeline(cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Constructs the exact micro-timeline for WoSign & StartCom distrust.
    """
    wosign_bugs = [
        1309707,  # Distrust new certs chaining up to current WoSign/StartCom roots
        1309923,  # Create blocklist entries for backdated WoSign SHA-1 certificates
        1311832,  # StartCom: Action Items
        1311995,  # NSS should implement the equivalent date-based distrust for WoSign/StartCom roots
        1387260,  # Remove old WoSign root certificates
        1392849,  # Remove old StartCom root certificates
        1408080,  # October 2017 batch of root CA changes
    ]

    timeline = []
    for b_id in wosign_bugs:
        data = cache.get(str(b_id), {})
        timeline.append({
            "bug_id": b_id,
            "summary": data.get("summary"),
            "status": data.get("status"),
            "resolution": data.get("resolution"),
            "created": data.get("creation_time", "")[:10],
            "resolved": (data.get("cf_last_resolved") or data.get("last_change_time") or "")[:10],
            "component": f"{data.get('product')}: {data.get('component')}",
            "blocks": data.get("blocks", []),
            "depends_on": data.get("depends_on", []),
        })
    return timeline


def analyze_sha1_timeline(cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Constructs the exact timeline for SHA-1 deprecation and phasing.
    """
    sha1_bugs = [
        942835,   # Phase out certificates with SHA-1 based signature algorithms
        1006540,  # Add mechanism to distrust SHA-1 certificates issued after a certain date
        1079858,  # Deal with deprecation of SHA1 Authenticode signatures
        1118377,  # Reject SHA-1 Code Signing Certificates after Jan 1, 2016
        1268219,  # Remove SHA-1 ApplicationCA - Japanese Government root certificate
        1302140,  # Add policy mode to completely disallow sha-1 signature
        1309923,  # Create blocklist entries for backdated WoSign SHA-1 certificates
        1336616,  # Deprecate SHA-1 to 50% of Beta Users
        1338228,  # Deprecate SHA-1 to 100% of Beta Users and 25% of Release Users
        1339662,  # Deprecate SHA-1 to 100% of Beta and Release Users
        1766687,  # Remove support for sha-1 signatures in all certificates
        1767489,  # Set pref to completely disable sha-1 in certificate signatures by default
    ]

    timeline = []
    for b_id in sha1_bugs:
        data = cache.get(str(b_id), {})
        timeline.append({
            "bug_id": b_id,
            "summary": data.get("summary"),
            "status": data.get("status"),
            "resolution": data.get("resolution"),
            "created": data.get("creation_time", "")[:10],
            "resolved": (data.get("cf_last_resolved") or data.get("last_change_time") or "")[:10],
            "component": f"{data.get('product')}: {data.get('component')}",
        })
    return timeline


def print_evaluation() -> None:
    df_commits, df_bugs, cache = load_datasets()
    stats = analyze_general_stats(df_commits, df_bugs)

    print("=" * 80)
    print("MOZILLA BUGZILLA & CERTDATA.TXT TRUST MINING EVALUATION")
    print("=" * 80)
    print(f"Total certdata.txt commits analyzed: {stats['total_commits']}")
    print(f"Commits linked to Bugzilla tickets: {stats['commits_with_bugs']} ({stats['commit_coverage_pct']:.1f}%)")
    print(f"Total Bugzilla tickets cataloged:   {stats['total_bugs_cataloged']}")
    print(f"Unique bugs linked in commits:      {stats['unique_commit_bugs']}")
    print("\nAction Type Breakdown across commits:")
    for action, count in stats["action_counts"].items():
        print(f"  - {action:12s}: {count:4d} ({count / len(df_commits) * 100:.1f}%)")

    print("\nLead Time Distribution (Bug creation -> Git commit in certdata.txt):")
    print(f"  - Mean lead time:   {stats['lead_mean']:.1f} days")
    print(f"  - Median lead time: {stats['lead_median']:.1f} days")
    print(f"  - 25th percentile:  {stats['lead_q25']:.1f} days")
    print(f"  - 75th percentile:  {stats['lead_q75']:.1f} days")

    print("\n" + "=" * 80)
    print("CASE STUDY 1: WOSIGN & STARTCOM DISTRUST TIMELINE")
    print("=" * 80)
    w_timeline = analyze_wosign_timeline(cache)
    for entry in w_timeline:
        print(f"Bug {entry['bug_id']} [{entry['created']} -> {entry['resolved']}] ({entry['resolution']}): {entry['summary']}")

    print("\n" + "=" * 80)
    print("CASE STUDY 2: SHA-1 PHASING & DEPRECATION PROGRESSION")
    print("=" * 80)
    s_timeline = analyze_sha1_timeline(cache)
    for entry in s_timeline:
        print(f"Bug {entry['bug_id']} [{entry['created']} -> {entry['resolved']}] ({entry['resolution']}): {entry['summary']}")


if __name__ == "__main__":
    print_evaluation()
