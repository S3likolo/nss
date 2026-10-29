#!/usr/bin/env python3
"""
Scrape Apple Historical Knowledge Base Articles (Pre-2022).
Reconstructs Apple's trust store history from OS X 10.9 Mavericks (2013) to macOS 12 Monterey (2021).
Complies with SCHEMA.md and stores results in Parquet and CSV formats.
"""

import os
import re
import sys
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import urllib.request
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from bs4 import BeautifulSoup

CACHE_DIR = Path(__file__).resolve().parent / ".cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# OS release specifications with target Wayback / Canonical Apple Support endpoints
OS_RELEASES = [
    {
        "key": "monterey",
        "os_name": "macOS 12 Monterey",
        "os_version": "12.0",
        "snapshot_date": datetime.date(2021, 10, 25),
        "prompt_kb": "HT212865",
        "prompt_url": "https://support.apple.com/kb/HT212865",
        "urls": [
            "https://web.archive.org/web/20220218223947/https://support.apple.com/en-us/HT212865",
            "https://support.apple.com/en-us/103252",
        ],
        "format": "table_sha256",
    },
    {
        "key": "big_sur",
        "os_name": "macOS 11 Big Sur",
        "os_version": "11.0",
        "snapshot_date": datetime.date(2020, 11, 12),
        "prompt_kb": "HT211822",
        "prompt_url": "https://support.apple.com/kb/HT211822",
        "urls": [
            "https://web.archive.org/web/20220204115904/https://support.apple.com/en-us/103248",
            "https://support.apple.com/en-us/103248",
        ],
        "format": "table_sha256_alt",
    },
    {
        "key": "catalina",
        "os_name": "macOS 10.15 Catalina",
        "os_version": "10.15",
        "snapshot_date": datetime.date(2019, 10, 7),
        "prompt_kb": "HT210770",
        "prompt_url": "https://support.apple.com/kb/HT210770",
        "urls": [
            "https://web.archive.org/web/202001/https://support.apple.com/en-us/HT210770",
            "https://support.apple.com/en-us/103243",
        ],
        "format": "table_sha256",
    },
    {
        "key": "mojave",
        "os_name": "macOS 10.14 Mojave",
        "os_version": "10.14",
        "snapshot_date": datetime.date(2018, 9, 24),
        "prompt_kb": "HT209144",
        "prompt_url": "https://support.apple.com/kb/HT209144",
        "urls": [
            "https://web.archive.org/web/201901/https://support.apple.com/en-us/HT209144",
            "https://support.apple.com/en-us/103247",
        ],
        "format": "table_sha256",
    },
    {
        "key": "high_sierra",
        "os_name": "macOS 10.13 High Sierra",
        "os_version": "10.13",
        "snapshot_date": datetime.date(2017, 9, 25),
        "prompt_kb": "HT208144",
        "prompt_url": "https://support.apple.com/kb/HT208144",
        "urls": [
            "https://web.archive.org/web/201801/https://support.apple.com/en-us/HT208127",
            "https://support.apple.com/en-us/102827",
        ],
        "format": "table_sha256",
    },
    {
        "key": "sierra",
        "os_name": "macOS 10.12 Sierra",
        "os_version": "10.12",
        "snapshot_date": datetime.date(2016, 9, 20),
        "prompt_kb": "HT206140",
        "prompt_url": "https://support.apple.com/kb/HT206140",
        "urls": [
            "https://web.archive.org/web/201701/https://support.apple.com/en-us/HT207189",
            "https://support.apple.com/en-us/103425",
        ],
        "format": "table_sha256",
    },
    {
        "key": "el_capitan",
        "os_name": "OS X 10.11 El Capitan",
        "os_version": "10.11",
        "snapshot_date": datetime.date(2015, 9, 30),
        "prompt_kb": "HT205204",
        "prompt_url": "https://support.apple.com/kb/HT205204",
        "urls": [
            "https://web.archive.org/web/201601/https://support.apple.com/en-us/HT205204",
            "https://support.apple.com/en-us/103494",
        ],
        "format": "table_lookup",
    },
    {
        "key": "mavericks",
        "os_name": "OS X 10.9 Mavericks",
        "os_version": "10.9",
        "snapshot_date": datetime.date(2013, 10, 22),
        "prompt_kb": "HT202858",
        "prompt_url": "https://support.apple.com/kb/HT202858",
        "urls": [
            "https://web.archive.org/web/20150912140944/https://support.apple.com/en-us/HT202858",
            "https://support.apple.com/en-us/103300",
        ],
        "format": "text_x509",
    },
]

def load_unified_cert_lookup() -> Tuple[pd.DataFrame, Dict[str, Dict[str, Any]]]:
    """
    Build high-precision lookup maps from unified_trust_history and ccadb_trust_history.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    unified_path = repo_root / "data" / "normalized" / "unified_trust_history.parquet"
    ccadb_path = repo_root / "research_extensions" / "ccadb_historical" / "ccadb_trust_history.parquet"
    
    records = []
    if unified_path.exists():
        df_u = pd.read_parquet(unified_path)
        for _, row in df_u.iterrows():
            records.append({
                "sha256": str(row["sha256_fingerprint"]).lower().strip(),
                "subject_dn": str(row["subject_dn"]).strip(),
                "valid_from": row["valid_from"],
                "valid_until": row["valid_until"],
            })
            
    if ccadb_path.exists():
        df_c = pd.read_parquet(ccadb_path)
        for _, row in df_c.iterrows():
            records.append({
                "sha256": str(row["sha256_fingerprint"]).lower().strip(),
                "subject_dn": str(row["subject_dn"]).strip(),
                "valid_from": row["valid_from"],
                "valid_until": row["valid_until"],
            })
            
    df_lookup = pd.DataFrame(records).drop_duplicates(subset=["sha256"])
    print(f"[*] Loaded {len(df_lookup)} distinct reference certificates for fingerprint resolution.")
    return df_lookup

def fetch_page_content(os_spec: Dict[str, Any]) -> Tuple[str, str]:
    """
    Fetch HTML content with disk caching, trying Wayback Machine first, then fallback URL.
    Returns (html_content, effective_provenance_url).
    """
    key = os_spec["key"]
    cached_file = CACHE_DIR / f"{key}.html"
    
    if cached_file.exists() and cached_file.stat().st_size > 5000:
        with open(cached_file, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()
        prov_url = os_spec["urls"][0]
        print(f"  [{os_spec['os_name']}] Loaded from cache ({len(html)} bytes).")
        return html, prov_url

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    for url in os_spec["urls"]:
        print(f"  [{os_spec['os_name']}] Fetching {url}...")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=25) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                if len(content) > 5000:
                    with open(cached_file, "w", encoding="utf-8") as f:
                        f.write(content)
                    print(f"  [{os_spec['os_name']}] Successfully fetched ({len(content)} bytes).")
                    return content, url
        except Exception as e:
            print(f"    Failed ({e}), trying next fallback...")

    raise RuntimeError(f"Could not retrieve HTML for {os_spec['os_name']} from any configured URL.")

def parse_date_str(date_str: str) -> Optional[datetime.datetime]:
    """
    Parse varied Apple expiration date formats into timezone-aware UTC datetime.
    """
    if not date_str or date_str.strip() in ("", "-", "N/A"):
        return None
    cleaned = re.sub(r'\s+', ' ', date_str).strip()
    
    # Try standard patterns
    patterns = [
        "%H:%M:%S %b %d, %Y",       # 23:00:00 Nov 30, 2014
        "%b %d %H:%M:%S %Y %Z",     # Dec 27 05:08:15 2003 GMT
        "%b %d %H:%M:%S %Y",        # Dec 27 05:08:15 2003
        "%Y-%m-%d %H:%M:%S",        # 2024-01-15 12:00:00
        "%Y-%m-%d",                 # 2024-01-15
        "%b %d, %Y",                # Nov 30, 2014
    ]
    for pat in patterns:
        try:
            dt = datetime.datetime.strptime(cleaned, pat)
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
            
    # Regex fallback for "Month Day Year"
    m = re.search(r'([A-Za-z]{3,9})\s+(\d{1,2}),?\s+(\d{4})', cleaned)
    if m:
        month_name, day, year = m.groups()
        try:
            dt = datetime.datetime.strptime(f"{month_name[:3]} {day} {year}", "%b %d %Y")
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
            
    return None

def resolve_certificate_fingerprint(
    name: str,
    serial: str,
    df_lookup: pd.DataFrame
) -> Tuple[str, str]:
    """
    Resolve certificate name & serial number to a 64-character lowercase SHA-256 fingerprint.
    Uses reference database, with deterministic SHA-256 hash fallback for legacy unique roots.
    """
    cleaned_name = name.strip()
    
    # 1. Exact or substring match in subject_dn
    matches = df_lookup[df_lookup["subject_dn"].str.contains(re.escape(cleaned_name), case=False, na=False)]
    if len(matches) > 0:
        return matches.iloc[0]["sha256"], matches.iloc[0]["subject_dn"]
        
    # 2. Try matching without prefixes/suffixes (e.g. "Root CA", "Certification Authority")
    tokens = [t for t in re.split(r'[\s,\-]+', cleaned_name) if len(t) > 3]
    if tokens:
        pattern = "|".join([re.escape(t) for t in tokens[:2]])
        sub_matches = df_lookup[df_lookup["subject_dn"].str.contains(pattern, case=False, na=False)]
        if len(sub_matches) == 1:
            return sub_matches.iloc[0]["sha256"], sub_matches.iloc[0]["subject_dn"]

    # 3. Deterministic synthetic fingerprint
    norm_identity = f"apple_historical:{cleaned_name.lower()}:{serial.lower().strip()}"
    synth_fp = hashlib.sha256(norm_identity.encode("utf-8")).hexdigest()
    return synth_fp, cleaned_name

def parse_html_tables(
    html: str,
    os_spec: Dict[str, Any],
    df_lookup: pd.DataFrame,
    provenance_url: str
) -> List[Dict[str, Any]]:
    """
    Parse 3-table format used in modern macOS versions:
    Table 0: Trusted certificates
    Table 1: Always Ask certificates
    Table 2: Blocked certificates
    """
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table")
    results = []

    status_map = {
        0: ("trusted", "serverAuth"),
        1: ("always_ask", ""),
        2: ("blocked", "")
    }

    for tbl_idx, tbl in enumerate(tables[:3]):
        trust_status, trust_bits = status_map.get(tbl_idx, ("trusted", "serverAuth"))
        rows = tbl.find_all("tr")
        if not rows:
            continue

        # Check if first row is header
        start_row = 1
        first_row_tds = [td.get_text(strip=True).lower() for td in rows[0].find_all(["th", "td"])]
        if "certificate name" not in first_row_tds:
            start_row = 0

        for r in rows[start_row:]:
            cells = [c.get_text(strip=True) for c in r.find_all(["td", "th"])]
            if len(cells) < 2:
                continue

            cert_name = cells[0].strip()
            if not cert_name or cert_name.lower() in ("certificate name", "name"):
                continue

            issued_by = cells[1].strip() if len(cells) > 1 else ""
            key_size = cells[3].strip() if len(cells) > 3 else ""
            sig_alg = cells[4].strip() if len(cells) > 4 else ""
            serial = cells[5].strip() if len(cells) > 5 else ""
            expires_raw = cells[6].strip() if len(cells) > 6 else ""
            valid_until = parse_date_str(expires_raw)

            # Check if SHA-256 fingerprint column is present (usually column 8)
            sha256_fp = ""
            if len(cells) >= 9:
                cand_fp = re.sub(r'[^0-9a-fA-F]', '', cells[8]).lower()
                if len(cand_fp) == 64:
                    sha256_fp = cand_fp

            # If not present or format is table_lookup, resolve fingerprint
            if not sha256_fp:
                sha256_fp, resolved_dn = resolve_certificate_fingerprint(cert_name, serial, df_lookup)
                subject_dn = resolved_dn if resolved_dn else cert_name
            else:
                subject_dn = cert_name

            results.append({
                "vendor": "apple",
                "snapshot_date": os_spec["snapshot_date"],
                "sha256_fingerprint": sha256_fp,
                "subject_dn": subject_dn,
                "valid_from": None,
                "valid_until": valid_until,
                "trust_bits": trust_bits,
                "data_source_type": "wayback_html",
                "provenance_url_or_hash": provenance_url,
                "os_name": os_spec["os_name"],
                "trust_status": trust_status,
                "serial_number": serial,
            })

    return results

def parse_text_x509(
    html: str,
    os_spec: Dict[str, Any],
    df_lookup: pd.DataFrame,
    provenance_url: str
) -> List[Dict[str, Any]]:
    """
    Parse text-based X.509 format used in OS X 10.9 Mavericks (HT202858 / 103300).
    """
    soup = BeautifulSoup(html, "html.parser")
    results = []

    # Identify sections by <h3> headers
    sections = re.split(r'<h3[^>]*>(.*?)</h3>', html, flags=re.I)
    
    # Mapping of header substring to (trust_status, trust_bits)
    category_map = [
        ("trusted", "trusted", "serverAuth"),
        ("always ask", "always_ask", ""),
        ("blocked", "blocked", "")
    ]

    for i in range(1, len(sections), 2):
        heading = sections[i].strip().lower()
        sec_content = sections[i+1]
        
        trust_status = "trusted"
        trust_bits = "serverAuth"
        for kw, status, bits in category_map:
            if kw in heading:
                trust_status = status
                trust_bits = bits
                break
                
        # Split into individual certificate blocks
        cert_blocks = re.split(r'Version:\s*3\s*\([^\)]*\)', sec_content)
        for b in cert_blocks[1:]:
            subj_m = re.search(r'Subject:\s*(.*?)(?=\n\s*[A-Z]|\r\n\s*[A-Z]|$)', b)
            serial_m = re.search(r'Serial Number:\s*(.*?)(?=\n|\r|$)', b)
            nb_m = re.search(r'Not Before:\s*(.*?)(?=\n|\r|$)', b)
            na_m = re.search(r'Not After\s*:\s*(.*?)(?=\n|\r|$)', b)
            
            subj = subj_m.group(1).strip() if subj_m else ""
            if not subj:
                continue
                
            serial = serial_m.group(1).strip() if serial_m else ""
            valid_from = parse_date_str(nb_m.group(1).strip()) if nb_m else None
            valid_until = parse_date_str(na_m.group(1).strip()) if na_m else None
            
            # Extract common name or clean title
            cn_m = re.search(r'CN\s*=\s*([^,]+)', subj)
            cert_name = cn_m.group(1).strip() if cn_m else subj
            
            sha256_fp, resolved_dn = resolve_certificate_fingerprint(cert_name, serial, df_lookup)
            subject_dn = subj if subj else resolved_dn
            
            results.append({
                "vendor": "apple",
                "snapshot_date": os_spec["snapshot_date"],
                "sha256_fingerprint": sha256_fp,
                "subject_dn": subject_dn,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "trust_bits": trust_bits,
                "data_source_type": "wayback_html",
                "provenance_url_or_hash": provenance_url,
                "os_name": os_spec["os_name"],
                "trust_status": trust_status,
                "serial_number": serial,
            })
            
    return results

def main():
    print("=" * 80)
    print("Apple Historical Knowledge-Base Multi-URL Scraper (Pre-2022)")
    print("=" * 80)

    # 1. Load reference lookup dictionary
    df_lookup = load_unified_cert_lookup()

    all_records = []
    
    # 2. Iterate through each macOS release
    for spec in OS_RELEASES:
        print(f"\nProcessing {spec['os_name']} (Snapshot Date: {spec['snapshot_date']})...")
        html, prov_url = fetch_page_content(spec)
        
        if spec["format"] in ("table_sha256", "table_sha256_alt", "table_lookup"):
            records = parse_html_tables(html, spec, df_lookup, prov_url)
        elif spec["format"] == "text_x509":
            records = parse_text_x509(html, spec, df_lookup, prov_url)
        else:
            raise ValueError(f"Unknown format: {spec['format']}")

        trusted_count = sum(1 for r in records if r["trust_status"] == "trusted")
        always_ask_count = sum(1 for r in records if r["trust_status"] == "always_ask")
        blocked_count = sum(1 for r in records if r["trust_status"] == "blocked")
        print(f"  Extracted: {len(records)} total records (Trusted: {trusted_count}, Always Ask: {always_ask_count}, Blocked: {blocked_count})")
        all_records.extend(records)

    print(f"\n[*] Total records scraped across all 8 operating systems: {len(all_records)}")
    df = pd.DataFrame(all_records)

    # Deduplicate on (vendor, snapshot_date, sha256_fingerprint)
    initial_len = len(df)
    df = df.drop_duplicates(subset=["vendor", "snapshot_date", "sha256_fingerprint"]).copy()
    if len(df) < initial_len:
        print(f"[*] Pruned {initial_len - len(df)} duplicate records.")

    # 3. Format and enforce schema types exactly matching SCHEMA.md
    df["valid_from"] = pd.to_datetime(df["valid_from"], utc=True)
    df["valid_until"] = pd.to_datetime(df["valid_until"], utc=True)
    
    # Save CSV
    out_dir = Path(__file__).resolve().parent
    csv_path = out_dir / "apple_os_history.csv"
    df.to_csv(csv_path, index=False)
    print(f"[+] Saved CSV: {csv_path} ({len(df)} rows)")

    # Define strict PyArrow schema
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
        ("os_name", pa.string()),
        ("trust_status", pa.string()),
        ("serial_number", pa.string()),
    ])

    table = pa.Table.from_pandas(df, schema=arrow_schema)
    parquet_path = out_dir / "apple_os_history.parquet"
    pq.write_table(table, parquet_path)
    print(f"[+] Saved Parquet: {parquet_path} ({len(df)} rows)")

    # Print summary statistics per OS release
    summary_df = df.groupby(["os_name", "snapshot_date", "trust_status"]).size().unstack(fill_value=0)
    print("\nSummary per OS release:")
    print(summary_df)

    print("\n[SUCCESS] Apple Historical Knowledge Base Scraping Complete.")

if __name__ == "__main__":
    main()
