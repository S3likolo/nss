# Web PKI Root Store Historical Schema

## 1. Overview & Purpose
This document defines the **Single Source of Truth (SSOT)** for the data schema used to record, normalize, and analyze the historical availability and trust status of Root CA certificates across the four major Web PKI root store vendors:
- **Mozilla** (NSS built-in root store)
- **Google** (Chrome Root Store / Chromium)
- **Apple** (macOS / iOS Trust Store)
- **Microsoft** (Trusted Root Certification Authorities / AuthRoot STL)

The schema is optimized for analytical querying via **DuckDB** and persistent columnar storage via **Apache Parquet**.

---

## 2. Target Column Specification

| Column Name | DuckDB Type | Parquet / Arrow Type | Nullable | Description | Example |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `vendor` | `VARCHAR` | `string` | **No** | Identifier of the root store vendor (`mozilla`, `google`, `apple`, `microsoft`). | `"mozilla"` |
| `snapshot_date` | `DATE` | `date32` | **No** | Temporal snapshot date in ISO 8601 format (`YYYY-MM-DD`). | `2024-01-15` |
| `sha256_fingerprint` | `VARCHAR` | `string` | **No** | 64-character lowercase hexadecimal SHA-256 digest of the DER-encoded certificate. | `"ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99"` |
| `subject_dn` | `VARCHAR` | `string` | **No** | RFC 4514 Distinguished Name (DN) string representing the certificate subject. | `"CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE"` |
| `valid_from` | `TIMESTAMP_TZ` | `timestamp[us, tz=UTC]` | **No** | Certificate validity start timestamp (`notBefore`) in UTC. | `1998-09-01 12:00:00+00` |
| `valid_until` | `TIMESTAMP_TZ` | `timestamp[us, tz=UTC]` | **No** | Certificate validity end timestamp (`notAfter`) in UTC. | `2028-01-28 12:00:00+00` |
| `trust_bits` | `VARCHAR` | `string` | Yes | Comma-separated list of standardized trust purposes granted to the root. | `"serverAuth,emailProtection,codeSigning"` |
| `data_source_type` | `VARCHAR` | `string` | **No** | Origin mechanism used to extract the snapshot. | `"git_commit"` |
| `provenance_url_or_hash` | `VARCHAR` | `string` | **No** | Full Git commit SHA, Wayback Machine archive URL, or STL download source. | `"fc168131f829f074d2b271d4976c66cf134bbcd2"` |

---

## 3. Standardization & Normalization Rules

### 3.1. `vendor`
Must be strictly lowercase string and one of the following enumerated values:
- `mozilla`
- `google`
- `apple`
- `microsoft`

### 3.2. `snapshot_date`
- Formatted as `YYYY-MM-DD`.
- For Git-backed sources, this is the author/commit date of the Git changeset in UTC.
- For Wayback Machine snapshots, this is the capture date extracted from the timestamp (`YYYYMMDDhhmmss`).
- For binary CTL/STL sources, this is the `EffectiveDate` or publication timestamp.

### 3.3. `sha256_fingerprint`
- Computed as `SHA-256(DER_BYTES)`.
- Normalized to **64 lowercase hexadecimal characters** without delimiters (no colons, spaces, or hyphens).
- Regular expression: `^[0-9a-f]{64}$`.

### 3.4. `subject_dn`
- Converted according to **RFC 4514** standard format (e.g. via `cryptography.x509.Name.rfc4514_string()` or normalized string representation from `asn1crypto`).
- Attribute components ordered consistently (e.g., `CN=...,O=...,C=...`).

### 3.5. `valid_from` & `valid_until`
- Extracted directly from the X.509 `Validity` sequence (`notBefore` and `notAfter`).
- Stored as timezone-aware UTC timestamps (`TIMESTAMP WITH TIME ZONE`).

### 3.6. `trust_bits`
Normalized comma-separated string of trusted key purposes. Standardized identifiers:
- `serverAuth`: TLS / Web PKI HTTPS Server Authentication (e.g., OID `1.3.6.1.5.5.7.3.1`, Mozilla `CKA_TRUST_SERVER_AUTH=CKT_NSS_TRUSTED_DELEGATOR`).
- `emailProtection`: S/MIME Secure Email (e.g., OID `1.3.6.1.5.5.7.3.4`, Mozilla `CKA_TRUST_EMAIL_PROTECTION=CKT_NSS_TRUSTED_DELEGATOR`).
- `codeSigning`: Software / Code Signing (e.g., OID `1.3.6.1.5.5.7.3.3`, Mozilla `CKA_TRUST_CODE_SIGNING=CKT_NSS_TRUSTED_DELEGATOR`).
- `timeStamping`: RFC 3161 Timestamping (e.g., OID `1.3.6.1.5.5.7.3.8`).
- If no explicit trust bits are enabled or trust is restricted/distrusted, the value is an empty string `""`.

### 3.7. `data_source_type`
Must be one of:
- `git_commit`: Sourced from a Git repository history (e.g. Mozilla NSS, Google Chrome).
- `wayback_html`: Scraped from archived vendor web pages via the Internet Archive Wayback Machine.
- `stl_binary`: Extracted from Microsoft Certificate Trust List (`authroot.stl`) binary files.

### 3.8. `provenance_url_or_hash`
Provides end-to-end auditability and provenance tracking:
- For `git_commit`: Full 40-character Git commit hash (e.g. `fc168131f829f074d2b271d4976c66cf134bbcd2`).
- For `wayback_html`: Complete archive URL (e.g. `https://web.archive.org/web/20180601...`).
- For `stl_binary`: URL or cryptographic SHA-256 digest of the downloaded `.stl` catalog file.

---

## 4. DuckDB DDL Specification

```sql
CREATE TABLE IF NOT EXISTS root_store_snapshots (
    vendor                  VARCHAR NOT NULL,
    snapshot_date           DATE NOT NULL,
    sha256_fingerprint      VARCHAR(64) NOT NULL,
    subject_dn              VARCHAR NOT NULL,
    valid_from              TIMESTAMPTZ NOT NULL,
    valid_until             TIMESTAMPTZ NOT NULL,
    trust_bits              VARCHAR,
    data_source_type        VARCHAR NOT NULL,
    provenance_url_or_hash  VARCHAR NOT NULL,
    PRIMARY KEY (vendor, snapshot_date, sha256_fingerprint)
);

-- Recommended analytical indices
CREATE INDEX IF NOT EXISTS idx_root_store_lookup 
    ON root_store_snapshots (vendor, snapshot_date);

CREATE INDEX IF NOT EXISTS idx_root_store_cert 
    ON root_store_snapshots (sha256_fingerprint);
```

---

## 5. Storage and Directory Conventions

- **`data/raw/`**: Raw extractor outputs per vendor before cross-vendor joining or aggregation (e.g., `data/raw/mozilla_history.parquet`).
- **`data/normalized/`**: Consolidated, unified Parquet dataset (e.g., `data/normalized/root_store_snapshots.parquet` or partitioned by `vendor=<vendor>/year=<year>`).
- **`extractors/`**: Python extraction modules for each vendor (`mozilla.py`, `google.py`, `apple.py`, `microsoft.py`).
- **`analysis/`**: Analytical SQL scripts, DuckDB queries, Jupyter notebooks, and metric reporting.
