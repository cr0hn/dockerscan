# nvd2sqlite - NVD API to SQLite Converter

A command-line tool that downloads CVE data from the NVD API 2.0 and stores it in an SQLite database for offline vulnerability scanning.

## Features

- **NVD API 2.0 Integration**: Downloads CVE data from the official NIST National Vulnerability Database
- **Automatic Pagination**: Handles large datasets with automatic pagination (2000 CVEs per request)
- **Rate Limiting**: Respects NVD API rate limits (5 req/30s without API key, 50 req/30s with key)
- **Date Range Chunking**: Automatically splits large date ranges into 120-day chunks (NVD API limitation)
- **Complete CVE Data**: Extracts descriptions, severity, CVSS v3 scores, references, and affected products
- **CPE Parsing**: Parses CPE 2.3 format to extract vendor, product, and version ranges
- **Package Aliases**: Includes 63+ predefined mappings between NVD vendor/product names and dpkg/apk package names
- **Optimized Database**: Includes indexes for fast vulnerability lookups

## Installation

```bash
# Build from source
cd cmd/nvd2sqlite
go build -o nvd2sqlite

# Or from the root of the project
go build -o bin/nvd2sqlite ./cmd/nvd2sqlite/
```

## Usage

### Basic Usage

Download CVEs from the last 5 years (default):

```bash
nvd2sqlite --output cve-db.sqlite
```

### Specify Date Range

Download CVEs for a specific date range:

```bash
nvd2sqlite --output cve-db.sqlite \
  --start-date 2024-01-01 \
  --end-date 2024-12-31
```

### With NVD API Key

Using an API key increases the rate limit from 5 to 50 requests per 30 seconds:

```bash
# Via command-line flag
nvd2sqlite --output cve-db.sqlite --api-key YOUR_API_KEY

# Or via environment variable
export NVD_API_KEY=YOUR_API_KEY
nvd2sqlite --output cve-db.sqlite
```

Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key

### Verbose Output

See detailed progress information:

```bash
nvd2sqlite --output cve-db.sqlite --verbose
```

## Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--output` | Output SQLite file path (required) | - |
| `--start-date` | Start date for CVEs (YYYY-MM-DD) | 5 years ago |
| `--end-date` | End date for CVEs (YYYY-MM-DD) | Now |
| `--api-key` | NVD API key (also reads from `NVD_API_KEY` env var) | - |
| `--rate-limit` | Requests per 30 seconds | 5 (50 with API key) |
| `--verbose` | Verbose output | false |

## Database Schema

The generated SQLite database contains four tables:

### `cves` Table

Stores CVE information:

| Column | Type | Description |
|--------|------|-------------|
| `cve_id` | TEXT | CVE identifier (e.g., CVE-2024-1234) |
| `description` | TEXT | English description of the vulnerability |
| `severity` | TEXT | CVSS v3 severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN) |
| `cvss_v3_score` | REAL | CVSS v3 base score (0.0-10.0) |
| `cvss_v3_vector` | TEXT | CVSS v3 vector string |
| `published_date` | TEXT | Publication date (ISO-8601) |
| `modified_date` | TEXT | Last modification date (ISO-8601) |
| `references_json` | TEXT | JSON array of reference URLs |

### `affected_products` Table

Stores affected vendor/product combinations with version ranges:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-increment ID |
| `cve_id` | TEXT | Foreign key to `cves.cve_id` |
| `vendor` | TEXT | Vendor name from CPE (e.g., "openssl") |
| `product` | TEXT | Product name from CPE (e.g., "openssl") |
| `version_start` | TEXT | Starting version (if specified) |
| `version_end` | TEXT | Ending version (if specified) |
| `version_start_type` | TEXT | "including" or "excluding" |
| `version_end_type` | TEXT | "including" or "excluding" |

### `package_aliases` Table

Maps NVD vendor/product names to package manager package names:

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-increment ID |
| `vendor` | TEXT | NVD vendor name |
| `product` | TEXT | NVD product name |
| `package_name` | TEXT | Package manager package name |
| `package_source` | TEXT | Package manager ("dpkg", "apk", "all") |

**Examples**:
- `openssl` + `openssl` → `libssl3` (dpkg)
- `gnu` + `glibc` → `libc6` (dpkg)
- `docker` + `docker` → `docker-ce` (dpkg)

### `metadata` Table

Stores database metadata:

| Column | Type | Description |
|--------|------|-------------|
| `key` | TEXT | Metadata key |
| `value` | TEXT | Metadata value |

**Keys**:
- `version`: Database format version
- `created_at`: Creation timestamp
- `nvd_source`: Source API version
- `total_cves`: Total number of CVEs
- `schema_version`: Schema version

## Example Queries

### Find all CVEs for a vendor/product

```sql
SELECT c.cve_id, c.severity, c.cvss_v3_score, c.description
FROM cves c
JOIN affected_products ap ON c.cve_id = ap.cve_id
WHERE ap.vendor = 'openssl' AND ap.product = 'openssl'
ORDER BY c.cvss_v3_score DESC;
```

### Find CVEs for a package name

```sql
SELECT DISTINCT c.cve_id, c.severity, c.cvss_v3_score
FROM cves c
JOIN affected_products ap ON c.cve_id = ap.cve_id
JOIN package_aliases pa ON ap.vendor = pa.vendor AND ap.product = pa.product
WHERE pa.package_name = 'libssl3' AND pa.package_source = 'dpkg'
ORDER BY c.cvss_v3_score DESC;
```

### Get CVE statistics by severity

```sql
SELECT severity, COUNT(*) as count
FROM cves
GROUP BY severity
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 4
    ELSE 5
  END;
```

## GitHub Actions Integration

This tool is designed to be run by GitHub Actions every 6 hours to keep the CVE database up-to-date.

Example workflow:

```yaml
name: Update CVE Database

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:  # Manual trigger

jobs:
  update-cve-db:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Build nvd2sqlite
        run: go build -o nvd2sqlite ./cmd/nvd2sqlite/

      - name: Download CVEs
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: |
          ./nvd2sqlite --output cve-db.sqlite --verbose

      - name: Upload database artifact
        uses: actions/upload-artifact@v4
        with:
          name: cve-database
          path: cve-db.sqlite
          retention-days: 30
```

## Performance

- **Speed**: Downloads and processes ~2000 CVEs per request
- **Rate Limiting**: Automatic rate limiting ensures compliance with NVD API limits
- **Database Size**: Approximately 150-200 MB for 5 years of CVE data
- **Build Time**: ~5-15 minutes for full 5-year download (depending on API key)

## Predefined Package Aliases

The tool includes 63+ predefined mappings for common packages:

**Security Libraries**:
- OpenSSL (openssl, libssl1.0.0, libssl1.1, libssl3)
- glibc (libc6, musl)

**Core Tools**:
- bash, curl, openssh, sudo, git

**Container Runtime**:
- Docker (docker-ce, docker.io)
- containerd, runc

**Languages**:
- Python (python3, python3.8-3.12)
- Node.js (nodejs)
- Java (openjdk-11-jre, openjdk-17-jre)
- Perl

**Databases**:
- PostgreSQL (postgresql, postgresql-client)
- MySQL/MariaDB (mysql-server, mariadb-server)
- Redis (redis-server, redis)

**Web Servers**:
- Apache (apache2, apache2-bin)
- nginx (nginx, nginx-common)

And many more...

## Troubleshooting

### Rate Limit Errors

If you encounter rate limit errors, try:
1. Get a free NVD API key (increases limit from 5 to 50 req/30s)
2. Reduce the `--rate-limit` value
3. Split your date range into smaller chunks

### Empty Database

If the database has no CVEs:
- Check your internet connection
- Verify the NVD API is accessible: https://services.nvd.nist.gov/
- Check your date range (use `--verbose` to see progress)

### Out of Memory

For very large date ranges:
- The tool processes CVEs in chunks, so memory usage should be reasonable
- Try reducing the date range if you encounter issues

## License

Part of DockerScan v2.0 - See main LICENSE file for details.

## Author

Daniel Garcia (cr0hn) - https://cr0hn.com

## References

- NVD API Documentation: https://nvd.nist.gov/developers
- NVD Data Feeds: https://nvd.nist.gov/vuln/data-feeds
- CPE Specification: https://csrc.nist.gov/publications/detail/nistir/7695/final
- CVSS v3 Specification: https://www.first.org/cvss/v3.0/specification-document
