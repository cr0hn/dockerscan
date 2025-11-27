# CVE Database

This directory contains the pre-built CVE database for DockerScan.

## Files

- `latest.db.gz` - Compressed SQLite database with CVE data
- `latest.db.gz.sha256` - SHA256 checksum for verification
- `metadata.json` - Database version and statistics

## Usage

DockerScan automatically downloads this database when you run:

```bash
dockerscan update-db
```

## Updates

The database is automatically updated every 6 hours via GitHub Actions.
See `.github/workflows/update-cve-db.yml` for details.

## Manual Generation

To generate the database manually:

```bash
# Build the tool
go build -o bin/nvd2sqlite ./cmd/nvd2sqlite

# Download CVEs (last 5 years)
./bin/nvd2sqlite --output data/cve-db.sqlite --verbose

# With NVD API key (faster)
NVD_API_KEY=your-key ./bin/nvd2sqlite --output data/cve-db.sqlite --verbose
```
