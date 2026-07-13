#!/usr/bin/env bash
#
# Smoke test for the nvd2sqlite-cvelistV5 tool.
#
# Builds the binary, generates a small fixture zip of CVE JSON 5.x records,
# runs the tool against it with --input (no network), and asserts the resulting
# SQLite database has the expected contents. Exits non-zero on any failure.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

BIN="$WORK_DIR/nvd2sqlite-cvelistV5"
ZIP="$WORK_DIR/baseline.zip"
DB="$WORK_DIR/cve.sqlite"
CVES_DIR="$WORK_DIR/cves/2024/1xxx"

echo "==> Building binary"
( cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/nvd2sqlite-cvelistV5 )

echo "==> Generating fixture CVE records"
mkdir -p "$CVES_DIR"

cat > "$CVES_DIR/CVE-2024-0001.json" <<'JSON'
{
  "cveMetadata": {"cveId":"CVE-2024-0001","state":"PUBLISHED","datePublished":"2024-05-01T00:00:00.000Z","dateUpdated":"2024-06-01T00:00:00.000Z"},
  "containers": {"cna": {
    "descriptions": [{"lang":"en","value":"nginx flaw"}],
    "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L"}}],
    "references": [{"url":"https://nginx.example/1"}],
    "affected": [{"vendor":"F5","product":"nginx","versions":[{"version":"1.20.0","status":"affected","lessThan":"1.20.2"}]}]
  }}
}
JSON

cat > "$CVES_DIR/CVE-2024-0002.json" <<'JSON'
{
  "cveMetadata": {"cveId":"CVE-2024-0002","state":"PUBLISHED","datePublished":"2024-05-02T00:00:00.000Z","dateUpdated":"2024-05-02T00:00:00.000Z"},
  "containers": {"cna": {
    "descriptions": [{"lang":"en","value":"openssl issue"}],
    "metrics": [{"cvssV2_0": {"baseScore": 10.0, "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}}],
    "affected": [{"vendor":"OpenSSL","product":"OpenSSL","versions":[{"version":"0","status":"affected","lessThanOrEqual":"3.0.1"}]}]
  }}
}
JSON

# A rejected record (must be skipped) and a malformed one (must not crash).
cat > "$CVES_DIR/CVE-2024-0003.json" <<'JSON'
{"cveMetadata": {"cveId":"CVE-2024-0003","state":"REJECTED"}}
JSON
echo '{not valid json' > "$CVES_DIR/CVE-2024-0004.json"

echo "==> Building fixture zip"
( cd "$WORK_DIR" && zip -q -r "$ZIP" cves )

echo "==> Running tool"
"$BIN" --input "$ZIP" --output "$DB"

echo "==> Asserting results"
fail() { echo "SMOKE FAIL: $1" >&2; exit 1; }

[ -f "$DB" ] || fail "database not created"

if command -v sqlite3 >/dev/null 2>&1; then
  cve_count="$(sqlite3 "$DB" 'SELECT COUNT(*) FROM cves;')"
  [ "$cve_count" = "2" ] || fail "expected 2 CVEs, got $cve_count"

  rejected="$(sqlite3 "$DB" "SELECT COUNT(*) FROM cves WHERE cve_id='CVE-2024-0003';")"
  [ "$rejected" = "0" ] || fail "rejected CVE present"

  sev="$(sqlite3 "$DB" "SELECT severity FROM cves WHERE cve_id='CVE-2024-0001';")"
  [ "$sev" = "HIGH" ] || fail "expected HIGH severity, got $sev"

  vendor="$(sqlite3 "$DB" "SELECT vendor FROM affected_products WHERE cve_id='CVE-2024-0001';")"
  [ "$vendor" = "f5" ] || fail "expected lowercased vendor f5, got $vendor"

  aliases="$(sqlite3 "$DB" 'SELECT COUNT(*) FROM package_aliases;')"
  [ "$aliases" -gt 0 ] || fail "no package aliases"

  echo "==> sqlite3 assertions passed (2 CVEs, aliases=$aliases)"
else
  echo "==> sqlite3 not found; verified DB file exists only"
fi

echo "SMOKE OK"
