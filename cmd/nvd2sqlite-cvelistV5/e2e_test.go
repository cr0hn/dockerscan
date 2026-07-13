package main

import (
	"archive/zip"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// fixtureFiles maps archive paths to CVE JSON 5.x contents. It intentionally
// includes a rejected record, a malformed record, and a record with version
// ranges to exercise the full pipeline.
var fixtureFiles = map[string]string{
	"cves/2024/1xxx/CVE-2024-0001.json": `{
		"cveMetadata": {"cveId":"CVE-2024-0001","state":"PUBLISHED","datePublished":"2024-05-01T00:00:00.000Z","dateUpdated":"2024-06-01T00:00:00.000Z"},
		"containers": {"cna": {
			"descriptions": [{"lang":"en","value":"nginx flaw"}],
			"metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L"}}],
			"references": [{"url":"https://nginx.example/1"}],
			"affected": [{"vendor":"F5","product":"nginx","versions":[{"version":"1.20.0","status":"affected","lessThan":"1.20.2"}]}]
		}}
	}`,
	"cves/2024/1xxx/CVE-2024-0002.json": `{
		"cveMetadata": {"cveId":"CVE-2024-0002","state":"PUBLISHED","datePublished":"2024-05-02T00:00:00.000Z","dateUpdated":"2024-05-02T00:00:00.000Z"},
		"containers": {"cna": {
			"descriptions": [{"lang":"en","value":"openssl issue"}],
			"metrics": [{"cvssV2_0": {"baseScore": 10.0, "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}}],
			"affected": [{"vendor":"OpenSSL","product":"OpenSSL","versions":[{"version":"0","status":"affected","lessThanOrEqual":"3.0.1"}]}]
		}}
	}`,
	"cves/2024/1xxx/CVE-2024-0003-rejected.json": `{
		"cveMetadata": {"cveId":"CVE-2024-0003","state":"REJECTED"}
	}`,
	"cves/2024/1xxx/CVE-2024-0004-malformed.json": `{not valid json`,
	"cves/2024/1xxx/CVE-2024-0005.json": `{
		"cveMetadata": {"cveId":"CVE-2024-0005","state":"PUBLISHED","datePublished":"2024-05-05T00:00:00.000Z","dateUpdated":"2024-05-05T00:00:00.000Z"},
		"containers": {"cna": {
			"descriptions": [{"lang":"en","value":"no version info"}],
			"affected": [{"vendor":"Acme","product":"Gadget"}]
		}}
	}`,
}

func writeFixtureZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
}

// writeNestedFixtureZip creates an outer zip containing a single inner zip (the
// .zip.zip layout).
func writeNestedFixtureZip(t *testing.T, outerPath string, files map[string]string) {
	t.Helper()
	inner := filepath.Join(t.TempDir(), "inner.zip")
	writeFixtureZip(t, inner, files)

	innerData, err := os.ReadFile(inner)
	if err != nil {
		t.Fatalf("read inner: %v", err)
	}

	f, err := os.Create(outerPath)
	if err != nil {
		t.Fatalf("create outer: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create("all_CVEs.zip")
	if err != nil {
		t.Fatalf("create inner entry: %v", err)
	}
	if _, err := w.Write(innerData); err != nil {
		t.Fatalf("write inner entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close outer: %v", err)
	}
}

func runPipeline(t *testing.T, zipPath, dbPath string) {
	t.Helper()
	cfg := config{
		outputPath: dbPath,
		start:      time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		end:        time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		inputPath:  zipPath,
		verbose:    false,
	}
	if err := run(cfg); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestE2E_FlatZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "baseline.zip")
	dbPath := filepath.Join(dir, "cve.sqlite")
	writeFixtureZip(t, zipPath, fixtureFiles)

	runPipeline(t, zipPath, dbPath)
	assertDatabase(t, dbPath)
}

func TestE2E_NestedZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "baseline.zip.zip")
	dbPath := filepath.Join(dir, "cve.sqlite")
	writeNestedFixtureZip(t, zipPath, fixtureFiles)

	runPipeline(t, zipPath, dbPath)
	assertDatabase(t, dbPath)
}

func assertDatabase(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// 3 published, in-range CVEs (0001, 0002, 0005). Rejected & malformed skipped.
	var cveCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM cves").Scan(&cveCount); err != nil {
		t.Fatalf("count cves: %v", err)
	}
	if cveCount != 3 {
		t.Errorf("cve count = %d, want 3", cveCount)
	}

	// Rejected must not be present.
	var rejected int
	db.QueryRow("SELECT COUNT(*) FROM cves WHERE cve_id = 'CVE-2024-0003'").Scan(&rejected)
	if rejected != 0 {
		t.Errorf("rejected CVE present")
	}

	// Verify nginx CVE mapping.
	var severity, vstart, vend, vstype, vetype string
	var score float64
	err = db.QueryRow(`
		SELECT c.severity, c.cvss_v3_score, ap.version_start, ap.version_end, ap.version_start_type, ap.version_end_type
		FROM cves c JOIN affected_products ap ON c.cve_id = ap.cve_id
		WHERE c.cve_id = 'CVE-2024-0001'`).Scan(&severity, &score, &vstart, &vend, &vstype, &vetype)
	if err != nil {
		t.Fatalf("query nginx: %v", err)
	}
	if severity != "HIGH" || score != 7.5 {
		t.Errorf("nginx severity/score = %q/%v", severity, score)
	}
	if vstart != "1.20.0" || vstype != "including" || vend != "1.20.2" || vetype != "excluding" {
		t.Errorf("nginx range = %q/%q..%q/%q", vstart, vstype, vend, vetype)
	}

	// Verify lowercased vendor/product.
	var vendor, product string
	db.QueryRow("SELECT vendor, product FROM affected_products WHERE cve_id = 'CVE-2024-0001'").Scan(&vendor, &product)
	if vendor != "f5" || product != "nginx" {
		t.Errorf("vendor/product = %q/%q, want lowercase", vendor, product)
	}

	// openssl CVE: v2 score 10.0 -> HIGH (no CRITICAL for v2), unbounded start.
	var osslSev string
	var osslStart, osslEnd, osslEndType string
	err = db.QueryRow(`
		SELECT c.severity, ap.version_start, ap.version_end, ap.version_end_type
		FROM cves c JOIN affected_products ap ON c.cve_id = ap.cve_id
		WHERE c.cve_id = 'CVE-2024-0002'`).Scan(&osslSev, &osslStart, &osslEnd, &osslEndType)
	if err != nil {
		t.Fatalf("query openssl: %v", err)
	}
	if osslSev != "HIGH" {
		t.Errorf("openssl severity = %q, want HIGH", osslSev)
	}
	if osslStart != "" || osslEnd != "3.0.1" || osslEndType != "including" {
		t.Errorf("openssl range = %q..%q/%q", osslStart, osslEnd, osslEndType)
	}

	// CVE-2024-0005 has no version info: expect a bare product row.
	var bareCount int
	db.QueryRow("SELECT COUNT(*) FROM affected_products WHERE cve_id = 'CVE-2024-0005'").Scan(&bareCount)
	if bareCount != 1 {
		t.Errorf("bare product rows = %d, want 1", bareCount)
	}

	// Published date normalized to NVD no-tz millis format.
	var pub string
	db.QueryRow("SELECT published_date FROM cves WHERE cve_id = 'CVE-2024-0001'").Scan(&pub)
	if pub != "2024-05-01T00:00:00.000" {
		t.Errorf("published_date = %q", pub)
	}

	// Aliases present.
	var aliasCount int
	db.QueryRow("SELECT COUNT(*) FROM package_aliases").Scan(&aliasCount)
	if aliasCount == 0 {
		t.Error("no package aliases inserted")
	}

	// Metadata: total_cves and schema_version.
	var totalCVEs, schemaVersion string
	db.QueryRow("SELECT value FROM metadata WHERE key = 'total_cves'").Scan(&totalCVEs)
	db.QueryRow("SELECT value FROM metadata WHERE key = 'schema_version'").Scan(&schemaVersion)
	if totalCVEs != "3" {
		t.Errorf("metadata total_cves = %q, want 3", totalCVEs)
	}
	if schemaVersion != "2" {
		t.Errorf("metadata schema_version = %q, want 2", schemaVersion)
	}
}
