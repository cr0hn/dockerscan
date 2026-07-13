package cvedb

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// insertCVE adds a minimal cves row.
func insertCVE(t *testing.T, db *sql.DB, id, severity string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO cves (cve_id, description, severity, cvss_v3_score, cvss_v3_vector, published_date, modified_date, references_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "desc", severity, 7.5, "", "2024-01-01T00:00:00.000", "2024-01-01T00:00:00.000", "[]")
	if err != nil {
		t.Fatalf("insert cve: %v", err)
	}
}

func insertProduct(t *testing.T, db *sql.DB, cveID, vendor, product, vStart, vEnd, sType, eType string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO affected_products (cve_id, vendor, product, version_start, version_end, version_start_type, version_end_type)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, cveID, vendor, product, vStart, vEnd, sType, eType)
	if err != nil {
		t.Fatalf("insert product: %v", err)
	}
}

func insertAlias(t *testing.T, db *sql.DB, vendor, product, pkgName, source string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO package_aliases (vendor, product, package_name, package_source) VALUES (?, ?, ?, ?)`,
		vendor, product, pkgName, source)
	if err != nil {
		t.Fatalf("insert alias: %v", err)
	}
}

// openRaw reopens the fixture DB for direct inserts.
func openRaw(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	return raw
}

// TestQueryByPackage_MultiProductIsolation verifies ranges come ONLY from the
// affected product matched by the package's aliases, not from unrelated
// products of the same CVE.
func TestQueryByPackage_MultiProductIsolation(t *testing.T) {
	dbPath := createTestDB(t, map[string]string{"schema_version": "2"})
	raw := openRaw(t, dbPath)
	insertCVE(t, raw, "CVE-2024-1", "HIGH")
	insertProduct(t, raw, "CVE-2024-1", "openssl", "openssl", "1.0", "2.0", "including", "excluding")
	insertProduct(t, raw, "CVE-2024-1", "other", "unrelated", "5.0", "6.0", "including", "excluding")
	raw.Close()

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	cves, err := db.QueryByPackage("openssl", "dpkg")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs, want 1", len(cves))
	}
	if len(cves[0].Products) != 1 {
		t.Fatalf("got %d products, want 1 (only matched product)", len(cves[0].Products))
	}
	if cves[0].Products[0].Product != "openssl" {
		t.Errorf("matched product = %q, want openssl", cves[0].Products[0].Product)
	}
}

// TestQueryByPackage_MultiRangeAccumulation verifies multiple ranges of the
// same product accumulate into one product group.
func TestQueryByPackage_MultiRangeAccumulation(t *testing.T) {
	dbPath := createTestDB(t, map[string]string{"schema_version": "2"})
	raw := openRaw(t, dbPath)
	insertCVE(t, raw, "CVE-2024-2", "HIGH")
	insertProduct(t, raw, "CVE-2024-2", "openssl", "openssl", "1.0", "1.5", "including", "excluding")
	insertProduct(t, raw, "CVE-2024-2", "openssl", "openssl", "2.0", "2.5", "including", "excluding")
	raw.Close()

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	cves, err := db.QueryByPackage("openssl", "dpkg")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(cves) != 1 || len(cves[0].Products) != 1 {
		t.Fatalf("unexpected shape: %d cves", len(cves))
	}
	if len(cves[0].Products[0].Ranges) != 2 {
		t.Fatalf("got %d ranges, want 2", len(cves[0].Products[0].Ranges))
	}
}

// TestQueryByPackage_AliasPath verifies matching through the package_aliases
// table for a product name not directly among the package aliases.
func TestQueryByPackage_AliasPath(t *testing.T) {
	dbPath := createTestDB(t, map[string]string{"schema_version": "2"})
	raw := openRaw(t, dbPath)
	insertCVE(t, raw, "CVE-2024-3", "HIGH")
	// Product name reachable only via the alias table (not an openssl alias).
	insertProduct(t, raw, "CVE-2024-3", "acme", "acme_crypto", "1.0", "2.0", "including", "excluding")
	insertAlias(t, raw, "acme", "acme_crypto", "openssl", "dpkg")
	raw.Close()

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	cves, err := db.QueryByPackage("openssl", "dpkg")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(cves) != 1 {
		t.Fatalf("got %d CVEs via alias path, want 1", len(cves))
	}

	// Wrong source must not match a dpkg-only alias.
	cvesApk, err := db.QueryByPackage("openssl", "apk")
	if err != nil {
		t.Fatalf("query apk: %v", err)
	}
	if len(cvesApk) != 0 {
		t.Errorf("dpkg-only alias should not match apk source, got %d", len(cvesApk))
	}
}

// TestQueryByPackage_AliasSourceAll verifies "all"-source aliases match any
// package source.
func TestQueryByPackage_AliasSourceAll(t *testing.T) {
	dbPath := createTestDB(t, map[string]string{"schema_version": "2"})
	raw := openRaw(t, dbPath)
	insertCVE(t, raw, "CVE-2024-4", "HIGH")
	insertProduct(t, raw, "CVE-2024-4", "acme", "acme_crypto", "1.0", "2.0", "including", "excluding")
	insertAlias(t, raw, "acme", "acme_crypto", "openssl", "all")
	raw.Close()

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	for _, src := range []string{"dpkg", "apk"} {
		cves, err := db.QueryByPackage("openssl", src)
		if err != nil {
			t.Fatalf("query %s: %v", src, err)
		}
		if len(cves) != 1 {
			t.Errorf("all-source alias should match %s, got %d CVEs", src, len(cves))
		}
	}
}

// TestQueryByPackage_SchemaGate verifies the C4 gate: a Start-only/including
// row is an open ">=X" range on schema v2, but an exact [X,X] match on a legacy
// (v1) schema.
func TestQueryByPackage_SchemaGate(t *testing.T) {
	build := func(schema string) CVEEntry {
		dbPath := createTestDB(t, map[string]string{"schema_version": schema})
		raw := openRaw(t, dbPath)
		insertCVE(t, raw, "CVE-2024-5", "HIGH")
		// Start-only/including, no end bound.
		insertProduct(t, raw, "CVE-2024-5", "openssl", "openssl", "2.0", "", "including", "")
		raw.Close()

		db, err := Open(dbPath)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer db.Close()

		cves, err := db.QueryByPackage("openssl", "dpkg")
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(cves) != 1 || len(cves[0].Products) != 1 || len(cves[0].Products[0].Ranges) != 1 {
			t.Fatalf("unexpected shape for schema %s: %+v", schema, cves)
		}
		return cves[0]
	}

	v2 := build("2")
	r2 := v2.Products[0].Ranges[0]
	if r2.End != "" {
		t.Errorf("schema v2: expected open range (End empty), got End=%q", r2.End)
	}

	v1 := build("1")
	r1 := v1.Products[0].Ranges[0]
	if r1.End != "2.0" || r1.EndType != "including" {
		t.Errorf("schema v1: expected exact [2.0,2.0], got End=%q/%q", r1.End, r1.EndType)
	}
}
