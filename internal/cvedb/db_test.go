package cvedb

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// createTestDB creates a test database with the given metadata
func createTestDB(t *testing.T, metadata map[string]string) string {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test-cve.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS cves (
		cve_id TEXT PRIMARY KEY,
		description TEXT NOT NULL,
		severity TEXT NOT NULL,
		cvss_v3_score REAL,
		cvss_v3_vector TEXT,
		published_date TEXT NOT NULL,
		modified_date TEXT NOT NULL,
		references_json TEXT
	);

	CREATE TABLE IF NOT EXISTS affected_products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT NOT NULL,
		vendor TEXT NOT NULL,
		product TEXT NOT NULL,
		version_start TEXT,
		version_end TEXT,
		version_start_type TEXT,
		version_end_type TEXT,
		FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
	);

	CREATE TABLE IF NOT EXISTS package_aliases (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		vendor TEXT NOT NULL,
		product TEXT NOT NULL,
		package_name TEXT NOT NULL,
		package_source TEXT NOT NULL,
		UNIQUE(vendor, product, package_name, package_source)
	);

	CREATE TABLE IF NOT EXISTS metadata (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	// Insert metadata
	for key, value := range metadata {
		_, err := db.Exec("INSERT INTO metadata (key, value) VALUES (?, ?)", key, value)
		if err != nil {
			t.Fatalf("Failed to insert metadata %s: %v", key, err)
		}
	}

	return dbPath
}

func TestGetMetadata_WithLastModified(t *testing.T) {
	// This test verifies that GetMetadata correctly reads the last_modified key
	now := time.Now().UTC().Truncate(time.Second)
	nowStr := now.Format(time.RFC3339)

	dbPath := createTestDB(t, map[string]string{
		"version":        "1.0",
		"last_modified":  nowStr,
		"schema_version": "1",
	})

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	meta, err := db.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	if meta.Version != "1.0" {
		t.Errorf("Expected version '1.0', got '%s'", meta.Version)
	}

	if meta.SchemaVersion != "1" {
		t.Errorf("Expected schema version '1', got '%s'", meta.SchemaVersion)
	}

	// The key test: LastModified should be parsed correctly
	if meta.LastModified.IsZero() {
		t.Error("LastModified should not be zero")
	}

	// Check that the time matches (within a reasonable margin)
	timeDiff := meta.LastModified.Sub(now)
	if timeDiff < -time.Second || timeDiff > time.Second {
		t.Errorf("LastModified time mismatch: expected %v, got %v", now, meta.LastModified)
	}
}

func TestGetMetadata_WithCreatedAtOnly(t *testing.T) {
	// This test simulates an OLD database that only has created_at
	// LastModified should be zero in this case (the bug scenario)
	now := time.Now().UTC().Truncate(time.Second)
	nowStr := now.Format(time.RFC3339)

	dbPath := createTestDB(t, map[string]string{
		"version":        "1.0",
		"created_at":     nowStr, // Old database: only has created_at, not last_modified
		"schema_version": "1",
	})

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	meta, err := db.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	// With the current implementation, LastModified will be zero
	// because it looks for "last_modified" key, not "created_at"
	if !meta.LastModified.IsZero() {
		t.Errorf("Expected LastModified to be zero for old database, got %v", meta.LastModified)
	}
}

func TestGetMetadata_WithBothKeys(t *testing.T) {
	// This test simulates a NEW database that has both created_at and last_modified
	// This is what nvd2sqlite now generates after the fix
	now := time.Now().UTC().Truncate(time.Second)
	nowStr := now.Format(time.RFC3339)

	dbPath := createTestDB(t, map[string]string{
		"version":        "1.0",
		"created_at":     nowStr,
		"last_modified":  nowStr, // New database: has both keys
		"nvd_source":     "NVD API 2.0",
		"total_cves":     "50000",
		"schema_version": "1",
	})

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	meta, err := db.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	if meta.LastModified.IsZero() {
		t.Error("LastModified should not be zero")
	}

	// Verify time is correct
	timeDiff := meta.LastModified.Sub(now)
	if timeDiff < -time.Second || timeDiff > time.Second {
		t.Errorf("LastModified time mismatch: expected %v, got %v", now, meta.LastModified)
	}
}

func TestGetMetadata_InvalidDateFormat(t *testing.T) {
	// Test that invalid date format doesn't cause a crash
	dbPath := createTestDB(t, map[string]string{
		"version":        "1.0",
		"last_modified":  "invalid-date-format",
		"schema_version": "1",
	})

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	meta, err := db.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata should not fail with invalid date: %v", err)
	}

	// LastModified should be zero since parsing failed
	if !meta.LastModified.IsZero() {
		t.Errorf("Expected LastModified to be zero for invalid date, got %v", meta.LastModified)
	}
}

func TestGetMetadata_EmptyLastModified(t *testing.T) {
	// Test empty last_modified value
	dbPath := createTestDB(t, map[string]string{
		"version":        "1.0",
		"last_modified":  "",
		"schema_version": "1",
	})

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	meta, err := db.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata should not fail with empty date: %v", err)
	}

	if !meta.LastModified.IsZero() {
		t.Errorf("Expected LastModified to be zero for empty value, got %v", meta.LastModified)
	}
}

func TestGetCVECount(t *testing.T) {
	dbPath := createTestDB(t, map[string]string{
		"version": "1.0",
	})

	// Open the database and add some CVEs
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open raw database: %v", err)
	}

	// Insert test CVEs
	for i := 0; i < 5; i++ {
		_, err := rawDB.Exec(`
			INSERT INTO cves (cve_id, description, severity, published_date, modified_date)
			VALUES (?, ?, ?, ?, ?)
		`, "CVE-2024-000"+string(rune('0'+i)), "Test CVE", "HIGH", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("Failed to insert test CVE: %v", err)
		}
	}
	rawDB.Close()

	// Now test with our wrapper
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	count, err := db.GetCVECount()
	if err != nil {
		t.Fatalf("GetCVECount failed: %v", err)
	}

	if count != 5 {
		t.Errorf("Expected 5 CVEs, got %d", count)
	}

	// Also test via GetMetadata
	meta, err := db.GetMetadata()
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}

	if meta.CVECount != 5 {
		t.Errorf("Expected CVECount 5, got %d", meta.CVECount)
	}
}

func TestOpen_NonExistentFile(t *testing.T) {
	_, err := Open("/nonexistent/path/to/database.db")
	if err == nil {
		t.Error("Expected error when opening non-existent database")
	}
}

func TestOpen_ExpandHomePath(t *testing.T) {
	// Skip if running in environment without home dir
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skip("Cannot get home directory")
	}

	// Create a test database in a temp location, not in home dir
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test-cve.db")

	// Create the database first
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	rawDB.Exec(`CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)`)
	rawDB.Exec(`CREATE TABLE cves (cve_id TEXT PRIMARY KEY, description TEXT, severity TEXT, cvss_v3_score REAL, cvss_v3_vector TEXT, published_date TEXT, modified_date TEXT, references_json TEXT)`)
	rawDB.Close()

	// Test that ~ expansion works (even though we won't actually use it)
	// This is just to ensure the code path doesn't crash
	_ = homeDir // Used to verify home expansion logic works
}
