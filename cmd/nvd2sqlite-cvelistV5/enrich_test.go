package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TestExtractCVSS verifies the metric preference order (v3.1 > v3.0 > v2), the
// v2 severity derivation, uppercase normalization, and the no-metrics case.
func TestExtractCVSS(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		wantOK       bool
		wantScore    float64
		wantSeverity string
		wantVector   string
	}{
		{
			name: "prefers v3.1 over v3.0 and v2",
			json: `{"cve":{"id":"CVE-2024-0001","metrics":{
				"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"critical","vectorString":"CVSS:3.1/AV:N"}}],
				"cvssMetricV30":[{"cvssData":{"baseScore":5.0,"baseSeverity":"medium","vectorString":"CVSS:3.0/AV:N"}}],
				"cvssMetricV2":[{"cvssData":{"baseScore":4.3,"vectorString":"AV:N/AC:M"}}]}}}`,
			wantOK: true, wantScore: 9.8, wantSeverity: "CRITICAL", wantVector: "CVSS:3.1/AV:N",
		},
		{
			name: "falls back to v3.0 when no v3.1",
			json: `{"cve":{"id":"CVE-2024-0002","metrics":{
				"cvssMetricV30":[{"cvssData":{"baseScore":7.5,"baseSeverity":"high","vectorString":"CVSS:3.0/AV:N"}}],
				"cvssMetricV2":[{"cvssData":{"baseScore":4.3,"vectorString":"AV:N/AC:M"}}]}}}`,
			wantOK: true, wantScore: 7.5, wantSeverity: "HIGH", wantVector: "CVSS:3.0/AV:N",
		},
		{
			name: "falls back to v2 and derives HIGH from score",
			json: `{"cve":{"id":"CVE-2024-0003","metrics":{
				"cvssMetricV2":[{"cvssData":{"baseScore":7.5,"vectorString":"AV:N/AC:L"}}]}}}`,
			wantOK: true, wantScore: 7.5, wantSeverity: "HIGH", wantVector: "AV:N/AC:L",
		},
		{
			name: "v2 derives MEDIUM from score",
			json: `{"cve":{"id":"CVE-2024-0004","metrics":{
				"cvssMetricV2":[{"cvssData":{"baseScore":4.0,"vectorString":"AV:N"}}]}}}`,
			wantOK: true, wantScore: 4.0, wantSeverity: "MEDIUM", wantVector: "AV:N",
		},
		{
			name: "v2 derives LOW from score",
			json: `{"cve":{"id":"CVE-2024-0005","metrics":{
				"cvssMetricV2":[{"cvssData":{"baseScore":2.6,"vectorString":"AV:L"}}]}}}`,
			wantOK: true, wantScore: 2.6, wantSeverity: "LOW", wantVector: "AV:L",
		},
		{
			name:   "no metrics returns not ok",
			json:   `{"cve":{"id":"CVE-2024-0006","metrics":{}}}`,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v nvdVuln
			if err := json.Unmarshal([]byte(tt.json), &v); err != nil {
				t.Fatalf("unmarshal fixture: %v", err)
			}
			got := extractCVSS(v)
			if got.ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", got.ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.score != tt.wantScore {
				t.Errorf("score = %v, want %v", got.score, tt.wantScore)
			}
			if got.severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", got.severity, tt.wantSeverity)
			}
			if got.vector != tt.wantVector {
				t.Errorf("vector = %q, want %q", got.vector, tt.wantVector)
			}
		})
	}
}

func TestDeriveV2Severity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10.0, "HIGH"}, {7.0, "HIGH"}, {6.9, "MEDIUM"}, {4.0, "MEDIUM"}, {3.9, "LOW"}, {0.0, "LOW"},
	}
	for _, tt := range tests {
		if got := deriveV2Severity(tt.score); got != tt.want {
			t.Errorf("deriveV2Severity(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// newTestDB creates a temp SQLite DB with a minimal cves table.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sqlite")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE cves (
		cve_id TEXT PRIMARY KEY,
		description TEXT NOT NULL,
		severity TEXT NOT NULL,
		cvss_v3_score REAL,
		cvss_v3_vector TEXT,
		published_date TEXT NOT NULL,
		modified_date TEXT NOT NULL,
		references_json TEXT
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func insertCVE(t *testing.T, db *sql.DB, id, severity string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO cves (cve_id, description, severity, published_date, modified_date)
		VALUES (?, 'desc', ?, '2024-01-01', '2024-01-01')`, id, severity)
	if err != nil {
		t.Fatalf("insert %s: %v", id, err)
	}
}

func severityOf(t *testing.T, db *sql.DB, id string) (string, sql.NullFloat64, sql.NullString) {
	t.Helper()
	var sev string
	var score sql.NullFloat64
	var vec sql.NullString
	err := db.QueryRow(`SELECT severity, cvss_v3_score, cvss_v3_vector FROM cves WHERE cve_id=?`, id).
		Scan(&sev, &score, &vec)
	if err != nil {
		t.Fatalf("query %s: %v", id, err)
	}
	return sev, score, vec
}

// TestUpdateCVSSBatch verifies only UNKNOWN/NONE rows are updated, and rows with
// an existing real severity are left untouched even if an update targets them.
func TestUpdateCVSSBatch(t *testing.T) {
	db := newTestDB(t)
	insertCVE(t, db, "CVE-2024-1001", "UNKNOWN")
	insertCVE(t, db, "CVE-2024-1002", "NONE")
	insertCVE(t, db, "CVE-2024-1003", "HIGH")

	updates := []cvssUpdate{
		{cveID: "CVE-2024-1001", severity: "CRITICAL", score: 9.8, vector: "v31"},
		{cveID: "CVE-2024-1002", severity: "MEDIUM", score: 5.0, vector: "v2"},
		{cveID: "CVE-2024-1003", severity: "LOW", score: 2.0, vector: "should-not-apply"},
	}

	changed, err := updateCVSSBatch(db, updates)
	if err != nil {
		t.Fatalf("updateCVSSBatch: %v", err)
	}
	if changed != 2 {
		t.Errorf("changed = %d, want 2", changed)
	}

	if sev, score, vec := severityOf(t, db, "CVE-2024-1001"); sev != "CRITICAL" || score.Float64 != 9.8 || vec.String != "v31" {
		t.Errorf("CVE-2024-1001 = %q/%v/%q, want CRITICAL/9.8/v31", sev, score.Float64, vec.String)
	}
	if sev, _, _ := severityOf(t, db, "CVE-2024-1002"); sev != "MEDIUM" {
		t.Errorf("CVE-2024-1002 severity = %q, want MEDIUM", sev)
	}
	// The HIGH row must be untouched despite the update targeting it.
	if sev, _, vec := severityOf(t, db, "CVE-2024-1003"); sev != "HIGH" || vec.Valid {
		t.Errorf("CVE-2024-1003 = %q/%q, want HIGH and NULL vector (unchanged)", sev, vec.String)
	}
}

// TestApplyEnrichmentPage checks that only target CVEs present in the page are
// updated and non-target items are ignored.
func TestApplyEnrichmentPage(t *testing.T) {
	db := newTestDB(t)
	insertCVE(t, db, "CVE-2024-2001", "UNKNOWN")
	insertCVE(t, db, "CVE-2024-2002", "UNKNOWN")

	targets := map[string]struct{}{"CVE-2024-2001": {}, "CVE-2024-2002": {}}

	page := `[
		{"cve":{"id":"CVE-2024-2001","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"v"}}]}}},
		{"cve":{"id":"CVE-2024-9999","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM","vectorString":"v"}}]}}}
	]`
	var vulns []nvdVuln
	if err := json.Unmarshal([]byte(page), &vulns); err != nil {
		t.Fatalf("unmarshal page: %v", err)
	}

	changed, err := applyEnrichmentPage(db, vulns, targets)
	if err != nil {
		t.Fatalf("applyEnrichmentPage: %v", err)
	}
	if changed != 1 {
		t.Errorf("changed = %d, want 1", changed)
	}
	if sev, _, _ := severityOf(t, db, "CVE-2024-2001"); sev != "CRITICAL" {
		t.Errorf("CVE-2024-2001 severity = %q, want CRITICAL", sev)
	}
	if sev, _, _ := severityOf(t, db, "CVE-2024-2002"); sev != "UNKNOWN" {
		t.Errorf("CVE-2024-2002 severity = %q, want UNKNOWN (untouched)", sev)
	}
}

const onePageBody = `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[
	{"cve":{"id":"CVE-2024-3001","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N"}}]}}}
]}`

// TestFetchPageHappyPath exercises one successful page fetch against httptest.
func TestFetchPageHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q, want %q", got, userAgent)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(onePageBody))
	}))
	defer srv.Close()

	client := &nvdClient{httpClient: srv.Client(), maxAttempts: nvdEnrichMaxAttempts, baseBackoff: time.Millisecond}
	resp, err := client.fetchPage(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchPage: %v", err)
	}
	if resp.TotalResults != 1 || len(resp.Vulnerabilities) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got := resp.Vulnerabilities[0].CVE.ID; got != "CVE-2024-3001" {
		t.Errorf("CVE ID = %q, want CVE-2024-3001", got)
	}
}

// TestFetchPageRetries verifies a 503 is retried and the following 200 succeeds.
func TestFetchPageRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(onePageBody))
	}))
	defer srv.Close()

	client := &nvdClient{httpClient: srv.Client(), maxAttempts: nvdEnrichMaxAttempts, baseBackoff: time.Millisecond}
	resp, err := client.fetchPage(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchPage: %v", err)
	}
	if resp == nil || len(resp.Vulnerabilities) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("server calls = %d, want 2 (one 503, one 200)", n)
	}
}
