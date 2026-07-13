package main

import (
	"testing"
	"time"
)

// wideStart/wideEnd bracket essentially all realistic publish dates so that
// date filtering does not interfere with mapping tests.
var (
	wideStart = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	wideEnd   = time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
)

func TestParseRecord_Basic(t *testing.T) {
	data := []byte(`{
		"cveMetadata": {
			"cveId": "CVE-2024-1000",
			"state": "PUBLISHED",
			"datePublished": "2024-03-01T10:00:00.000Z",
			"dateUpdated": "2024-04-02T12:30:00.000Z"
		},
		"containers": {
			"cna": {
				"descriptions": [
					{"lang": "es", "value": "hola"},
					{"lang": "en", "value": "a buffer overflow"}
				],
				"metrics": [
					{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "critical", "vectorString": "CVSS:3.1/AV:N"}}
				],
				"references": [
					{"url": "https://example.com/a"},
					{"url": "https://example.com/b"}
				],
				"affected": [
					{"vendor": "Acme", "product": "Widget", "versions": [
						{"version": "1.0", "status": "affected", "lessThan": "1.5"}
					]}
				]
			}
		}
	}`)

	outcome, cve, prods := parseRecord(data, wideStart, wideEnd)
	if outcome != outcomeOK {
		t.Fatalf("outcome = %d, want outcomeOK", outcome)
	}
	if cve.ID != "CVE-2024-1000" {
		t.Errorf("ID = %q", cve.ID)
	}
	if cve.Description != "a buffer overflow" {
		t.Errorf("Description = %q, want English", cve.Description)
	}
	if cve.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", cve.Severity)
	}
	if cve.CVSSScore != 9.8 {
		t.Errorf("CVSSScore = %v", cve.CVSSScore)
	}
	if cve.Published != "2024-03-01T10:00:00.000" {
		t.Errorf("Published = %q, want normalized no-tz millis", cve.Published)
	}
	if cve.Modified != "2024-04-02T12:30:00.000" {
		t.Errorf("Modified = %q", cve.Modified)
	}
	if cve.ReferencesJSON != `["https://example.com/a","https://example.com/b"]` {
		t.Errorf("ReferencesJSON = %q", cve.ReferencesJSON)
	}
	if len(prods) != 1 {
		t.Fatalf("len(prods) = %d, want 1", len(prods))
	}
	p := prods[0]
	if p.Vendor != "acme" || p.Product != "widget" {
		t.Errorf("vendor/product = %q/%q, want lowercased", p.Vendor, p.Product)
	}
	if p.VersionStart != "1.0" || p.VersionStartType != "including" {
		t.Errorf("start = %q/%q", p.VersionStart, p.VersionStartType)
	}
	if p.VersionEnd != "1.5" || p.VersionEndType != "excluding" {
		t.Errorf("end = %q/%q", p.VersionEnd, p.VersionEndType)
	}
}

func TestParseRecord_Rejected(t *testing.T) {
	data := []byte(`{"cveMetadata":{"cveId":"CVE-2024-2000","state":"REJECTED"}}`)
	outcome, _, _ := parseRecord(data, wideStart, wideEnd)
	if outcome != outcomeSkippedRejected {
		t.Fatalf("outcome = %d, want outcomeSkippedRejected", outcome)
	}
}

func TestParseRecord_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"invalid json": []byte(`{not json`),
		"missing id":   []byte(`{"cveMetadata":{"state":"PUBLISHED"}}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			outcome, _, _ := parseRecord(data, wideStart, wideEnd)
			if outcome != outcomeMalformed {
				t.Fatalf("outcome = %d, want outcomeMalformed", outcome)
			}
		})
	}
}

func TestParseRecord_DateFilter(t *testing.T) {
	data := []byte(`{
		"cveMetadata": {"cveId":"CVE-2020-1","state":"PUBLISHED","datePublished":"2020-01-01T00:00:00.000Z"}
	}`)
	start := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	outcome, _, _ := parseRecord(data, start, end)
	if outcome != outcomeSkippedDate {
		t.Fatalf("outcome = %d, want outcomeSkippedDate", outcome)
	}
}

func TestSelectDescription(t *testing.T) {
	tests := []struct {
		name  string
		descs []langValue
		want  string
	}{
		{"exact en", []langValue{{"fr", "x"}, {"en", "y"}}, "y"},
		{"en variant", []langValue{{"fr", "x"}, {"en-US", "y"}}, "y"},
		{"fallback first", []langValue{{"de", "x"}, {"fr", "y"}}, "x"},
		{"empty", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectDescription(tt.descs); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectCVSS_Preference(t *testing.T) {
	tests := []struct {
		name     string
		rec      *cveRecord
		wantSev  string
		wantScr  float64
	}{
		{
			name: "prefer v3.1 over v3.0",
			rec: recWithCNAMetrics(
				metricEntry{CvssV30: &cvssData{BaseScore: 5.0, BaseSeverity: "MEDIUM", VectorString: "v30"}},
				metricEntry{CvssV31: &cvssData{BaseScore: 8.1, BaseSeverity: "HIGH", VectorString: "v31"}},
			),
			wantSev: "HIGH", wantScr: 8.1,
		},
		{
			name: "prefer v3.0 over v4.0",
			rec: recWithCNAMetrics(
				metricEntry{CvssV40: &cvssData{BaseScore: 9.0, BaseSeverity: "CRITICAL", VectorString: "v40"}},
				metricEntry{CvssV30: &cvssData{BaseScore: 6.0, BaseSeverity: "MEDIUM", VectorString: "v30"}},
			),
			wantSev: "MEDIUM", wantScr: 6.0,
		},
		{
			name: "prefer v4.0 over v2.0",
			rec: recWithCNAMetrics(
				metricEntry{CvssV2: &cvssData{BaseScore: 10.0, VectorString: "v2"}},
				metricEntry{CvssV40: &cvssData{BaseScore: 7.7, BaseSeverity: "HIGH", VectorString: "v40"}},
			),
			wantSev: "HIGH", wantScr: 7.7,
		},
		{
			name: "v2 severity derived from score",
			rec: recWithCNAMetrics(
				metricEntry{CvssV2: &cvssData{BaseScore: 10.0, BaseSeverity: "IGNORED", VectorString: "v2"}},
			),
			wantSev: "HIGH", wantScr: 10.0, // v2 has no CRITICAL band
		},
		{
			name:    "no metrics",
			rec:     recWithCNAMetrics(),
			wantSev: "UNKNOWN", wantScr: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, sev, _ := selectCVSS(tt.rec)
			if sev != tt.wantSev || score != tt.wantScr {
				t.Errorf("got %v/%q, want %v/%q", score, sev, tt.wantScr, tt.wantSev)
			}
		})
	}
}

func TestSelectCVSS_ADPFallback(t *testing.T) {
	rec := &cveRecord{}
	rec.Containers.ADP = []struct {
		Metrics []metricEntry `json:"metrics"`
	}{
		{Metrics: []metricEntry{{CvssV31: &cvssData{BaseScore: 7.5, BaseSeverity: "HIGH", VectorString: "adp"}}}},
	}
	score, sev, vec := selectCVSS(rec)
	if score != 7.5 || sev != "HIGH" || vec != "adp" {
		t.Errorf("ADP fallback failed: %v/%q/%q", score, sev, vec)
	}
}

func TestDeriveSeverity(t *testing.T) {
	tests := []struct {
		score float64
		v2    bool
		want  string
	}{
		{9.5, false, "CRITICAL"},
		{7.2, false, "HIGH"},
		{5.0, false, "MEDIUM"},
		{1.0, false, "LOW"},
		{0, false, "NONE"},
		{10.0, true, "HIGH"}, // v2 caps at HIGH
		{7.0, true, "HIGH"},
		{4.0, true, "MEDIUM"},
		{3.9, true, "LOW"},
	}
	for _, tt := range tests {
		if got := deriveSeverity(tt.score, tt.v2); got != tt.want {
			t.Errorf("deriveSeverity(%v, %v) = %q, want %q", tt.score, tt.v2, got, tt.want)
		}
	}
}

func TestExpandVersions(t *testing.T) {
	tests := []struct {
		name string
		in   versionEntry
		want []versionRange
	}{
		{"exact + lessThan", versionEntry{Version: "1.0", LessThan: "1.5"},
			[]versionRange{{"1.0", "including", "1.5", "excluding"}}},
		{"exact + lessThanOrEqual", versionEntry{Version: "2.0", LessThanOrEqual: "2.9"},
			[]versionRange{{"2.0", "including", "2.9", "including"}}},
		{"unbounded start zero", versionEntry{Version: "0", LessThan: "3.0"},
			[]versionRange{{"", "", "3.0", "excluding"}}},
		{"unbounded start star", versionEntry{Version: "*", LessThan: "4.0"},
			[]versionRange{{"", "", "4.0", "excluding"}}},
		{"free text version", versionEntry{Version: "before 1.2.3"},
			[]versionRange{{"before 1.2.3", "including", "", ""}}},
		{"only exact", versionEntry{Version: "5.5"},
			[]versionRange{{"5.5", "including", "", ""}}},
		// Free-text operator expressions (CNA-provided, ~13% of real rows).
		{"lt in version field", versionEntry{Version: "< 3.1.1"},
			[]versionRange{{"", "", "3.1.1", "excluding"}}},
		{"lte in version field", versionEntry{Version: "<=5.4"},
			[]versionRange{{"", "", "5.4", "including"}}},
		{"combined range", versionEntry{Version: ">=v1.0.0-rc93, < 1.1.12"},
			[]versionRange{{"1.0.0-rc93", "including", "1.1.12", "excluding"}}},
		{"gt bound", versionEntry{Version: "> 2.0"},
			[]versionRange{{"2.0", "excluding", "", ""}}},
		{"comma list of exacts", versionEntry{Version: "11.0.0, 11.0.1"},
			[]versionRange{{"11.0.0", "including", "", ""}, {"11.0.1", "including", "", ""}}},
		{"v prefix stripped exact", versionEntry{Version: "v2.0.1"},
			[]versionRange{{"2.0.1", "including", "", ""}}},
		{"v prefix stripped in lessThan", versionEntry{Version: "1.0", LessThan: "v1.5"},
			[]versionRange{{"1.0", "including", "1.5", "excluding"}}},
		{"unparseable mixed stays verbatim", versionEntry{Version: "8.0 SP1, < 9"},
			[]versionRange{{"8.0 SP1, < 9", "including", "", ""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandVersions(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d ranges (%+v), want %d (%+v)", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("range %d: got %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestBuildProductRows(t *testing.T) {
	t.Run("skip n/a both", func(t *testing.T) {
		rows := buildProductRows([]affectedEntry{{Vendor: "n/a", Product: "n/a"}})
		if len(rows) != 0 {
			t.Fatalf("len = %d, want 0", len(rows))
		}
	})

	t.Run("no versions emits bare row", func(t *testing.T) {
		rows := buildProductRows([]affectedEntry{{Vendor: "Acme", Product: "Thing"}})
		if len(rows) != 1 {
			t.Fatalf("len = %d, want 1", len(rows))
		}
		if rows[0].Vendor != "acme" || rows[0].Product != "thing" || rows[0].VersionStart != "" {
			t.Errorf("bare row wrong: %+v", rows[0])
		}
	})

	t.Run("skip unaffected versions", func(t *testing.T) {
		rows := buildProductRows([]affectedEntry{{
			Vendor: "v", Product: "p",
			Versions: []versionEntry{
				{Version: "1.0", Status: "unaffected"},
				{Version: "2.0", Status: "affected", LessThan: "2.5"},
			},
		}})
		if len(rows) != 1 {
			t.Fatalf("len = %d, want 1 (only affected)", len(rows))
		}
		if rows[0].VersionStart != "2.0" {
			t.Errorf("wrong version kept: %+v", rows[0])
		}
	})
}

func TestParseFlexTime(t *testing.T) {
	inputs := []string{
		"2024-03-01T10:00:00.000Z",
		"2024-03-01T10:00:00Z",
		"2024-03-01T10:00:00.123456Z",
		"2024-03-01T10:00:00+02:00",
		"2024-03-01T10:00:00",
		"2024-03-01",
	}
	for _, in := range inputs {
		if _, ok := parseFlexTime(in); !ok {
			t.Errorf("failed to parse %q", in)
		}
	}
	if _, ok := parseFlexTime("garbage"); ok {
		t.Error("parsed garbage")
	}
}

// recWithCNAMetrics builds a cveRecord with the given cna.metrics entries.
func recWithCNAMetrics(metrics ...metricEntry) *cveRecord {
	rec := &cveRecord{}
	rec.Containers.CNA.Metrics = metrics
	return rec
}
