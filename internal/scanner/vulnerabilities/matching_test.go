package vulnerabilities

import (
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/cvedb"
	"github.com/cr0hn/dockerscan/v2/internal/version"
)

func vr(start, startType, end, endType string) cvedb.VersionRange {
	return cvedb.VersionRange{Start: start, StartType: startType, End: end, EndType: endType}
}

func TestMatchRange(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		r         cvedb.VersionRange
		want      bool
	}{
		{"unbounded matches anything", "1.2.3", vr("", "", "", ""), true},
		{"half-open in", "1.5", vr("1.0", "including", "2.0", "excluding"), true},
		{"half-open at start", "1.0", vr("1.0", "including", "2.0", "excluding"), true},
		{"half-open at exclusive end", "2.0", vr("1.0", "including", "2.0", "excluding"), false},
		{"half-open below start", "0.9", vr("1.0", "including", "2.0", "excluding"), false},
		{"exclusive start at bound", "1.0", vr("1.0", "excluding", "2.0", "excluding"), false},
		{"exclusive start above", "1.1", vr("1.0", "excluding", "2.0", "excluding"), true},
		{"including end at bound", "2.0", vr("1.0", "including", "2.0", "including"), true},
		{"including end above", "2.1", vr("1.0", "including", "2.0", "including"), false},
		{"exact closed match", "1.5", vr("1.5", "including", "1.5", "including"), true},
		{"exact closed no match", "1.6", vr("1.5", "including", "1.5", "including"), false},
		{"open start only match", "5.0", vr("1.0", "including", "", ""), true},
		{"open start only below", "0.9", vr("1.0", "including", "", ""), false},
		{"open end only match", "0.5", vr("", "", "2.0", "excluding"), true},
		{"open end only at bound", "2.0", vr("", "", "2.0", "excluding"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchRange(version.NormalizeInstalled(tt.installed, "dpkg"), tt.r)
			if got != tt.want {
				t.Errorf("matchRange(%q, %+v) = %v, want %v", tt.installed, tt.r, got, tt.want)
			}
		})
	}
}

func TestEvaluateCVE_VersionlessPolicy(t *testing.T) {
	installed := version.NormalizeInstalled("3.0", "dpkg")

	// A versionless range is ignored when the group has bounded ranges.
	bounded := cvedb.CVEEntry{Products: []cvedb.ProductRanges{{
		Vendor: "v", Product: "p",
		Ranges: []cvedb.VersionRange{
			vr("1.0", "including", "2.0", "excluding"),
			vr("", "", "", ""),
		},
	}}}
	if _, _, ok := evaluateCVE(installed, bounded); ok {
		t.Error("3.0 should not match a group whose only bounded range is [1.0,2.0)")
	}

	// A versionless-only group matches anything — but only when the
	// (vendor, product) pair is alias-verified.
	versionless := cvedb.CVEEntry{Products: []cvedb.ProductRanges{{
		Vendor: "v", Product: "p", AliasVerified: true,
		Ranges: []cvedb.VersionRange{vr("", "", "", "")},
	}}}
	if _, _, ok := evaluateCVE(installed, versionless); !ok {
		t.Error("alias-verified versionless-only group should match")
	}

	// A versionless-only group matched only by bare product name must NOT
	// match (GNU coreutils vs uutils/coreutils collision).
	unverified := cvedb.CVEEntry{Products: []cvedb.ProductRanges{{
		Vendor: "uutils", Product: "coreutils", AliasVerified: false,
		Ranges: []cvedb.VersionRange{vr("", "", "", "")},
	}}}
	if _, _, ok := evaluateCVE(installed, unverified); ok {
		t.Error("unverified versionless-only group must not match")
	}

	// CVE matches if ANY group matches; all matching groups are returned.
	multi := cvedb.CVEEntry{Products: []cvedb.ProductRanges{
		{Vendor: "a", Product: "x", Ranges: []cvedb.VersionRange{vr("10.0", "including", "11.0", "excluding")}},
		{Vendor: "b", Product: "y", Ranges: []cvedb.VersionRange{vr("2.0", "including", "4.0", "excluding")}},
	}}
	groups, _, ok := evaluateCVE(installed, multi)
	if !ok || len(groups) != 1 || groups[0].Product != "y" {
		t.Errorf("expected match on group y only, got ok=%v groups=%+v", ok, groups)
	}

	// FixedVersion pools ranges across ALL matching groups: the max excluding
	// end must escape every matching range.
	twoGroups := cvedb.CVEEntry{Products: []cvedb.ProductRanges{
		{Vendor: "a", Product: "x", Ranges: []cvedb.VersionRange{vr("1.0", "including", "1.6", "excluding")}},
		{Vendor: "b", Product: "y", Ranges: []cvedb.VersionRange{vr("1.0", "including", "3.0", "excluding")}},
	}}
	installed15 := version.NormalizeInstalled("1.5", "dpkg")
	groups2, matched2, ok2 := evaluateCVE(installed15, twoGroups)
	if !ok2 || len(groups2) != 2 {
		t.Fatalf("expected both groups to match, got ok=%v groups=%+v", ok2, groups2)
	}
	if got := fixedVersion(matched2); got != "3.0" {
		t.Errorf("fixedVersion across groups = %q, want 3.0", got)
	}
}

// TestEvaluateCVE_GarbageRow verifies a verbatim [raw,raw] dead row matches
// nothing above its bound (E6).
func TestEvaluateCVE_GarbageRow(t *testing.T) {
	garbage := vr("8.0 SP1, < 9", "including", "8.0 SP1, < 9", "including")
	if matchRange(version.NormalizeInstalled("9.1", "dpkg"), garbage) {
		t.Error("installed 9.1 must not match a [raw,raw] garbage range")
	}
	if matchRange(version.NormalizeInstalled("99.0", "dpkg"), garbage) {
		t.Error("installed 99.0 must not match a [raw,raw] garbage range")
	}
}

// TestFixedVersion covers D3: the max excluding-end bound among matched ranges.
func TestFixedVersion(t *testing.T) {
	// Overlapping matched ranges [1.0,1.5) + [1.0,2.0) -> 2.0 (E7).
	matched := []cvedb.VersionRange{
		vr("1.0", "including", "1.5", "excluding"),
		vr("1.0", "including", "2.0", "excluding"),
	}
	if got := fixedVersion(matched); got != "2.0" {
		t.Errorf("fixedVersion = %q, want 2.0", got)
	}

	// No excluding end -> empty.
	incl := []cvedb.VersionRange{vr("1.0", "including", "2.0", "including")}
	if got := fixedVersion(incl); got != "" {
		t.Errorf("fixedVersion = %q, want empty", got)
	}
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "CRITICAL",
		"high":     "HIGH",
		"Medium":   "MEDIUM",
		"LOW":      "LOW",
		"UNKNOWN":  "INFO",
		"NONE":     "INFO",
		"":         "INFO",
	}
	for raw, want := range cases {
		if got := string(mapSeverity(raw)); got != want {
			t.Errorf("mapSeverity(%q) = %q, want %q", raw, got, want)
		}
	}
}
