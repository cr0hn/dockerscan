package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// nvdTimeFormat is the timestamp layout the existing nvd2sqlite tool stores
// (NVD API 2.0 style: no timezone suffix, millisecond precision). We normalize
// cvelistV5 timestamps to this format so the resulting database is a drop-in
// replacement.
const nvdTimeFormat = "2006-01-02T15:04:05.000"

// Parse outcomes for a single CVE JSON 5.x record.
const (
	outcomeOK = iota
	outcomeSkippedRejected
	outcomeSkippedDate
	outcomeMalformed
)

// cveRecord models the subset of the CVE JSON 5.x schema we consume.
type cveRecord struct {
	CVEMetadata struct {
		CVEID         string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
		DateReserved  string `json:"dateReserved"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Descriptions []langValue     `json:"descriptions"`
			Metrics      []metricEntry   `json:"metrics"`
			Affected     []affectedEntry `json:"affected"`
			References   []refEntry      `json:"references"`
		} `json:"cna"`
		ADP []struct {
			Metrics []metricEntry `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}

type langValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type refEntry struct {
	URL string `json:"url"`
}

type cvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

// metricEntry represents a single element of a metrics[] array. Each element
// carries at most one CVSS object keyed by version.
type metricEntry struct {
	CvssV31 *cvssData `json:"cvssV3_1"`
	CvssV30 *cvssData `json:"cvssV3_0"`
	CvssV40 *cvssData `json:"cvssV4_0"`
	CvssV2  *cvssData `json:"cvssV2_0"`
}

type affectedEntry struct {
	Vendor        string         `json:"vendor"`
	Product       string         `json:"product"`
	DefaultStatus string         `json:"defaultStatus"`
	Versions      []versionEntry `json:"versions"`
}

type versionEntry struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	VersionType     string `json:"versionType"`
}

// cveRow is a row destined for the cves table.
type cveRow struct {
	ID             string
	Description    string
	Severity       string
	CVSSScore      float64
	CVSSVector     string
	Published      string
	Modified       string
	ReferencesJSON string
}

// productRow is a row destined for the affected_products table.
type productRow struct {
	Vendor           string
	Product          string
	VersionStart     string
	VersionEnd       string
	VersionStartType string
	VersionEndType   string
}

// parseRecord parses a single CVE JSON 5.x record and maps it to the SQLite
// schema. It never panics on malformed input: a bad record returns
// outcomeMalformed. Records outside [start, end] (by datePublished) return
// outcomeSkippedDate; REJECTED records return outcomeSkippedRejected.
func parseRecord(data []byte, start, end time.Time) (int, cveRow, []productRow) {
	var rec cveRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return outcomeMalformed, cveRow{}, nil
	}

	if strings.TrimSpace(rec.CVEMetadata.CVEID) == "" {
		return outcomeMalformed, cveRow{}, nil
	}

	if strings.EqualFold(strings.TrimSpace(rec.CVEMetadata.State), "REJECTED") {
		return outcomeSkippedRejected, cveRow{}, nil
	}

	// Date filter on datePublished. If the date is missing/unparseable we keep
	// the record (rather than silently dropping it).
	published := rec.CVEMetadata.DatePublished
	if pubT, ok := parseFlexTime(rec.CVEMetadata.DatePublished); ok {
		if pubT.Before(start) || pubT.After(end) {
			return outcomeSkippedDate, cveRow{}, nil
		}
		published = pubT.UTC().Format(nvdTimeFormat)
	}

	modified := rec.CVEMetadata.DateUpdated
	if updT, ok := parseFlexTime(rec.CVEMetadata.DateUpdated); ok {
		modified = updT.UTC().Format(nvdTimeFormat)
	}
	if modified == "" {
		modified = published
	}

	score, severity, vector := selectCVSS(&rec)
	description := selectDescription(rec.Containers.CNA.Descriptions)

	var refs []string
	for _, r := range rec.Containers.CNA.References {
		if strings.TrimSpace(r.URL) != "" {
			refs = append(refs, r.URL)
		}
	}
	refsJSON, _ := json.Marshal(refs)

	row := cveRow{
		ID:             strings.TrimSpace(rec.CVEMetadata.CVEID),
		Description:    description,
		Severity:       severity,
		CVSSScore:      score,
		CVSSVector:     vector,
		Published:      published,
		Modified:       modified,
		ReferencesJSON: string(refsJSON),
	}

	return outcomeOK, row, buildProductRows(rec.Containers.CNA.Affected)
}

// selectDescription returns the best English description, falling back to any
// "en-*" locale, then to the first available description.
func selectDescription(descs []langValue) string {
	if len(descs) == 0 {
		return ""
	}
	for _, d := range descs {
		if strings.EqualFold(d.Lang, "en") {
			return d.Value
		}
	}
	for _, d := range descs {
		if strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			return d.Value
		}
	}
	return descs[0].Value
}

// selectCVSS searches containers.cna.metrics first, then containers.adp[].metrics,
// preferring CVSS v3.1 > v3.0 > v4.0 > v2.0. It returns the base score, an
// uppercased severity, and the vector string.
func selectCVSS(rec *cveRecord) (float64, string, string) {
	sources := [][]metricEntry{rec.Containers.CNA.Metrics}
	for _, adp := range rec.Containers.ADP {
		sources = append(sources, adp.Metrics)
	}

	type accessor struct {
		get func(metricEntry) *cvssData
		v2  bool
	}
	accessors := []accessor{
		{func(m metricEntry) *cvssData { return m.CvssV31 }, false},
		{func(m metricEntry) *cvssData { return m.CvssV30 }, false},
		{func(m metricEntry) *cvssData { return m.CvssV40 }, false},
		{func(m metricEntry) *cvssData { return m.CvssV2 }, true},
	}

	for _, a := range accessors {
		for _, metrics := range sources {
			for _, m := range metrics {
				c := a.get(m)
				if c == nil {
					continue
				}
				// Skip empty metric objects (no score and no vector).
				if c.BaseScore == 0 && strings.TrimSpace(c.VectorString) == "" {
					continue
				}
				severity := strings.ToUpper(strings.TrimSpace(c.BaseSeverity))
				if a.v2 || severity == "" {
					severity = deriveSeverity(c.BaseScore, a.v2)
				}
				return c.BaseScore, severity, c.VectorString
			}
		}
	}

	return 0, "UNKNOWN", ""
}

// deriveSeverity computes a severity band from a base score. CVSS v2 has no
// CRITICAL band (>=7 HIGH, >=4 MEDIUM, else LOW).
func deriveSeverity(score float64, v2 bool) string {
	if v2 {
		switch {
		case score >= 7.0:
			return "HIGH"
		case score >= 4.0:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

// buildProductRows maps containers.cna.affected[] into affected_products rows.
// Entries where both vendor and product are empty or "n/a" are skipped. Vendor
// and product are lowercased to match how CPE-derived data is stored (and how
// the consumer queries). Identical (vendor, product, range) rows within a
// single record are de-duplicated (A6).
func buildProductRows(affected []affectedEntry) []productRow {
	var rows []productRow
	seen := make(map[productRow]bool)

	add := func(r productRow) {
		if seen[r] {
			return
		}
		seen[r] = true
		rows = append(rows, r)
	}

	for _, a := range affected {
		vendor := strings.ToLower(strings.TrimSpace(a.Vendor))
		product := strings.ToLower(strings.TrimSpace(a.Product))

		if isNA(vendor) && isNA(product) {
			continue
		}

		emitted := 0
		for _, v := range a.Versions {
			if !strings.EqualFold(strings.TrimSpace(v.Status), "affected") {
				continue
			}
			// A4: git versionType values are commit hashes, not comparable.
			if strings.EqualFold(strings.TrimSpace(v.VersionType), "git") {
				continue
			}
			for _, r := range expandVersions(v) {
				add(productRow{
					Vendor:           vendor,
					Product:          product,
					VersionStart:     r.start,
					VersionEnd:       r.end,
					VersionStartType: r.startType,
					VersionEndType:   r.endType,
				})
				emitted++
			}
		}

		// A3: when no "affected" version enumeration produced a row, the branch
		// is affected as a whole only if the default status says so. A missing
		// defaultStatus keeps the previous behavior (a product-level match); an
		// explicit "unaffected" default emits nothing (avoids a bogus unbounded
		// row on fully-fixed products).
		if emitted == 0 && !strings.EqualFold(strings.TrimSpace(a.DefaultStatus), "unaffected") {
			add(productRow{Vendor: vendor, Product: product})
		}
	}

	return rows
}

// versionRange is a normalized version constraint destined for one
// affected_products row.
type versionRange struct {
	start, startType, end, endType string
}

// expandVersions maps a single affected version entry to one or more
// normalized version ranges.
//
//	version "0"/"*"/""       -> unbounded start (empty version_start)
//	version X                -> exact match, stored as the closed range [X,X]
//	lessThan Y               -> version_end = Y, type "excluding"
//	lessThanOrEqual Y        -> version_end = Y, type "including"
//
// Many CNAs put free-text range expressions in the version field instead of
// using lessThan/lessThanOrEqual (~13% of rows in a full snapshot). The common
// shapes are normalized here so the scanner's version comparator can use them:
//
//	"< 1.5" / "<= 1.5"           -> bound-only range
//	">= 1.0, < 2.0"              -> combined range
//	"1.0, 1.1, 2.0"              -> one exact [X,X] row per version
//	"v1.2.3"                     -> "1.2.3" (leading v stripped everywhere)
//	"2.x" / "2.5.X" / "2.*"      -> [2,3) / [2.5,2.6) (A4 wildcard)
//	"X and earlier"             -> (-inf, X] (A2)
//	"A through B" / "A - B"     -> [A,B] (A2)
//
// After the structured end bound (lessThan/lessThanOrEqual) is merged in, an
// exact version that still has no end bound becomes the closed range [X,X]
// (A1): the only Start-only/including rows left are genuine ">=X" open ranges.
// Anything that still does not parse is stored as the closed range [raw,raw]
// (A2): a harmless dead row that never matches but preserves the record.
func expandVersions(v versionEntry) []versionRange {
	// Structured bounds from the schema fields.
	var structEnd, structEndType string
	switch {
	case strings.TrimSpace(v.LessThan) != "":
		structEnd = cleanVersion(v.LessThan)
		structEndType = "excluding"
	case strings.TrimSpace(v.LessThanOrEqual) != "":
		structEnd = cleanVersion(v.LessThanOrEqual)
		structEndType = "including"
	}

	ver := strings.TrimSpace(v.Version)
	if ver == "" || ver == "0" || ver == "*" {
		return []versionRange{{end: structEnd, endType: structEndType}}
	}

	// A4: wildcard branch versions expand to a bounded [prefix, next) range. A
	// structured end bound is the CNA's explicit upper limit and wins over the
	// computed next-prefix (e.g. version "1.x" + lessThanOrEqual "1.8" -> [1,1.8]).
	if r, ok := parseWildcard(ver); ok {
		if structEnd != "" {
			r.end, r.endType = structEnd, structEndType
		}
		return []versionRange{r}
	}

	if bound, exacts, ok := parseVersionExpr(ver); ok {
		var ranges []versionRange
		if bound != nil {
			// Structured end bound fills a single open-ended operator range.
			if bound.end == "" && structEnd != "" {
				bound.end, bound.endType = structEnd, structEndType
			}
			ranges = append(ranges, *bound)
		}
		// Comma-listed exacts plus a structured end bound mean "these versions
		// up to the bound" (e.g. version "1.0, 1.1", lessThan "2.0"): collapse
		// to [first, bound) — CNAs list versions in ascending order.
		if bound == nil && len(exacts) > 0 && structEnd != "" {
			return append(ranges, versionRange{
				start: exacts[0], startType: "including",
				end: structEnd, endType: structEndType,
			})
		}
		for _, e := range exacts {
			// A1: exact match without an end bound -> closed range [X,X].
			ranges = append(ranges, versionRange{
				start: e, startType: "including",
				end: e, endType: "including",
			})
		}
		return ranges
	}

	// A2: recognizable free-text ranges before falling back to verbatim.
	if r, ok := parseFreeTextRange(ver); ok {
		return []versionRange{r}
	}

	// A2: unparseable text. With a structured end bound the row keeps it (the
	// bound is machine-generated and trustworthy even when the version text is
	// not); otherwise a closed [raw,raw] dead row preserves the record without
	// ever becoming an open ">=garbage" range.
	if structEnd != "" {
		return []versionRange{{start: ver, startType: "including", end: structEnd, endType: structEndType}}
	}
	return []versionRange{{start: ver, startType: "including", end: ver, endType: "including"}}
}

// parseVersionExpr parses a version field that may contain comma-separated
// exact versions and/or operator expressions. It returns the combined operator
// bound (nil when the field has none) and the list of exact versions. ok is
// false when any token does not parse, in which case the caller falls back to
// free-text handling.
func parseVersionExpr(expr string) (bound *versionRange, exacts []string, ok bool) {
	var combined versionRange
	hasBound := false

	for _, tok := range strings.Split(expr, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		op, val, tokOK := parseVersionToken(tok)
		if !tokOK {
			return nil, nil, false
		}
		switch op {
		case ">=":
			combined.start, combined.startType = val, "including"
			hasBound = true
		case ">":
			combined.start, combined.startType = val, "excluding"
			hasBound = true
		case "<":
			combined.end, combined.endType = val, "excluding"
			hasBound = true
		case "<=":
			combined.end, combined.endType = val, "including"
			hasBound = true
		default: // exact version
			exacts = append(exacts, val)
		}
	}

	if !hasBound && len(exacts) == 0 {
		return nil, nil, false
	}
	if hasBound {
		bound = &combined
	}
	return bound, exacts, true
}

// wildcardRe matches a wildcard branch version such as "2.x", "2.5.X" or "2.*".
// The captured group is the numeric prefix.
var wildcardRe = regexp.MustCompile(`^[vV]?([0-9]+(?:\.[0-9]+)*)\.(?:[xX]|\*)$`)

// parseWildcard converts a wildcard branch version into the bounded range
// [prefix, next) where next increments the last numeric component of the prefix
// (A4). "2.x" -> [2,3), "2.5.X" -> [2.5,2.6).
func parseWildcard(s string) (versionRange, bool) {
	m := wildcardRe.FindStringSubmatch(s)
	if m == nil {
		return versionRange{}, false
	}
	prefix := m[1]
	parts := strings.Split(prefix, ".")
	last, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return versionRange{}, false
	}
	parts[len(parts)-1] = strconv.Itoa(last + 1)
	next := strings.Join(parts, ".")
	return versionRange{start: prefix, startType: "including", end: next, endType: "excluding"}, true
}

// Free-text range shapes (A2). The version token allows the usual
// version-looking characters after an optional leading "v".
const versionTokenPat = `[vV]?([0-9][0-9A-Za-z.\-+_]*)`

var (
	earlierRe   = regexp.MustCompile(`(?i)^\s*` + versionTokenPat + `\s+(?:and|or)\s+(?:earlier|prior)\s*$`)
	throughRe   = regexp.MustCompile(`(?i)^\s*` + versionTokenPat + `\s+(?:through|to)\s+` + versionTokenPat + `\s*$`)
	dashRangeRe = regexp.MustCompile(`(?i)^\s*` + versionTokenPat + `\s+-\s+` + versionTokenPat + `\s*$`)
)

// parseFreeTextRange recognizes two common English range shapes:
//
//	"X and earlier" / "X or prior"  -> (-inf, X] including
//	"A through B" / "A to B" / "A - B" -> [A,B] both including
//
// The dash form requires spaces around the dash so a version-internal hyphen is
// never mistaken for a range separator.
func parseFreeTextRange(s string) (versionRange, bool) {
	if m := earlierRe.FindStringSubmatch(s); m != nil {
		return versionRange{end: cleanVersion(m[1]), endType: "including"}, true
	}
	if m := throughRe.FindStringSubmatch(s); m != nil {
		return versionRange{
			start: cleanVersion(m[1]), startType: "including",
			end: cleanVersion(m[2]), endType: "including",
		}, true
	}
	if m := dashRangeRe.FindStringSubmatch(s); m != nil {
		return versionRange{
			start: cleanVersion(m[1]), startType: "including",
			end: cleanVersion(m[2]), endType: "including",
		}, true
	}
	return versionRange{}, false
}

// versionTokenRe matches an optional comparison operator followed by a
// version-looking value (starts with a digit after an optional leading v).
var versionTokenRe = regexp.MustCompile(`^(>=|<=|>|<)?\s*[vV]?([0-9][0-9A-Za-z.\-+_]*)$`)

// parseVersionToken parses one token like ">= 1.2.3", "<v2.0" or "1.4.7".
func parseVersionToken(tok string) (op, val string, ok bool) {
	m := versionTokenRe.FindStringSubmatch(tok)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// cleanVersion trims a version value and strips a leading "v"/"V" prefix when
// followed by a digit (e.g. "v1.1.12" -> "1.1.12").
func cleanVersion(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9' {
		return s[1:]
	}
	return s
}

func isNA(s string) bool {
	return s == "" || s == "n/a"
}

// parseFlexTime parses the range of timestamp formats seen in cvelistV5 records.
func parseFlexTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z07:00",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
