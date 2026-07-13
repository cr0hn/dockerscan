package cvedb

import "time"

// CVEEntry represents a CVE record from the database. Version matching is done
// per affected product: Products holds one entry per (vendor, product) matched
// by the queried package's aliases, each with its own set of version ranges.
type CVEEntry struct {
	CVEID         string
	Description   string
	Severity      string // CRITICAL, HIGH, MEDIUM, LOW
	CVSSScore     float64
	CVSSVector    string
	PublishedDate time.Time
	ModifiedDate  time.Time
	References    []string
	Products      []ProductRanges
}

// ProductRanges holds the version ranges of a single affected (vendor, product)
// pair for one CVE. AliasVerified is true when the pair was matched through the
// package_aliases table (vendor-verified) rather than by bare product name;
// versionless product-level matches are only trusted when it is set (a bare
// product-name collision like GNU coreutils vs uutils/coreutils must not match
// without version evidence).
type ProductRanges struct {
	Vendor        string
	Product       string
	AliasVerified bool
	Ranges        []VersionRange
}

// VersionRange is a single affected version range. An empty Start or End means
// that bound is unbounded. Types are "including" or "excluding". A range with
// both bounds empty is a "versionless" product-level match.
type VersionRange struct {
	Start     string
	End       string
	StartType string
	EndType   string
}

// DBMetadata contains database version info
type DBMetadata struct {
	Version       string
	LastModified  time.Time
	CVECount      int
	SchemaVersion string
}

// PackageInfo represents a package to query for CVEs
type PackageInfo struct {
	Name    string // Package name (e.g., "nginx", "libssl1.1")
	Version string // Package version (e.g., "1.18.0-1")
	Source  string // Package source: dpkg, apk, rpm
}
