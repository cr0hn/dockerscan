package cvedb

import "time"

// CVEEntry represents a CVE record from the database
type CVEEntry struct {
	CVEID            string
	Description      string
	Severity         string // CRITICAL, HIGH, MEDIUM, LOW
	CVSSScore        float64
	CVSSVector       string
	PublishedDate    time.Time
	ModifiedDate     time.Time
	References       []string
	// Version constraints for matching
	VersionStart     string
	VersionEnd       string
	VersionStartType string // "including" or "excluding"
	VersionEndType   string // "including" or "excluding"
	FixedVersion     string
}

// AffectedProduct represents a product affected by a CVE
type AffectedProduct struct {
	CVEID            string
	Vendor           string
	Product          string
	VersionStart     string
	VersionEnd       string
	VersionStartType string // "including" or "excluding"
	VersionEndType   string // "including" or "excluding"
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
