package cvedb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// CVEDB represents a CVE database connection
type CVEDB struct {
	db     *sql.DB
	dbPath string
}

// Open opens a connection to the CVE database
// If dbPath starts with ~, it will be expanded to the user's home directory
func Open(dbPath string) (*CVEDB, error) {
	// Expand ~ to home directory
	if strings.HasPrefix(dbPath, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		dbPath = filepath.Join(homeDir, dbPath[1:])
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Check if database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("database file does not exist: %s (run download first)", dbPath)
	}

	// Open database with SQLite driver
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Verify database is accessible
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &CVEDB{
		db:     db,
		dbPath: dbPath,
	}, nil
}

// Close closes the database connection
func (d *CVEDB) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// GetMetadata retrieves database metadata
func (d *CVEDB) GetMetadata() (*DBMetadata, error) {
	metadata := &DBMetadata{}

	// Get version
	var version string
	err := d.db.QueryRow("SELECT value FROM metadata WHERE key = 'version'").Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get version: %w", err)
	}
	metadata.Version = version

	// Get last modified
	var lastModifiedStr string
	err = d.db.QueryRow("SELECT value FROM metadata WHERE key = 'last_modified'").Scan(&lastModifiedStr)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get last_modified: %w", err)
	}
	if lastModifiedStr != "" {
		lastModified, err := time.Parse(time.RFC3339, lastModifiedStr)
		if err == nil {
			metadata.LastModified = lastModified
		}
	}

	// Get schema version
	var schemaVersion string
	err = d.db.QueryRow("SELECT value FROM metadata WHERE key = 'schema_version'").Scan(&schemaVersion)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get schema_version: %w", err)
	}
	metadata.SchemaVersion = schemaVersion

	// Get CVE count
	count, err := d.GetCVECount()
	if err != nil {
		return nil, fmt.Errorf("failed to get CVE count: %w", err)
	}
	metadata.CVECount = count

	return metadata, nil
}

// GetCVECount returns the total number of CVEs in the database
func (d *CVEDB) GetCVECount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM cves").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count CVEs: %w", err)
	}
	return count, nil
}

// QueryByPackage finds CVEs affecting a specific package
func (d *CVEDB) QueryByPackage(pkgName, pkgSource string) ([]CVEEntry, error) {
	packages := []PackageInfo{{Name: pkgName, Source: pkgSource}}
	results, err := d.QueryByPackages(packages)
	if err != nil {
		return nil, err
	}
	return results[pkgName], nil
}

// QueryByPackages finds CVEs for multiple packages (batch query)
func (d *CVEDB) QueryByPackages(packages []PackageInfo) (map[string][]CVEEntry, error) {
	results := make(map[string][]CVEEntry)

	for _, pkg := range packages {
		cves, err := d.queryPackage(pkg)
		if err != nil {
			return nil, fmt.Errorf("failed to query package %s: %w", pkg.Name, err)
		}
		results[pkg.Name] = cves
	}

	return results, nil
}

// queryPackage performs the actual CVE lookup for a single package
func (d *CVEDB) queryPackage(pkg PackageInfo) ([]CVEEntry, error) {
	// Get all possible aliases for this package
	aliases := GetCommonAliases(pkg.Name)

	// Build query to search by CPE and direct product name
	// Strategy:
	// 1. Look in package_aliases for CPE vendor/product
	// 2. Also try direct match on affected_products.product
	var cveIDs []string
	cveIDSet := make(map[string]bool)

	// Query 1: Via package_aliases
	query1 := `
		SELECT DISTINCT ap.cve_id
		FROM package_aliases pa
		JOIN affected_products ap ON pa.cpe_vendor = ap.vendor AND pa.cpe_product = ap.product
		WHERE pa.package_name IN (` + buildPlaceholders(len(aliases)) + `)
	`
	if pkg.Source != "" {
		query1 += ` AND (pa.package_source = ? OR pa.package_source IS NULL)`
	}

	args := make([]interface{}, len(aliases))
	for i, alias := range aliases {
		args[i] = alias
	}
	if pkg.Source != "" {
		args = append(args, pkg.Source)
	}

	rows, err := d.db.Query(query1, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query via package_aliases: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			return nil, fmt.Errorf("failed to scan CVE ID: %w", err)
		}
		if !cveIDSet[cveID] {
			cveIDSet[cveID] = true
			cveIDs = append(cveIDs, cveID)
		}
	}

	// Query 2: Direct product name match
	query2 := `
		SELECT DISTINCT cve_id
		FROM affected_products
		WHERE product IN (` + buildPlaceholders(len(aliases)) + `)
	`

	rows2, err := d.db.Query(query2, args[:len(aliases)]...)
	if err != nil {
		return nil, fmt.Errorf("failed to query via product name: %w", err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var cveID string
		if err := rows2.Scan(&cveID); err != nil {
			return nil, fmt.Errorf("failed to scan CVE ID: %w", err)
		}
		if !cveIDSet[cveID] {
			cveIDSet[cveID] = true
			cveIDs = append(cveIDs, cveID)
		}
	}

	// Now fetch full CVE details for all matching IDs
	if len(cveIDs) == 0 {
		return []CVEEntry{}, nil
	}

	return d.getCVEDetails(cveIDs)
}

// getCVEDetails retrieves full CVE information for given CVE IDs
func (d *CVEDB) getCVEDetails(cveIDs []string) ([]CVEEntry, error) {
	if len(cveIDs) == 0 {
		return []CVEEntry{}, nil
	}

	query := `
		SELECT
			c.cve_id,
			c.description,
			c.severity,
			c.cvss_v3_score,
			c.cvss_v3_vector,
			c.published_date,
			c.modified_date,
			c.references_json,
			ap.version_start,
			ap.version_end,
			ap.version_start_type,
			ap.version_end_type
		FROM cves c
		LEFT JOIN affected_products ap ON c.cve_id = ap.cve_id
		WHERE c.cve_id IN (` + buildPlaceholders(len(cveIDs)) + `)
	`

	args := make([]interface{}, len(cveIDs))
	for i, id := range cveIDs {
		args[i] = id
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query CVE details: %w", err)
	}
	defer rows.Close()

	// Map to deduplicate CVEs (since LEFT JOIN can create multiple rows per CVE)
	cveMap := make(map[string]*CVEEntry)

	for rows.Next() {
		var (
			cveID                                                string
			description, severity, cvssVector                    string
			publishedDateStr, modifiedDateStr, referencesJSON    string
			cvssScore                                            float64
			versionStart, versionEnd                             sql.NullString
			versionStartType, versionEndType                     sql.NullString
		)

		err := rows.Scan(
			&cveID,
			&description,
			&severity,
			&cvssScore,
			&cvssVector,
			&publishedDateStr,
			&modifiedDateStr,
			&referencesJSON,
			&versionStart,
			&versionEnd,
			&versionStartType,
			&versionEndType,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CVE row: %w", err)
		}

		// Get or create CVE entry
		cve, exists := cveMap[cveID]
		if !exists {
			cve = &CVEEntry{
				CVEID:       cveID,
				Description: description,
				Severity:    severity,
				CVSSScore:   cvssScore,
				CVSSVector:  cvssVector,
			}

			// Parse dates
			if publishedDate, err := time.Parse(time.RFC3339, publishedDateStr); err == nil {
				cve.PublishedDate = publishedDate
			}
			if modifiedDate, err := time.Parse(time.RFC3339, modifiedDateStr); err == nil {
				cve.ModifiedDate = modifiedDate
			}

			// Parse references JSON
			if referencesJSON != "" {
				var refs []string
				if err := json.Unmarshal([]byte(referencesJSON), &refs); err == nil {
					cve.References = refs
				}
			}

			cveMap[cveID] = cve
		}

		// Update version constraints (take first non-null values)
		if versionStart.Valid && cve.VersionStart == "" {
			cve.VersionStart = versionStart.String
		}
		if versionEnd.Valid && cve.VersionEnd == "" {
			cve.VersionEnd = versionEnd.String
		}
		if versionStartType.Valid && cve.VersionStartType == "" {
			cve.VersionStartType = versionStartType.String
		}
		if versionEndType.Valid && cve.VersionEndType == "" {
			cve.VersionEndType = versionEndType.String
		}
	}

	// Convert map to slice
	cves := make([]CVEEntry, 0, len(cveMap))
	for _, cve := range cveMap {
		cves = append(cves, *cve)
	}

	return cves, nil
}

// buildPlaceholders builds a string of SQL placeholders (?, ?, ?)
func buildPlaceholders(count int) string {
	if count == 0 {
		return ""
	}
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = "?"
	}
	return strings.Join(placeholders, ", ")
}
