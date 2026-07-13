package cvedb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/logger"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// CVEDB represents a CVE database connection
type CVEDB struct {
	db     *sql.DB
	dbPath string

	schemaV2Once sync.Once
	schemaV2Val  bool
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

// schemaIsV2 reports whether the database schema version is 2 or newer. On a
// legacy (v1 or missing) schema it logs a one-time verbose warning, because
// Start-only/including rows are then treated as exact matches (a safe,
// rare-false-negative failure mode) rather than genuine ">=X" open ranges.
func (d *CVEDB) schemaIsV2() bool {
	d.schemaV2Once.Do(func() {
		var sv string
		_ = d.db.QueryRow("SELECT value FROM metadata WHERE key = 'schema_version'").Scan(&sv)
		n, _ := strconv.Atoi(strings.TrimSpace(sv))
		d.schemaV2Val = n >= 2
		if !d.schemaV2Val {
			logger.Verbose("CVE database schema is legacy (schema_version=%q); treating open '>=X' ranges as exact matches. Run 'dockerscan update-db' to refresh.", sv)
		}
	})
	return d.schemaV2Val
}

type vendorProduct struct{ vendor, product string }

// aliasVerifiedPairs returns the (vendor, product) pairs the package_aliases
// table maps this package's aliases to. These pairs are vendor-verified:
// versionless product-level CVE rows are only trusted for them.
func (d *CVEDB) aliasVerifiedPairs(aliases []string, source string) (map[vendorProduct]bool, error) {
	query := `
		SELECT DISTINCT vendor, product FROM package_aliases
		WHERE package_name IN (` + buildPlaceholders(len(aliases)) + `) AND (package_source = ? OR package_source = 'all')
	`
	args := make([]interface{}, 0, len(aliases)+1)
	for _, a := range aliases {
		args = append(args, a)
	}
	args = append(args, source)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query alias pairs: %w", err)
	}
	defer rows.Close()

	pairs := make(map[vendorProduct]bool)
	for rows.Next() {
		var v, p string
		if err := rows.Scan(&v, &p); err != nil {
			return nil, fmt.Errorf("failed to scan alias pair: %w", err)
		}
		pairs[vendorProduct{v, p}] = true
	}
	return pairs, rows.Err()
}

// queryPackage performs the actual CVE lookup for a single package. Version
// ranges come ONLY from affected_products rows matched by this package's
// aliases (direct product match, or via the package_aliases table for the
// package's source or the "all" source). CVE metadata is fetched separately by
// cve_id so it is never fanned out across unrelated products.
func (d *CVEDB) queryPackage(pkg PackageInfo) ([]CVEEntry, error) {
	aliases := GetCommonAliases(pkg.Name)
	if len(aliases) == 0 {
		return []CVEEntry{}, nil
	}

	placeholders := buildPlaceholders(len(aliases))
	// Portable UNION (no row-value IN); ORDER BY makes grouping deterministic.
	query := `
		SELECT ap.cve_id, ap.vendor, ap.product, ap.version_start, ap.version_end,
		       ap.version_start_type, ap.version_end_type
		FROM affected_products ap
		WHERE ap.product IN (` + placeholders + `)
		UNION
		SELECT ap.cve_id, ap.vendor, ap.product, ap.version_start, ap.version_end,
		       ap.version_start_type, ap.version_end_type
		FROM package_aliases pa
		JOIN affected_products ap ON pa.vendor = ap.vendor AND pa.product = ap.product
		WHERE pa.package_name IN (` + placeholders + `) AND (pa.package_source = ? OR pa.package_source = 'all')
		ORDER BY ap.cve_id, ap.vendor, ap.product
	`

	args := make([]interface{}, 0, len(aliases)*2+1)
	for _, a := range aliases {
		args = append(args, a)
	}
	for _, a := range aliases {
		args = append(args, a)
	}
	args = append(args, pkg.Source)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query affected products: %w", err)
	}
	defer rows.Close()

	verifiedPairs, err := d.aliasVerifiedPairs(aliases, pkg.Source)
	if err != nil {
		return nil, err
	}

	schemaV2 := d.schemaIsV2()

	type prodKey struct{ cveID, vendor, product string }
	prodByKey := make(map[prodKey]*ProductRanges)
	prodsByCVE := make(map[string][]*ProductRanges)
	var cveOrder []string
	cveSeen := make(map[string]bool)

	for rows.Next() {
		var (
			cveID, vendor, product       string
			vStart, vEnd, vStartT, vEndT sql.NullString
		)
		if err := rows.Scan(&cveID, &vendor, &product, &vStart, &vEnd, &vStartT, &vEndT); err != nil {
			return nil, fmt.Errorf("failed to scan affected product row: %w", err)
		}

		if !cveSeen[cveID] {
			cveSeen[cveID] = true
			cveOrder = append(cveOrder, cveID)
		}

		k := prodKey{cveID, vendor, product}
		pr, ok := prodByKey[k]
		if !ok {
			pr = &ProductRanges{
				Vendor:        vendor,
				Product:       product,
				AliasVerified: verifiedPairs[vendorProduct{vendor, product}],
			}
			prodByKey[k] = pr
			prodsByCVE[cveID] = append(prodsByCVE[cveID], pr)
		}

		vr := VersionRange{
			Start:     vStart.String,
			End:       vEnd.String,
			StartType: vStartT.String,
			EndType:   vEndT.String,
		}
		pr.Ranges = append(pr.Ranges, applySchemaGate(vr, schemaV2))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate affected product rows: %w", err)
	}

	if len(cveOrder) == 0 {
		return []CVEEntry{}, nil
	}

	meta, err := d.fetchCVEMetadata(cveOrder)
	if err != nil {
		return nil, err
	}

	cves := make([]CVEEntry, 0, len(cveOrder))
	for _, cveID := range cveOrder {
		cve, ok := meta[cveID]
		if !ok {
			continue // affected_products row without a matching cves row
		}
		for _, pr := range prodsByCVE[cveID] {
			cve.Products = append(cve.Products, *pr)
		}
		cves = append(cves, *cve)
	}

	return cves, nil
}

// applySchemaGate implements the C4 schema-version gate. On schema v2+ ranges
// are used as-is. On legacy schemas a Start-only/including row (no end bound)
// is reinterpreted as an exact match [Start,Start] so that open ">=X" rows do
// not match everything above X.
func applySchemaGate(vr VersionRange, schemaV2 bool) VersionRange {
	if schemaV2 {
		return vr
	}
	if vr.Start != "" && vr.StartType == "including" && vr.End == "" {
		vr.End = vr.Start
		vr.EndType = "including"
	}
	return vr
}

// fetchCVEMetadata retrieves CVE metadata (no product join) for the given IDs.
func (d *CVEDB) fetchCVEMetadata(cveIDs []string) (map[string]*CVEEntry, error) {
	query := `
		SELECT cve_id, description, severity, cvss_v3_score, cvss_v3_vector,
		       published_date, modified_date, references_json
		FROM cves
		WHERE cve_id IN (` + buildPlaceholders(len(cveIDs)) + `)
	`

	args := make([]interface{}, len(cveIDs))
	for i, id := range cveIDs {
		args[i] = id
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query CVE metadata: %w", err)
	}
	defer rows.Close()

	cveMap := make(map[string]*CVEEntry)
	for rows.Next() {
		var (
			cveID, description, severity, cvssVector          string
			publishedDateStr, modifiedDateStr, referencesJSON string
			cvssScore                                         float64
		)
		if err := rows.Scan(&cveID, &description, &severity, &cvssScore, &cvssVector,
			&publishedDateStr, &modifiedDateStr, &referencesJSON); err != nil {
			return nil, fmt.Errorf("failed to scan CVE metadata row: %w", err)
		}

		cve := &CVEEntry{
			CVEID:       cveID,
			Description: description,
			Severity:    severity,
			CVSSScore:   cvssScore,
			CVSSVector:  cvssVector,
		}
		if publishedDate, ok := parseDBTime(publishedDateStr); ok {
			cve.PublishedDate = publishedDate
		}
		if modifiedDate, ok := parseDBTime(modifiedDateStr); ok {
			cve.ModifiedDate = modifiedDate
		}
		if referencesJSON != "" {
			var refs []string
			if err := json.Unmarshal([]byte(referencesJSON), &refs); err == nil {
				cve.References = refs
			}
		}
		cveMap[cveID] = cve
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate CVE metadata rows: %w", err)
	}

	return cveMap, nil
}

// buildPlaceholders builds a string of SQL placeholders (?, ?, ?)
// parseDBTime parses the timestamp formats stored in the CVE database
// (NVD-style without timezone, or RFC3339).
func parseDBTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

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
