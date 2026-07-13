// Command nvd2sqlite-cvelistV5 builds the same SQLite CVE database as the
// nvd2sqlite tool, but sourcing data from the MITRE CVEProject/cvelistV5 GitHub
// release (a single zip snapshot of every CVE JSON 5.x record) instead of the
// NVD API. The output is a drop-in replacement consumed by
// internal/scanner/vulnerabilities via internal/cvedb.
package main

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	releaseAPIURL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
	userAgent     = "dockerscan-nvd2sqlite-cvelistv5/2.0"
	assetSuffix   = "_all_CVEs_at_midnight.zip.zip"
	batchSize     = 5000 // CVEs per SQLite transaction
	downloadTries = 3
)

// cvePathRe matches CVE JSON entries inside the archive, tolerating any leading
// path prefix (e.g. "cvelistV5-main/cves/2024/...").
var cvePathRe = regexp.MustCompile(`cves/.*/CVE-[^/]+\.json$`)

// Command-line flags.
var (
	outputPath = flag.String("output", "", "Output SQLite file path (required)")
	startDate  = flag.String("start-date", "", "Start date for CVEs (YYYY-MM-DD, default: 30 months ago)")
	endDate    = flag.String("end-date", "", "End date for CVEs (YYYY-MM-DD, default: now)")
	inputPath  = flag.String("input", "", "Path to a local baseline zip (skips download)")
	keepZip    = flag.Bool("keep-zip", false, "Do not delete the downloaded zip")
	verbose    = flag.Bool("verbose", false, "Verbose output")
)

// config holds the parsed runtime configuration for run().
type config struct {
	outputPath string
	start      time.Time
	end        time.Time
	inputPath  string
	keepZip    bool
	verbose    bool
}

// stats aggregates counters reported in the final summary.
type stats struct {
	cves      int
	products  int
	skipped   int
	malformed int
}

func main() {
	flag.Parse()

	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --output is required")
		flag.Usage()
		os.Exit(1)
	}

	start, err := parseDateFlag(*startDate, time.Now().AddDate(-2, -6, 0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing start-date: %v\n", err)
		os.Exit(1)
	}
	end, err := parseDateFlag(*endDate, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing end-date: %v\n", err)
		os.Exit(1)
	}

	cfg := config{
		outputPath: *outputPath,
		start:      start,
		end:        end,
		inputPath:  *inputPath,
		keepZip:    *keepZip,
		verbose:    *verbose,
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseDateFlag(value string, def time.Time) (time.Time, error) {
	if value == "" {
		return def, nil
	}
	return time.Parse("2006-01-02", value)
}

// run executes the full pipeline. It is separated from main() so it can be
// driven directly from tests.
func run(cfg config) error {
	// Banner.
	fmt.Println("🔍 nvd2sqlite-cvelistV5 - MITRE cvelistV5 to SQLite Converter")
	fmt.Printf("  Using %d parser workers\n", runtime.NumCPU())
	fmt.Println()

	// Phase 1: obtain the zip snapshot (local input or GitHub release download).
	zipPath := cfg.inputPath
	cleanupZip := func() {}
	if zipPath == "" {
		fmt.Println("📥 Phase 1: Downloading latest cvelistV5 release...")
		path, cleanup, err := downloadLatestRelease(cfg.verbose)
		if err != nil {
			return fmt.Errorf("download release: %w", err)
		}
		zipPath = path
		if cfg.keepZip {
			fmt.Printf("  Keeping downloaded zip: %s\n", zipPath)
		} else {
			cleanupZip = cleanup
		}
	} else {
		fmt.Printf("📥 Phase 1: Using local baseline zip: %s\n", zipPath)
	}
	defer cleanupZip()

	// Phase 2: open the archive (handling the .zip.zip nesting).
	fmt.Println("\n📦 Phase 2: Opening archive...")
	zr, files, cleanupArchive, err := openCVEArchive(zipPath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer cleanupArchive()
	_ = zr // kept open by cleanupArchive
	fmt.Printf("  Found %d CVE JSON files\n", len(files))

	// Phase 3: create database and process records.
	fmt.Println("\n🗄️  Phase 3: Building database...")
	db, err := initDatabase(cfg.outputPath)
	if err != nil {
		return fmt.Errorf("init database: %w", err)
	}
	defer db.Close()

	st, err := processFiles(db, files, cfg.start, cfg.end, cfg.verbose)
	if err != nil {
		return fmt.Errorf("process files: %w", err)
	}

	// Package aliases.
	fmt.Println("\n🔗 Inserting package aliases...")
	if err := insertAliases(db); err != nil {
		return fmt.Errorf("insert aliases: %w", err)
	}

	// Metadata.
	fmt.Println("📝 Updating metadata...")
	if err := updateMetadata(db, st.cves); err != nil {
		return fmt.Errorf("update metadata: %w", err)
	}

	// VACUUM.
	fmt.Println("🧹 Running VACUUM...")
	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("run VACUUM: %w", err)
	}

	// Summary.
	var sizeMB float64
	if fi, err := os.Stat(cfg.outputPath); err == nil {
		sizeMB = float64(fi.Size()) / (1024 * 1024)
	}
	fmt.Println("\n✅ Complete!")
	fmt.Printf("  Total CVEs: %d\n", st.cves)
	fmt.Printf("  Total affected products: %d\n", st.products)
	fmt.Printf("  Skipped (rejected/out-of-range): %d\n", st.skipped)
	fmt.Printf("  Malformed (skipped): %d\n", st.malformed)
	fmt.Printf("  Database size: %.1f MB\n", sizeMB)
	fmt.Printf("  Output: %s\n", cfg.outputPath)

	return nil
}

// initDatabase creates (or opens) the SQLite database and applies the schema.
// The schema is identical to the one produced by cmd/nvd2sqlite.
func initDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

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

	CREATE INDEX IF NOT EXISTS idx_affected_products_cve ON affected_products(cve_id);
	CREATE INDEX IF NOT EXISTS idx_affected_products_vendor_product ON affected_products(vendor, product);
	CREATE INDEX IF NOT EXISTS idx_package_aliases_lookup ON package_aliases(package_name, package_source);
	CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
	CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date);
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// parsedRecord is the unit of work passed from parser workers to the writer.
type parsedRecord struct {
	outcome int
	cve     cveRow
	prods   []productRow
}

// processFiles parses all CVE JSON entries using a worker pool and inserts them
// via a single writer goroutine that batches commits every batchSize CVEs.
func processFiles(db *sql.DB, files []*zip.File, start, end time.Time, verbose bool) (stats, error) {
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	jobs := make(chan *zip.File, numWorkers*4)
	results := make(chan parsedRecord, numWorkers*4)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				data, err := readZipEntry(f)
				if err != nil {
					results <- parsedRecord{outcome: outcomeMalformed}
					continue
				}
				outcome, cve, prods := parseRecord(data, start, end)
				results <- parsedRecord{outcome: outcome, cve: cve, prods: prods}
			}
		}()
	}

	go func() {
		for _, f := range files {
			jobs <- f
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return writeRecords(db, results, len(files), verbose)
}

// writeRecords consumes parsed records and writes them in batched transactions.
func writeRecords(db *sql.DB, results <-chan parsedRecord, total int, verbose bool) (stats, error) {
	var st stats

	tx, cveStmt, prodStmt, err := beginBatch(db)
	if err != nil {
		return st, err
	}
	batchCount := 0

	commit := func() error {
		cveStmt.Close()
		prodStmt.Close()
		return tx.Commit()
	}

	for r := range results {
		switch r.outcome {
		case outcomeMalformed:
			st.malformed++
			continue
		case outcomeSkippedRejected, outcomeSkippedDate:
			st.skipped++
			continue
		}

		if _, err := cveStmt.Exec(r.cve.ID, r.cve.Description, r.cve.Severity,
			r.cve.CVSSScore, r.cve.CVSSVector, r.cve.Published, r.cve.Modified,
			r.cve.ReferencesJSON); err != nil {
			tx.Rollback()
			return st, fmt.Errorf("insert cve %s: %w", r.cve.ID, err)
		}
		st.cves++

		for _, p := range r.prods {
			if _, err := prodStmt.Exec(r.cve.ID, p.Vendor, p.Product,
				p.VersionStart, p.VersionEnd, p.VersionStartType, p.VersionEndType); err != nil {
				tx.Rollback()
				return st, fmt.Errorf("insert product for %s: %w", r.cve.ID, err)
			}
			st.products++
		}

		batchCount++
		if batchCount >= batchSize {
			if err := commit(); err != nil {
				return st, fmt.Errorf("commit batch: %w", err)
			}
			if verbose {
				fmt.Printf("  Committed %d CVEs so far...\n", st.cves)
			}
			batchCount = 0
			tx, cveStmt, prodStmt, err = beginBatch(db)
			if err != nil {
				return st, err
			}
		}
	}

	if err := commit(); err != nil {
		return st, fmt.Errorf("commit final batch: %w", err)
	}

	return st, nil
}

// beginBatch opens a transaction and prepares the insert statements.
func beginBatch(db *sql.DB) (*sql.Tx, *sql.Stmt, *sql.Stmt, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, nil, nil, err
	}

	cveStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO cves
		(cve_id, description, severity, cvss_v3_score, cvss_v3_vector, published_date, modified_date, references_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return nil, nil, nil, err
	}

	prodStmt, err := tx.Prepare(`
		INSERT INTO affected_products
		(cve_id, vendor, product, version_start, version_end, version_start_type, version_end_type)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		cveStmt.Close()
		tx.Rollback()
		return nil, nil, nil, err
	}

	return tx, cveStmt, prodStmt, nil
}

// readZipEntry reads and decompresses a single zip entry fully into memory.
func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// openCVEArchive opens the zip at path and returns the CVE JSON entries. If the
// zip has no CVE entries but contains a nested *.zip (the .zip.zip case), that
// nested zip is extracted to a temp file and opened recursively. The returned
// cleanup closes the archive and removes any temp files.
func openCVEArchive(path string) (*zip.ReadCloser, []*zip.File, func(), error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open zip %s: %w", path, err)
	}

	var cveFiles []*zip.File
	var nestedZip *zip.File
	for _, f := range zr.File {
		if cvePathRe.MatchString(f.Name) {
			cveFiles = append(cveFiles, f)
		}
		if strings.HasSuffix(strings.ToLower(f.Name), ".zip") {
			if nestedZip == nil || f.UncompressedSize64 > nestedZip.UncompressedSize64 {
				nestedZip = f
			}
		}
	}

	if len(cveFiles) > 0 {
		return zr, cveFiles, func() { zr.Close() }, nil
	}

	if nestedZip != nil {
		innerPath, err := extractToTemp(nestedZip)
		zr.Close()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("extract nested zip: %w", err)
		}
		innerZr, innerFiles, innerCleanup, err := openCVEArchive(innerPath)
		if err != nil {
			os.Remove(innerPath)
			return nil, nil, nil, err
		}
		cleanup := func() {
			innerCleanup()
			os.Remove(innerPath)
		}
		return innerZr, innerFiles, cleanup, nil
	}

	zr.Close()
	return nil, nil, nil, fmt.Errorf("no CVE JSON files found in %s", path)
}

// extractToTemp writes a zip entry to a temp file and returns its path.
func extractToTemp(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "cvelistv5-inner-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// githubRelease models the GitHub "latest release" API response.
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// downloadLatestRelease fetches the latest cvelistV5 release, picks the
// all-CVEs asset and streams it to a temp file. The returned cleanup removes it.
func downloadLatestRelease(verbose bool) (string, func(), error) {
	name, url, size, err := findLatestAsset()
	if err != nil {
		return "", nil, err
	}
	fmt.Printf("  Asset: %s (%.0f MB)\n", name, float64(size)/(1024*1024))

	tmp, err := os.CreateTemp("", "cvelistv5-*.zip.zip")
	if err != nil {
		return "", nil, err
	}
	tmpPath := tmp.Name()
	tmp.Close()

	var lastErr error
	for attempt := 1; attempt <= downloadTries; attempt++ {
		if attempt > 1 && verbose {
			fmt.Printf("  Retry %d/%d after error: %v\n", attempt, downloadTries, lastErr)
		}
		if err := downloadTo(url, tmpPath); err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		os.Remove(tmpPath)
		return "", nil, fmt.Errorf("download after %d attempts: %w", downloadTries, lastErr)
	}

	cleanup := func() { os.Remove(tmpPath) }
	return tmpPath, cleanup, nil
}

// findLatestAsset queries the GitHub API and returns the all-CVEs asset details.
func findLatestAsset() (name, url string, size int64, err error) {
	req, err := http.NewRequest(http.MethodGet, releaseAPIURL, nil)
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", 0, fmt.Errorf("GitHub API HTTP %d: %s", resp.StatusCode, string(body))
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", 0, fmt.Errorf("decode release JSON: %w", err)
	}

	for _, a := range release.Assets {
		if strings.HasSuffix(a.Name, assetSuffix) {
			return a.Name, a.BrowserDownloadURL, a.Size, nil
		}
	}
	return "", "", 0, fmt.Errorf("no asset matching *%s in release %s", assetSuffix, release.TagName)
}

// downloadTo streams a URL to a file path, truncating any partial content.
func downloadTo(url, dest string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// defaultAliases mirrors the package aliases inserted by cmd/nvd2sqlite so the
// resulting database is a drop-in replacement.
var defaultAliases = []struct {
	Vendor, Product, PackageName, Source string
}{
	// OpenSSL
	{"openssl", "openssl", "openssl", "all"},
	{"openssl", "openssl", "libssl1.0.0", "dpkg"},
	{"openssl", "openssl", "libssl1.1", "dpkg"},
	{"openssl", "openssl", "libssl3", "dpkg"},
	{"openssl", "openssl", "libssl-dev", "dpkg"},
	{"openssl", "openssl", "libssl", "apk"},

	// glibc
	{"gnu", "glibc", "libc6", "dpkg"},
	{"gnu", "glibc", "libc-bin", "dpkg"},
	{"gnu", "glibc", "libc-dev-bin", "dpkg"},
	{"gnu", "glibc", "musl", "apk"},
	{"gnu", "glibc", "musl-utils", "apk"},

	// bash
	{"gnu", "bash", "bash", "all"},

	// curl
	{"haxx", "curl", "curl", "all"},
	{"haxx", "curl", "libcurl4", "dpkg"},
	{"haxx", "curl", "libcurl3-gnutls", "dpkg"},
	{"haxx", "curl", "libcurl", "apk"},

	// OpenSSH
	{"openbsd", "openssh", "openssh-server", "dpkg"},
	{"openbsd", "openssh", "openssh-client", "dpkg"},
	{"openbsd", "openssh", "openssh", "apk"},

	// sudo
	{"todd_miller", "sudo", "sudo", "all"},

	// Docker/containerd/runc
	{"linuxfoundation", "runc", "runc", "all"},
	{"docker", "docker", "docker-ce", "dpkg"},
	{"docker", "docker", "docker.io", "dpkg"},
	{"docker", "docker", "docker-cli", "dpkg"},
	{"docker", "docker", "docker", "apk"},
	{"containerd", "containerd", "containerd", "all"},

	// Git
	{"git-scm", "git", "git", "all"},

	// Python
	{"python", "python", "python3", "dpkg"},
	{"python", "python", "python3.8", "dpkg"},
	{"python", "python", "python3.9", "dpkg"},
	{"python", "python", "python3.10", "dpkg"},
	{"python", "python", "python3.11", "dpkg"},
	{"python", "python", "python3.12", "dpkg"},
	{"python", "python", "python3", "apk"},

	// Node.js
	{"nodejs", "node.js", "nodejs", "dpkg"},
	{"nodejs", "node.js", "nodejs", "apk"},

	// Apache
	{"apache", "http_server", "apache2", "dpkg"},
	{"apache", "http_server", "apache2-bin", "dpkg"},
	{"apache", "http_server", "apache2", "apk"},

	// nginx
	{"f5", "nginx", "nginx", "all"},
	{"f5", "nginx", "nginx-common", "dpkg"},

	// PostgreSQL
	{"postgresql", "postgresql", "postgresql", "dpkg"},
	{"postgresql", "postgresql", "postgresql-client", "dpkg"},
	{"postgresql", "postgresql", "postgresql-common", "dpkg"},
	{"postgresql", "postgresql", "postgresql", "apk"},

	// MySQL/MariaDB
	{"oracle", "mysql", "mysql-server", "dpkg"},
	{"oracle", "mysql", "mysql-client", "dpkg"},
	{"mariadb", "mariadb", "mariadb-server", "dpkg"},
	{"mariadb", "mariadb", "mariadb-client", "dpkg"},
	{"mariadb", "mariadb", "mariadb", "apk"},

	// Redis
	{"redis", "redis", "redis-server", "dpkg"},
	{"redis", "redis", "redis", "apk"},

	// zlib (vendor/product "zlib" in CVE data; the historical gnu/gzip mapping
	// was wrong and leaked gzip CVEs into zlib packages)
	{"zlib", "zlib", "zlib1g", "dpkg"},
	{"zlib", "zlib", "zlib", "apk"},

	// systemd
	{"systemd_project", "systemd", "systemd", "dpkg"},
	{"systemd_project", "systemd", "libsystemd0", "dpkg"},

	// Perl
	{"perl", "perl", "perl", "all"},
	{"perl", "perl", "perl-base", "dpkg"},

	// Java
	{"oracle", "jdk", "openjdk-11-jre", "dpkg"},
	{"oracle", "jdk", "openjdk-17-jre", "dpkg"},
	{"oracle", "jdk", "openjdk", "apk"},

	// Linux kernel
	{"linux", "linux_kernel", "linux-image-generic", "dpkg"},
	{"linux", "linux_kernel", "linux-headers", "apkg"},
}

func insertAliases(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO package_aliases
		(vendor, product, package_name, package_source)
		VALUES (?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, alias := range defaultAliases {
		if _, err := stmt.Exec(alias.Vendor, alias.Product, alias.PackageName, alias.Source); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func updateMetadata(db *sql.DB, totalCVEs int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339)
	metadata := map[string]string{
		"version":        "1.0",
		"created_at":     now,
		"last_modified":  now, // Used by dockerscan to check database age
		"nvd_source":     "MITRE cvelistV5",
		"total_cves":     fmt.Sprintf("%d", totalCVEs),
		"schema_version": "2",
	}

	for key, value := range metadata {
		if _, err := stmt.Exec(key, value); err != nil {
			return err
		}
	}

	return tx.Commit()
}
