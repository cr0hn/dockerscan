package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	nvdBaseURL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	maxDateRangeDays = 120 // NVD API max date range
	defaultRateLimit = 5   // Requests per 30 seconds without API key
	resultsPerPage   = 2000
	numDownloaders   = 4   // Number of parallel download workers
	maxRetries       = 5   // Max retries for rate-limited requests
	baseBackoff      = 30 * time.Second // Base backoff for 429 errors
)

// Command-line flags
var (
	outputPath = flag.String("output", "", "Output SQLite file path (required)")
	startDate  = flag.String("start-date", "", "Start date for CVEs (YYYY-MM-DD, default: 2.5 years ago)")
	endDate    = flag.String("end-date", "", "End date for CVEs (YYYY-MM-DD, default: now)")
	apiKey     = flag.String("api-key", "", "NVD API key (optional, env: NVD_API_KEY)")
	rateLimit  = flag.Int("rate-limit", defaultRateLimit, "Requests per 30 seconds")
	verbose    = flag.Bool("verbose", false, "Verbose output")
)

// NVD API response structures
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CpeMatch []struct {
						Vulnerable            bool   `json:"vulnerable"`
						Criteria              string `json:"criteria"` // CPE 2.3 string
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
						VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
						VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// downloadTask represents a single download job
type downloadTask struct {
	chunk      dateChunk
	chunkIndex int
	startIndex int
	pageIndex  int
}

// downloadResult represents the result of a download
type downloadResult struct {
	task     downloadTask
	filePath string
	err      error
}

// Predefined package aliases
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

	// zlib
	{"gnu", "gzip", "zlib1g", "dpkg"},
	{"gnu", "gzip", "zlib", "apk"},

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

func main() {
	flag.Parse()

	if *outputPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --output is required")
		flag.Usage()
		os.Exit(1)
	}

	// Get API key from env if not provided
	if *apiKey == "" {
		*apiKey = os.Getenv("NVD_API_KEY")
	}

	// Adjust rate limit based on API key
	if *apiKey != "" && *rateLimit == defaultRateLimit {
		*rateLimit = 50 // Higher limit with API key
	}

	// Parse dates
	var start, end time.Time
	var err error

	if *startDate == "" {
		start = time.Now().AddDate(-2, -6, 0) // 2.5 years ago
	} else {
		start, err = time.Parse("2006-01-02", *startDate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing start-date: %v\n", err)
			os.Exit(1)
		}
	}

	if *endDate == "" {
		end = time.Now()
	} else {
		end, err = time.Parse("2006-01-02", *endDate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing end-date: %v\n", err)
			os.Exit(1)
		}
	}

	// Banner
	fmt.Println("nvd2sqlite - NVD to SQLite Converter")
	fmt.Printf("  Using %d parallel downloaders\n", numDownloaders)
	fmt.Println()

	// Create temporary directory for downloads
	tmpDir, err := os.MkdirTemp("", "nvd2sqlite-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	if *verbose {
		fmt.Printf("  Temp directory: %s\n", tmpDir)
	}

	// Phase 1: Download CVEs in parallel
	fmt.Printf("Phase 1: Downloading CVEs from %s to %s...\n", start.Format("2006-01-02"), end.Format("2006-01-02"))
	downloadedFiles, err := downloadCVEsParallel(tmpDir, start, end)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading CVEs: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Downloaded %d files\n\n", len(downloadedFiles))

	// Phase 2: Create/open database and process files sequentially
	fmt.Println("Phase 2: Processing downloaded files...")
	db, err := initDatabase(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	totalCVEs, totalProducts, err := processDownloadedFiles(db, downloadedFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error processing files: %v\n", err)
		os.Exit(1)
	}

	// Insert package aliases
	fmt.Println("\nInserting package aliases...")
	if err := insertAliases(db); err != nil {
		fmt.Fprintf(os.Stderr, "Error inserting aliases: %v\n", err)
		os.Exit(1)
	}

	// Update metadata
	fmt.Println("Updating metadata...")
	if err := updateMetadata(db, totalCVEs); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating metadata: %v\n", err)
		os.Exit(1)
	}

	// VACUUM database
	fmt.Println("Running VACUUM...")
	if _, err := db.Exec("VACUUM"); err != nil {
		fmt.Fprintf(os.Stderr, "Error running VACUUM: %v\n", err)
		os.Exit(1)
	}

	// Get file size
	fileInfo, _ := os.Stat(*outputPath)
	sizeMB := float64(fileInfo.Size()) / (1024 * 1024)

	// Summary
	fmt.Println("\nComplete!")
	fmt.Printf("  Total CVEs: %d\n", totalCVEs)
	fmt.Printf("  Total affected products: %d\n", totalProducts)
	fmt.Printf("  Database size: %.1f MB\n", sizeMB)
	fmt.Printf("  Output: %s\n", *outputPath)
}

func initDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

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

	CREATE INDEX IF NOT EXISTS idx_affected_products_cve ON affected_products(cve_id);
	CREATE INDEX IF NOT EXISTS idx_affected_products_vendor_product ON affected_products(vendor, product);
	CREATE INDEX IF NOT EXISTS idx_package_aliases_lookup ON package_aliases(package_name, package_source);
	CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
	CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date);
	`

	_, err = db.Exec(schema)
	return db, err
}

// downloadCVEsParallel downloads CVEs using multiple workers in parallel
func downloadCVEsParallel(tmpDir string, start, end time.Time) ([]string, error) {
	chunks := calculateDateChunks(start, end)

	// First, we need to discover all pages for each chunk
	// This requires sequential queries to get TotalResults
	fmt.Printf("  Discovering pages for %d date chunks...\n", len(chunks))

	var allTasks []downloadTask
	var tasksMu sync.Mutex

	// Rate limiter shared across all workers
	rateLimiter := time.NewTicker(time.Duration(30000.0/float64(*rateLimit)) * time.Millisecond)
	defer rateLimiter.Stop()

	// Discover tasks sequentially (we need TotalResults from each chunk)
	for i, chunk := range chunks {
		<-rateLimiter.C

		url := buildNVDURL(chunk.start, chunk.end, 0)
		resp, err := queryNVD(url)
		if err != nil {
			return nil, fmt.Errorf("discover chunk %d: %w", i+1, err)
		}

		// Calculate number of pages needed
		totalPages := (resp.TotalResults + resultsPerPage - 1) / resultsPerPage
		if totalPages == 0 {
			totalPages = 1
		}

		if *verbose {
			fmt.Printf("    Chunk %d/%d (%s to %s): %d CVEs, %d pages\n",
				i+1, len(chunks),
				chunk.start.Format("2006-01-02"), chunk.end.Format("2006-01-02"),
				resp.TotalResults, totalPages)
		}

		// Save first page (we already have it)
		filePath := filepath.Join(tmpDir, fmt.Sprintf("chunk%03d_page%03d.json", i, 0))
		if err := saveResponse(resp, filePath); err != nil {
			return nil, fmt.Errorf("save first page: %w", err)
		}

		tasksMu.Lock()
		// Add remaining pages as tasks
		for page := 1; page < totalPages; page++ {
			allTasks = append(allTasks, downloadTask{
				chunk:      chunk,
				chunkIndex: i,
				startIndex: page * resultsPerPage,
				pageIndex:  page,
			})
		}
		tasksMu.Unlock()
	}

	fmt.Printf("  Downloading %d additional pages with %d workers...\n", len(allTasks), numDownloaders)

	// Channel for tasks
	taskChan := make(chan downloadTask, len(allTasks))
	resultChan := make(chan downloadResult, len(allTasks))

	// Start workers
	var wg sync.WaitGroup
	var downloadedCount int64

	for w := 0; w < numDownloaders; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for task := range taskChan {
				// Rate limit
				<-rateLimiter.C

				url := buildNVDURL(task.chunk.start, task.chunk.end, task.startIndex)
				resp, err := queryNVD(url)

				if err != nil {
					resultChan <- downloadResult{task: task, err: err}
					continue
				}

				filePath := filepath.Join(tmpDir, fmt.Sprintf("chunk%03d_page%03d.json", task.chunkIndex, task.pageIndex))
				if err := saveResponse(resp, filePath); err != nil {
					resultChan <- downloadResult{task: task, err: err}
					continue
				}

				resultChan <- downloadResult{task: task, filePath: filePath}

				count := atomic.AddInt64(&downloadedCount, 1)
				if *verbose {
					fmt.Printf("    [Worker %d] Downloaded page %d of chunk %d (%d/%d)\n",
						workerID, task.pageIndex, task.chunkIndex+1, count, len(allTasks))
				}
			}
		}(w)
	}

	// Send all tasks
	for _, task := range allTasks {
		taskChan <- task
	}
	close(taskChan)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var errors []error
	for result := range resultChan {
		if result.err != nil {
			errors = append(errors, fmt.Errorf("chunk %d page %d: %w",
				result.task.chunkIndex+1, result.task.pageIndex, result.err))
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("download errors: %v", errors)
	}

	// Collect all downloaded files
	files, err := filepath.Glob(filepath.Join(tmpDir, "*.json"))
	if err != nil {
		return nil, err
	}

	// Sort files to ensure consistent processing order
	sort.Strings(files)

	return files, nil
}

// saveResponse saves an NVD response to a JSON file
func saveResponse(resp *NVDResponse, filePath string) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// processDownloadedFiles processes all downloaded JSON files sequentially
func processDownloadedFiles(db *sql.DB, files []string) (int, int, error) {
	totalCVEs := 0
	totalProducts := 0

	for i, filePath := range files {
		if *verbose {
			fmt.Printf("  Processing file %d/%d: %s\n", i+1, len(files), filepath.Base(filePath))
		}

		// Read and parse file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return totalCVEs, totalProducts, fmt.Errorf("read file %s: %w", filePath, err)
		}

		var resp NVDResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return totalCVEs, totalProducts, fmt.Errorf("parse file %s: %w", filePath, err)
		}

		// Insert CVEs
		cveCount, prodCount, err := insertCVEs(db, &resp)
		if err != nil {
			return totalCVEs, totalProducts, fmt.Errorf("insert CVEs from %s: %w", filePath, err)
		}

		totalCVEs += cveCount
		totalProducts += prodCount

		if !*verbose && (i+1)%10 == 0 {
			fmt.Printf("  Processed %d/%d files (%d CVEs so far)\n", i+1, len(files), totalCVEs)
		}
	}

	return totalCVEs, totalProducts, nil
}

type dateChunk struct {
	start, end time.Time
}

func calculateDateChunks(start, end time.Time) []dateChunk {
	var chunks []dateChunk
	current := start

	for current.Before(end) {
		chunkEnd := current.AddDate(0, 0, maxDateRangeDays)
		if chunkEnd.After(end) {
			chunkEnd = end
		}
		chunks = append(chunks, dateChunk{start: current, end: chunkEnd})
		current = chunkEnd
	}

	return chunks
}

func buildNVDURL(start, end time.Time, startIndex int) string {
	// ISO-8601 format with milliseconds
	startStr := start.Format("2006-01-02T15:04:05.000Z")
	endStr := end.Format("2006-01-02T15:04:05.000Z")

	url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%d&startIndex=%d",
		nvdBaseURL, startStr, endStr, resultsPerPage, startIndex)

	if *apiKey != "" {
		url += "&apiKey=" + *apiKey
	}

	return url
}

func queryNVD(url string) (*NVDResponse, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("User-Agent", "dockerscan-nvd2sqlite/2.0")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Handle rate limiting (429)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			backoff := baseBackoff * time.Duration(1<<attempt) // Exponential backoff
			if *verbose {
				fmt.Printf("    ⚠️  Rate limited (429), waiting %v before retry %d/%d...\n",
					backoff, attempt+1, maxRetries)
			}
			time.Sleep(backoff)
			lastErr = fmt.Errorf("rate limited (attempt %d)", attempt+1)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}

		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		return &nvdResp, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func insertCVEs(db *sql.DB, resp *NVDResponse) (int, int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	cveStmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO cves
		(cve_id, description, severity, cvss_v3_score, cvss_v3_vector, published_date, modified_date, references_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, 0, err
	}
	defer cveStmt.Close()

	prodStmt, err := tx.Prepare(`
		INSERT INTO affected_products
		(cve_id, vendor, product, version_start, version_end, version_start_type, version_end_type)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, 0, err
	}
	defer prodStmt.Close()

	cveCount := 0
	prodCount := 0

	for _, vuln := range resp.Vulnerabilities {
		cve := vuln.CVE

		// Get English description
		description := ""
		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		// Get CVSS v3 metrics
		severity := "UNKNOWN"
		var cvssScore float64
		cvssVector := ""

		if len(cve.Metrics.CvssMetricV31) > 0 {
			metric := cve.Metrics.CvssMetricV31[0].CvssData
			severity = metric.BaseSeverity
			cvssScore = metric.BaseScore
			cvssVector = metric.VectorString
		}

		// Get references
		var refs []string
		for _, ref := range cve.References {
			refs = append(refs, ref.URL)
		}
		refsJSON, _ := json.Marshal(refs)

		// Insert CVE
		_, err = cveStmt.Exec(cve.ID, description, severity, cvssScore, cvssVector,
			cve.Published, cve.LastModified, string(refsJSON))
		if err != nil {
			return 0, 0, err
		}
		cveCount++

		// Insert affected products
		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, cpe := range node.CpeMatch {
					if !cpe.Vulnerable {
						continue
					}

					vendor, product := parseCPE(cpe.Criteria)
					if vendor == "" || product == "" {
						continue
					}

					// Determine version range types
					startType := ""
					if cpe.VersionStartIncluding != "" {
						startType = "including"
					} else if cpe.VersionStartExcluding != "" {
						startType = "excluding"
					}

					endType := ""
					if cpe.VersionEndIncluding != "" {
						endType = "including"
					} else if cpe.VersionEndExcluding != "" {
						endType = "excluding"
					}

					versionStart := cpe.VersionStartIncluding
					if versionStart == "" {
						versionStart = cpe.VersionStartExcluding
					}

					versionEnd := cpe.VersionEndIncluding
					if versionEnd == "" {
						versionEnd = cpe.VersionEndExcluding
					}

					_, err = prodStmt.Exec(cve.ID, vendor, product,
						versionStart, versionEnd, startType, endType)
					if err != nil {
						return 0, 0, err
					}
					prodCount++
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}

	return cveCount, prodCount, nil
}

// parseCPE extracts vendor and product from CPE 2.3 format
// Format: cpe:2.3:a:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
func parseCPE(cpe string) (string, string) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return "", ""
	}

	vendor := parts[3]
	product := parts[4]

	// Unescape CPE encoding
	vendor = strings.ReplaceAll(vendor, "\\:", ":")
	product = strings.ReplaceAll(product, "\\:", ":")

	return vendor, product
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
		_, err = stmt.Exec(alias.Vendor, alias.Product, alias.PackageName, alias.Source)
		if err != nil {
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

	metadata := map[string]string{
		"version":        "1.0",
		"created_at":     time.Now().Format(time.RFC3339),
		"nvd_source":     "NVD API 2.0",
		"total_cves":     fmt.Sprintf("%d", totalCVEs),
		"schema_version": "1",
	}

	for key, value := range metadata {
		_, err = stmt.Exec(key, value)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
