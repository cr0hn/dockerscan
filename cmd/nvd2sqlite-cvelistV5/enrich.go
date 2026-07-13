package main

// Optional, best-effort CVSS enrichment from the NVD API 2.0.
//
// About 7% of CVEs sourced from the MITRE cvelistV5 baseline lack CVSS metrics
// (severity UNKNOWN/NONE) because the CNA did not provide them; NVD publishes
// them later. This phase fills those gaps when the NVD API is reachable and is
// deliberately non-blocking: any network/NVD problem is downgraded to a warning
// so the build always succeeds with whatever was already updated. Only
// programming/SQL errors are fatal.
//
// The retry/rate-limit structure mirrors queryNVD in the deprecated
// cmd/nvd2sqlite tool, reimplemented locally so that tool is not imported.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	nvdEnrichBaseURL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdEnrichPerPage     = 2000
	nvdEnrichMaxRange    = 120 // days per pubStartDate/pubEndDate chunk (NVD max)
	nvdEnrichRate        = 6 * time.Second
	nvdEnrichMaxAttempts = 4                // 1 initial + 3 retries on transient errors
	nvdEnrichBaseBackoff = 30 * time.Second // exponential base between retries
	nvdEnrichBatchSize   = 500              // UPDATEs per SQLite transaction
	nvdEnrichHTTPTimeout = 300 * time.Second
)

// NVD API 2.0 response subset. Only the fields needed for CVSS enrichment are
// modelled; everything else is ignored by encoding/json.
type nvdEnrichResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE struct {
		ID      string `json:"id"`
		Metrics struct {
			CvssMetricV31 []nvdMetric `json:"cvssMetricV31"`
			CvssMetricV30 []nvdMetric `json:"cvssMetricV30"`
			CvssMetricV2  []nvdMetric `json:"cvssMetricV2"`
		} `json:"metrics"`
	} `json:"cve"`
}

type nvdMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// extractedCVSS is the normalized CVSS pulled from an NVD vulnerability item.
type extractedCVSS struct {
	score    float64
	severity string
	vector   string
	ok       bool
}

// extractCVSS returns the preferred CVSS for a vulnerability, trying v3.1, then
// v3.0, then v2. For v2 the severity is derived from the base score since the
// v2 cvssData block does not carry a base severity.
func extractCVSS(v nvdVuln) extractedCVSS {
	m := v.CVE.Metrics
	if len(m.CvssMetricV31) > 0 {
		d := m.CvssMetricV31[0].CvssData
		return extractedCVSS{score: d.BaseScore, severity: strings.ToUpper(d.BaseSeverity), vector: d.VectorString, ok: true}
	}
	if len(m.CvssMetricV30) > 0 {
		d := m.CvssMetricV30[0].CvssData
		return extractedCVSS{score: d.BaseScore, severity: strings.ToUpper(d.BaseSeverity), vector: d.VectorString, ok: true}
	}
	if len(m.CvssMetricV2) > 0 {
		d := m.CvssMetricV2[0].CvssData
		return extractedCVSS{score: d.BaseScore, severity: deriveV2Severity(d.BaseScore), vector: d.VectorString, ok: true}
	}
	return extractedCVSS{}
}

// deriveV2Severity maps a CVSS v2 base score to a qualitative severity using the
// NVD thresholds (>=7 HIGH, >=4 MEDIUM, else LOW).
func deriveV2Severity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// cvssUpdate is a single row-level CVSS update.
type cvssUpdate struct {
	cveID    string
	severity string
	score    float64
	vector   string
}

// enrichChunk is a pubStartDate/pubEndDate window.
type enrichChunk struct {
	start, end time.Time
}

// enrichDateChunks splits [start, end] into <=nvdEnrichMaxRange-day windows,
// mirroring the chunking used by the deprecated cmd/nvd2sqlite tool.
func enrichDateChunks(start, end time.Time) []enrichChunk {
	var chunks []enrichChunk
	current := start
	for current.Before(end) {
		chunkEnd := current.AddDate(0, 0, nvdEnrichMaxRange)
		if chunkEnd.After(end) {
			chunkEnd = end
		}
		chunks = append(chunks, enrichChunk{start: current, end: chunkEnd})
		current = chunkEnd
	}
	return chunks
}

// buildEnrichURL constructs an NVD API 2.0 query URL for a page of a window.
func buildEnrichURL(base string, start, end time.Time, startIndex int) string {
	startStr := start.Format("2006-01-02T15:04:05.000Z")
	endStr := end.Format("2006-01-02T15:04:05.000Z")
	return fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&resultsPerPage=%d&startIndex=%d",
		base, startStr, endStr, nvdEnrichPerPage, startIndex)
}

// rateLimiter enforces a minimum spacing between requests, honouring context
// cancellation while it waits.
type rateLimiter struct {
	interval time.Duration
	last     time.Time
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if !r.last.IsZero() {
		if remaining := r.interval - time.Since(r.last); remaining > 0 {
			t := time.NewTimer(remaining)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	r.last = time.Now()
	return nil
}

// nvdClient fetches NVD pages with retry/backoff. It is a small value so tests
// can point baseURL at an httptest server and shrink baseBackoff.
type nvdClient struct {
	httpClient  *http.Client
	apiKey      string
	maxAttempts int
	baseBackoff time.Duration
	verbose     bool
}

// fetchPage GETs a single NVD page, retrying on 429/5xx, network errors and
// body-read timeouts with exponential backoff. Context cancellation aborts.
func (c *nvdClient) fetchPage(ctx context.Context, url string) (*nvdEnrichResponse, error) {
	var lastErr error
	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		if attempt > 0 {
			backoff := c.baseBackoff * time.Duration(1<<(attempt-1))
			if c.verbose {
				fmt.Printf("    ⚠️  %v, waiting %v before retry %d/%d...\n", lastErr, backoff, attempt+1, c.maxAttempts)
			}
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if c.apiKey != "" {
			// NVD API 2.0 expects the key in the "apiKey" header, not the URL.
			req.Header.Set("apiKey", c.apiKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err // network error or timeout: retryable
			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			var out nvdEnrichResponse
			err := json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if err != nil {
				lastErr = fmt.Errorf("read body: %w", err) // truncation/timeout: retryable
				continue
			}
			return &out, nil

		case http.StatusTooManyRequests, http.StatusServiceUnavailable,
			http.StatusBadGateway, http.StatusGatewayTimeout:
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue

		default:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
	}
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// collectEnrichTargets returns the set of CVE IDs still missing CVSS.
func collectEnrichTargets(db *sql.DB) (map[string]struct{}, error) {
	rows, err := db.Query(`SELECT cve_id FROM cves WHERE severity IN ('UNKNOWN','NONE')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := make(map[string]struct{})
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		targets[id] = struct{}{}
	}
	return targets, rows.Err()
}

// countUnknownSeverity counts the CVEs still lacking CVSS.
func countUnknownSeverity(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM cves WHERE severity IN ('UNKNOWN','NONE')`).Scan(&n)
	return n, err
}

// updateCVSSBatch applies a batch of CVSS updates in a single transaction. The
// WHERE clause restricts changes to rows still marked UNKNOWN/NONE, so rows that
// already carry a real severity are never overwritten. Returns rows changed.
func updateCVSSBatch(db *sql.DB, updates []cvssUpdate) (int, error) {
	if len(updates) == 0 {
		return 0, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE cves SET severity=?, cvss_v3_score=?, cvss_v3_vector=? WHERE cve_id=? AND severity IN ('UNKNOWN','NONE')`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	changed := 0
	for _, u := range updates {
		res, err := stmt.Exec(u.severity, u.score, u.vector, u.cveID)
		if err != nil {
			return changed, err
		}
		if n, err := res.RowsAffected(); err == nil {
			changed += int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return changed, err
	}
	return changed, nil
}

// applyEnrichmentPage extracts CVSS for the target CVEs found in one NVD page
// and writes them in transactions of at most nvdEnrichBatchSize rows. Returns
// the number of rows changed.
func applyEnrichmentPage(db *sql.DB, vulns []nvdVuln, targets map[string]struct{}) (int, error) {
	var updates []cvssUpdate
	for _, v := range vulns {
		id := v.CVE.ID
		if _, ok := targets[id]; !ok {
			continue
		}
		c := extractCVSS(v)
		if !c.ok || c.severity == "" {
			continue
		}
		updates = append(updates, cvssUpdate{cveID: id, severity: c.severity, score: c.score, vector: c.vector})
	}

	changed := 0
	for i := 0; i < len(updates); i += nvdEnrichBatchSize {
		j := i + nvdEnrichBatchSize
		if j > len(updates) {
			j = len(updates)
		}
		n, err := updateCVSSBatch(db, updates[i:j])
		if err != nil {
			return changed, err
		}
		changed += n
	}
	return changed, nil
}

// enrichFromNVDPhase fills missing CVSS from the NVD API 2.0. It is best effort:
// network/NVD failures and the time bound end the phase gracefully, keeping
// whatever was already updated, and return nil. Only SQL/programming errors are
// returned as fatal.
func enrichFromNVDPhase(db *sql.DB, start, end time.Time, timeout time.Duration, verbose bool) error {
	fmt.Println("\n💉 Enrichment phase: filling missing CVSS from NVD API 2.0 (best effort)...")

	targets, err := collectEnrichTargets(db)
	if err != nil {
		return fmt.Errorf("collect enrichment targets: %w", err)
	}
	totalTargets := len(targets)
	if totalTargets == 0 {
		fmt.Println("  No CVEs need enrichment (none with UNKNOWN/NONE severity). Skipping.")
		return nil
	}
	fmt.Printf("  %d CVEs missing CVSS; querying NVD over %s..%s (timeout %s)\n",
		totalTargets, start.Format("2006-01-02"), end.Format("2006-01-02"), timeout)

	apiKey := os.Getenv("NVD_API_KEY")
	if verbose {
		if apiKey != "" {
			fmt.Println("  Using NVD_API_KEY from environment")
		} else {
			fmt.Println("  No NVD_API_KEY set; running keyless (6s request spacing)")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &nvdClient{
		httpClient:  &http.Client{Timeout: nvdEnrichHTTPTimeout},
		apiKey:      apiKey,
		maxAttempts: nvdEnrichMaxAttempts,
		baseBackoff: nvdEnrichBaseBackoff,
		verbose:     verbose,
	}
	limiter := &rateLimiter{interval: nvdEnrichRate}

	updated := 0
	pageCount := 0
	stopReason := "date window exhausted"

	chunks := enrichDateChunks(start, end)
loop:
	for _, chunk := range chunks {
		startIndex := 0
		for {
			if err := limiter.wait(ctx); err != nil {
				stopReason = fmt.Sprintf("timeout reached after page %d", pageCount)
				break loop
			}

			url := buildEnrichURL(nvdEnrichBaseURL, chunk.start, chunk.end, startIndex)
			resp, err := client.fetchPage(ctx, url)
			pageCount++
			if err != nil {
				stopReason = fmt.Sprintf("NVD unavailable after page %d (%v)", pageCount, err)
				break loop
			}

			n, err := applyEnrichmentPage(db, resp.Vulnerabilities, targets)
			if err != nil {
				return fmt.Errorf("apply enrichment page: %w", err)
			}
			updated += n
			if verbose {
				fmt.Printf("    page %d: %d NVD items, %d updates applied (total %d)\n",
					pageCount, len(resp.Vulnerabilities), n, updated)
			}

			startIndex += nvdEnrichPerPage
			if startIndex >= resp.TotalResults {
				break
			}
		}
	}

	remaining, err := countUnknownSeverity(db)
	if err != nil {
		return fmt.Errorf("count remaining: %w", err)
	}

	fmt.Printf("  Enrichment summary: enriched %d of %d; %d still UNKNOWN/NONE (%s)\n",
		updated, totalTargets, remaining, stopReason)
	return nil
}
