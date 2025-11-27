package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/config"
	"github.com/cr0hn/dockerscan/v2/internal/cvedb"
	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/report"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/cis"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/runtime"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/secrets"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/supplychain"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/vulnerabilities"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

const (
	defaultDBPath = "~/.dockerscan/cve-db.sqlite"
)

func main() {
	// Print banner
	fmt.Print(config.Banner())

	// Handle subcommands
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "update-db":
			if err := handleUpdateDB(); err != nil {
				fmt.Fprintf(os.Stderr, "\n❌ Error: %v\n", err)
				os.Exit(1)
			}
			return
		case "version", "--version", "-v":
			fmt.Printf("dockerscan %s\n", config.Version)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	// Initialize CVE database (REQUIRED)
	dbPath := expandPath(defaultDBPath)
	cveDB, err := cvedb.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ Error: CVE database not available.\n")
		fmt.Fprintf(os.Stderr, "   Run 'dockerscan update-db' to download the vulnerability database.\n")
		fmt.Fprintf(os.Stderr, "   Details: %v\n\n", err)
		os.Exit(1)
	}
	defer cveDB.Close()

	// Warn if database is outdated
	warnIfOutdated(cveDB)

	// Parse CLI arguments
	ctx := context.Background()
	cfg := config.NewDefaultConfig()

	// Get image name from args
	// Support both: dockerscan <image> and dockerscan scan <image>
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var imageName string
	if os.Args[1] == "scan" {
		if len(os.Args) < 3 {
			fmt.Println("\nUsage: dockerscan scan <image-name>")
			fmt.Println("\nExample:")
			fmt.Println("  dockerscan scan nginx:latest")
			os.Exit(1)
		}
		imageName = os.Args[2]
	} else {
		imageName = os.Args[1]
	}

	// Create Docker client
	dockerClient, err := docker.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Docker client: %v\n", err)
		os.Exit(1)
	}
	defer dockerClient.Close()

	// Create scanner registry
	registry := scanner.NewRegistry()

	// Register all scanners
	registry.Register(cis.NewCISScanner(dockerClient))
	registry.Register(secrets.NewSecretsScanner(dockerClient))
	registry.Register(supplychain.NewSupplyChainScanner(dockerClient))
	registry.Register(vulnerabilities.NewVulnerabilityScanner(dockerClient, cveDB))
	registry.Register(runtime.NewRuntimeScanner(dockerClient))

	fmt.Printf("\n🔍 Scanning image: %s\n", imageName)

	// Check if image exists locally
	exists, err := dockerClient.ImageExists(ctx, imageName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking image: %v\n", err)
		os.Exit(1)
	}

	if !exists {
		fmt.Printf("   Image not found locally. Pulling from registry...\n")
		if err := dockerClient.PullImage(ctx, imageName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Image '%s' not found locally and could not be pulled from registry.\n", imageName)
			fmt.Fprintf(os.Stderr, "       Please check the image name and try again.\n")
			fmt.Fprintf(os.Stderr, "       Details: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("   Image pulled successfully.\n")
	}

	fmt.Println()

	// Create scan target
	target := models.ScanTarget{
		ImageName: imageName,
	}

	// Run all scanners
	startTime := time.Now()
	findings, stats, err := registry.ScanAll(ctx, target)
	endTime := time.Now()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during scan: %v\n", err)
		os.Exit(1)
	}

	// Build scan result
	result := buildScanResult(target, findings, stats, startTime, endTime)

	// Print summary
	printSummary(result)

	// Generate reports
	if err := generateReports(result, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating reports: %v\n", err)
		os.Exit(1)
	}

	// Exit with appropriate code
	if result.Summary.BySeverity[models.SeverityCritical] > 0 {
		os.Exit(2) // Critical issues found
	} else if result.Summary.BySeverity[models.SeverityHigh] > 0 {
		os.Exit(1) // High severity issues found
	}

	os.Exit(0)
}

func buildScanResult(target models.ScanTarget, findings []models.Finding, stats map[string]int, start, end time.Time) *models.ScanResult {
	// Build summary
	summary := models.Summary{
		TotalFindings: len(findings),
		BySeverity:    make(map[models.Severity]int),
		ByCategory:    make(map[string]int),
	}

	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
		summary.ByCategory[finding.Category]++
	}

	return &models.ScanResult{
		Target:       target,
		StartTime:    start,
		EndTime:      end,
		Duration:     end.Sub(start).String(),
		Findings:     findings,
		Summary:      summary,
		ScannerStats: stats,
		Metadata: map[string]string{
			"version": config.Version,
			"author":  config.Author,
		},
	}
}

func printSummary(result *models.ScanResult) {
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println("                         SCAN RESULTS")
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   Total Findings: %d\n", result.Summary.TotalFindings)
	fmt.Printf("   Duration: %s\n\n", result.Duration)

	// Print severity table
	fmt.Println("🔴 By Severity:")
	printSeverityTable(result.Summary.BySeverity)

	// Print category table
	fmt.Println("\n📁 By Category:")
	printCategoryTable(result.Summary.ByCategory)

	fmt.Println("\n═══════════════════════════════════════════════════════════════════")

	// Print detailed findings
	if len(result.Findings) > 0 {
		fmt.Println("\n🔍 Detailed Findings:")
		printFindingsTable(result.Findings)
	}
}

// printSeverityTable prints the severity summary in a bordered table format
func printSeverityTable(bySeverity map[models.Severity]int) {
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("Severity", "Count")

	// Severity rows in order
	severities := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo,
	}

	for _, severity := range severities {
		count := bySeverity[severity]
		table.Append(string(severity), fmt.Sprintf("%d", count))
	}

	table.Render()
}

// printCategoryTable prints the category summary in a bordered table format
func printCategoryTable(byCategory map[string]int) {
	if len(byCategory) == 0 {
		fmt.Println("   No categories found")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.Header("Category", "Count")

	// Category rows
	for category, count := range byCategory {
		table.Append(category, fmt.Sprintf("%d", count))
	}

	table.Render()
}

// printFindingsTable prints detailed findings in a clean table format
func printFindingsTable(findings []models.Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Println()

	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithColumnMax(70),
		tablewriter.WithRendition(tw.Rendition{
			Settings: tw.Settings{
				Separators: tw.Separators{
					BetweenRows: tw.On,
				},
			},
		}),
	)
	table.Header("#", "Severity", "ID", "Details")

	// Findings rows
	for i, finding := range findings {
		severitySymbol := getSeveritySymbol(finding.Severity)
		sevStr := fmt.Sprintf("%s %s", severitySymbol, finding.Severity)

		// Build details column with title, description, and remediation
		var details strings.Builder
		details.WriteString(finding.Title)

		if finding.Description != "" {
			details.WriteString("\nDescription: ")
			details.WriteString(finding.Description)
		}

		if finding.Remediation != "" {
			details.WriteString("\n💡 Remediation: ")
			details.WriteString(finding.Remediation)
		}

		table.Append(
			fmt.Sprintf("%d", i+1),
			sevStr,
			finding.ID,
			details.String(),
		)
	}

	table.Render()
}

func getSeveritySymbol(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🔵"
	default:
		return "ℹ️"
	}
}

func generateReports(result *models.ScanResult, cfg *config.Config) error {
	// Generate JSON report
	jsonReporter := report.NewJSONReporter(true)
	if err := jsonReporter.WriteToFile(result, "dockerscan-report.json"); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}
	fmt.Printf("\n📄 JSON report saved to: dockerscan-report.json\n")

	// Generate SARIF report
	sarifReporter := report.NewSARIFReporter()
	if err := sarifReporter.WriteToFile(result, "dockerscan-report.sarif"); err != nil {
		return fmt.Errorf("failed to write SARIF report: %w", err)
	}
	fmt.Printf("📄 SARIF report saved to: dockerscan-report.sarif\n")

	return nil
}

func handleUpdateDB() error {
	fmt.Println("\n🔄 Downloading CVE database...")

	dbPath := expandPath(defaultDBPath)

	downloader := cvedb.NewDownloader(
		config.DefaultCVEDBURL,
		config.DefaultCVEChecksumURL,
		dbPath,
	)

	// Check if update needed
	needsUpdate, _, err := downloader.NeedsUpdate()
	if err != nil {
		// If error checking, try to download anyway
		needsUpdate = true
	}

	if !needsUpdate {
		fmt.Println("✅ Database is already up to date.")
		printDBInfo(dbPath)
		return nil
	}

	// Download
	ctx := context.Background()
	if err := downloader.Download(ctx); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	fmt.Println("\n✅ Database updated successfully!")
	printDBInfo(dbPath)
	return nil
}

func printDBInfo(dbPath string) {
	db, err := cvedb.Open(dbPath)
	if err != nil {
		return
	}
	defer db.Close()

	meta, err := db.GetMetadata()
	if err != nil {
		return
	}

	fmt.Printf("   Version:    %s\n", meta.Version)
	fmt.Printf("   Generated:  %s\n", meta.LastModified.Format("2006-01-02 15:04"))
	fmt.Printf("   Total CVEs: %d\n", meta.CVECount)
	fmt.Printf("   Location:   %s\n\n", dbPath)
}

func warnIfOutdated(db *cvedb.CVEDB) {
	meta, err := db.GetMetadata()
	if err != nil {
		return
	}

	age := time.Since(meta.LastModified)
	if age > 7*24*time.Hour {
		fmt.Printf("⚠️  Warning: CVE database is %d days old. Run 'dockerscan update-db' to update.\n\n",
			int(age.Hours()/24))
	}
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

func printUsage() {
	fmt.Println(`
Usage: dockerscan [command] [options] <image>

Commands:
  scan        Scan a Docker image (default)
  update-db   Download or update the CVE database
  version     Show version information
  help        Show this help message

Before first scan, run: dockerscan update-db

Examples:
  dockerscan update-db
  dockerscan nginx:latest
  dockerscan --scanners cis,secrets alpine:3.18
`)
}
