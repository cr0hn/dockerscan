package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/config"
	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/report"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/cis"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/runtime"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/secrets"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/supplychain"
	"github.com/cr0hn/dockerscan/v2/internal/scanner/vulnerabilities"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

func main() {
	// Print banner
	fmt.Print(config.Banner())

	// Parse CLI arguments
	ctx := context.Background()
	cfg := config.NewDefaultConfig()

	// Get image name from args
	// Support both: dockerscan <image> and dockerscan scan <image>
	if len(os.Args) < 2 {
		fmt.Println("\nUsage: dockerscan [scan] <image-name>")
		fmt.Println("\nExample:")
		fmt.Println("  dockerscan nginx:latest")
		fmt.Println("  dockerscan scan nginx:latest")
		fmt.Println("  dockerscan --format sarif --output report.sarif ubuntu:22.04")
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
	registry.Register(vulnerabilities.NewVulnerabilityScanner(dockerClient))
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
	// Table header
	fmt.Println("   ┌────────────┬───────┐")
	fmt.Println("   │ Severity   │ Count │")
	fmt.Println("   ├────────────┼───────┤")

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
		fmt.Printf("   │ %-10s │ %5d │\n", severity, count)
	}

	// Table footer
	fmt.Println("   └────────────┴───────┘")
}

// printCategoryTable prints the category summary in a bordered table format
func printCategoryTable(byCategory map[string]int) {
	if len(byCategory) == 0 {
		fmt.Println("   No categories found")
		return
	}

	// Calculate max category name length for column width
	maxLen := 15
	for category := range byCategory {
		if len(category) > maxLen {
			maxLen = len(category)
		}
	}

	// Build format strings for dynamic width
	headerFormat := fmt.Sprintf("   │ %%-%ds │ Count │\n", maxLen)
	rowFormat := fmt.Sprintf("   │ %%-%ds │ %%5d │\n", maxLen)

	// Table header
	printTableBorder(maxLen, "top")
	fmt.Printf(headerFormat, "Category")
	printTableBorder(maxLen, "middle")

	// Category rows (sorted for consistent output)
	for category, count := range byCategory {
		fmt.Printf(rowFormat, category, count)
	}

	// Table footer
	printTableBorder(maxLen, "bottom")
}

// printFindingsTable prints detailed findings in a clean table format
func printFindingsTable(findings []models.Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Println()

	// Calculate max title length for column width
	maxTitleLen := 50
	for _, finding := range findings {
		if len(finding.Title) > maxTitleLen {
			maxTitleLen = len(finding.Title)
		}
	}

	// Cap the title length to keep table reasonable
	if maxTitleLen > 80 {
		maxTitleLen = 80
	}

	// Build format strings
	headerFormat := fmt.Sprintf("   │ %%3s │ %%10s │ %%-%ds │ %%-%ds │\n", 15, maxTitleLen)
	rowFormat := fmt.Sprintf("   │ %%3d │ %%10s │ %%-%ds │ %%-%ds │\n", 15, maxTitleLen)

	// Table header
	printFindingsTableBorder(maxTitleLen, "top")
	fmt.Printf(headerFormat, "#", "Severity", "ID", "Title")
	printFindingsTableBorder(maxTitleLen, "middle")

	// Findings rows
	for i, finding := range findings {
		severitySymbol := getSeveritySymbol(finding.Severity)
		sevStr := fmt.Sprintf("%s %s", severitySymbol, finding.Severity)

		// Truncate title if too long
		title := finding.Title
		if len(title) > maxTitleLen {
			title = title[:maxTitleLen-3] + "..."
		}

		// Truncate ID if too long
		id := finding.ID
		if len(id) > 15 {
			id = id[:12] + "..."
		}

		fmt.Printf(rowFormat, i+1, sevStr, id, title)

		// Print description and remediation below the table row
		if finding.Description != "" {
			fmt.Printf("   │     │            │ Description: %s\n", finding.Description)
		}

		if finding.Remediation != "" {
			fmt.Printf("   │     │            │ 💡 Remediation: %s\n", finding.Remediation)
		}

		// Add separator between findings (except for last one)
		if i < len(findings)-1 {
			printFindingsTableBorder(maxTitleLen, "separator")
		}
	}

	// Table footer
	printFindingsTableBorder(maxTitleLen, "bottom")
}

// printTableBorder prints a table border for category table
func printTableBorder(categoryWidth int, position string) {
	switch position {
	case "top":
		fmt.Printf("   ┌%s┬───────┐\n", repeatChar('─', categoryWidth+2))
	case "middle":
		fmt.Printf("   ├%s┼───────┤\n", repeatChar('─', categoryWidth+2))
	case "bottom":
		fmt.Printf("   └%s┴───────┘\n", repeatChar('─', categoryWidth+2))
	}
}

// printFindingsTableBorder prints a table border for findings table
func printFindingsTableBorder(titleWidth int, position string) {
	switch position {
	case "top":
		fmt.Printf("   ┌─────┬────────────┬%s┬%s┐\n",
			repeatChar('─', 17), repeatChar('─', titleWidth+2))
	case "middle":
		fmt.Printf("   ├─────┼────────────┼%s┼%s┤\n",
			repeatChar('─', 17), repeatChar('─', titleWidth+2))
	case "separator":
		fmt.Printf("   ├─────┼────────────┼%s┼%s┤\n",
			repeatChar('─', 17), repeatChar('─', titleWidth+2))
	case "bottom":
		fmt.Printf("   └─────┴────────────┴%s┴%s┘\n",
			repeatChar('─', 17), repeatChar('─', titleWidth+2))
	}
}

// repeatChar returns a string with the character repeated n times
func repeatChar(char rune, count int) string {
	result := make([]rune, count)
	for i := range result {
		result[i] = char
	}
	return string(result)
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
