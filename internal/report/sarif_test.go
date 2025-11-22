package report

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func TestNewSARIFReporter(t *testing.T) {
	reporter := NewSARIFReporter()
	if reporter == nil {
		t.Fatal("Expected reporter to be created")
	}
	if reporter.Version == "" {
		t.Error("Expected version to be set")
	}
}

func TestSARIFReporterGenerate(t *testing.T) {
	reporter := NewSARIFReporter()

	result := &models.ScanResult{
		Target: models.ScanTarget{
			ImageName: "test:latest",
		},
		StartTime: time.Now(),
		EndTime:   time.Now().Add(5 * time.Second),
		Duration:  "5s",
		Findings: []models.Finding{
			{
				ID:          "TEST-001",
				Title:       "Test Finding",
				Description: "Test description",
				Severity:    models.SeverityCritical,
				Category:    "Security",
				Source:      "test-scanner",
				Remediation: "Fix the issue",
				Location: &models.Location{
					File: "Dockerfile",
					Line: 10,
				},
			},
		},
		Summary: models.Summary{
			TotalFindings: 1,
		},
	}

	data, err := reporter.Generate(result)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify it's valid SARIF JSON
	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("Generated data is not valid SARIF JSON: %v", err)
	}

	// Verify SARIF structure
	if sarif.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Errorf("Expected 1 run, got %d", len(sarif.Runs))
	}
	if sarif.Runs[0].Tool.Driver.Name != "DockerScan" {
		t.Errorf("Expected tool name 'DockerScan', got %s", sarif.Runs[0].Tool.Driver.Name)
	}
	if len(sarif.Runs[0].Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(sarif.Runs[0].Results))
	}
}

func TestSARIFReporterMultipleFindings(t *testing.T) {
	reporter := NewSARIFReporter()

	result := &models.ScanResult{
		Target: models.ScanTarget{ImageName: "test:latest"},
		Findings: []models.Finding{
			{
				ID:          "CRIT-001",
				Title:       "Critical Issue",
				Description: "Critical description",
				Severity:    models.SeverityCritical,
				Category:    "Security",
			},
			{
				ID:          "HIGH-001",
				Title:       "High Issue",
				Description: "High description",
				Severity:    models.SeverityHigh,
				Category:    "Config",
			},
			{
				ID:          "MED-001",
				Title:       "Medium Issue",
				Description: "Medium description",
				Severity:    models.SeverityMedium,
				Category:    "Best-Practice",
			},
		},
		Summary: models.Summary{TotalFindings: 3},
	}

	data, err := reporter.Generate(result)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("Invalid SARIF: %v", err)
	}

	if len(sarif.Runs[0].Results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(sarif.Runs[0].Results))
	}
	if len(sarif.Runs[0].Tool.Driver.Rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(sarif.Runs[0].Tool.Driver.Rules))
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	reporter := NewSARIFReporter()

	tests := []struct {
		severity     models.Severity
		expectedLevel string
	}{
		{models.SeverityCritical, "error"},
		{models.SeverityHigh, "error"},
		{models.SeverityMedium, "warning"},
		{models.SeverityLow, "note"},
		{models.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			level := reporter.severityToSARIFLevel(tt.severity)
			if level != tt.expectedLevel {
				t.Errorf("Expected level %s for severity %s, got %s",
					tt.expectedLevel, tt.severity, level)
			}
		})
	}
}

func TestSARIFReporterWriteToFile(t *testing.T) {
	reporter := NewSARIFReporter()

	result := &models.ScanResult{
		Target: models.ScanTarget{ImageName: "test:latest"},
		Findings: []models.Finding{
			{ID: "F1", Title: "Finding 1", Severity: models.SeverityCritical},
		},
		Summary: models.Summary{TotalFindings: 1},
	}

	tmpfile := "/tmp/test-report.sarif"
	defer os.Remove(tmpfile)

	err := reporter.WriteToFile(result, tmpfile)
	if err != nil {
		t.Fatalf("Expected no error writing file, got %v", err)
	}

	// Verify file exists and is valid SARIF
	data, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}

	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("File contains invalid SARIF: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", sarif.Version)
	}
}

func TestSARIFReporterWithLocation(t *testing.T) {
	reporter := NewSARIFReporter()

	result := &models.ScanResult{
		Target: models.ScanTarget{ImageName: "test:latest"},
		Findings: []models.Finding{
			{
				ID:          "LOC-001",
				Title:       "Finding with location",
				Severity:    models.SeverityHigh,
				Location: &models.Location{
					File:  "Dockerfile",
					Layer: "layer123",
					Line:  42,
				},
			},
		},
		Summary: models.Summary{TotalFindings: 1},
	}

	data, err := reporter.Generate(result)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("Invalid SARIF: %v", err)
	}

	result0 := sarif.Runs[0].Results[0]
	if len(result0.Locations) != 1 {
		t.Fatalf("Expected 1 location, got %d", len(result0.Locations))
	}

	location := result0.Locations[0]
	if location.PhysicalLocation.ArtifactLocation.URI != "Dockerfile" {
		t.Errorf("Expected URI 'Dockerfile', got %s",
			location.PhysicalLocation.ArtifactLocation.URI)
	}
	if location.PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("Expected line 42, got %d",
			location.PhysicalLocation.Region.StartLine)
	}
}
