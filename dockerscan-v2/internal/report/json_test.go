package report

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func TestNewJSONReporter(t *testing.T) {
	reporter := NewJSONReporter(true)
	if reporter == nil {
		t.Fatal("Expected reporter to be created")
	}
	if !reporter.Pretty {
		t.Error("Expected pretty formatting to be enabled")
	}
}

func TestJSONReporterGenerate(t *testing.T) {
	reporter := NewJSONReporter(false)

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
				Severity:    models.SeverityHigh,
				Category:    "Test",
				Source:      "test",
			},
		},
		Summary: models.Summary{
			TotalFindings: 1,
			BySeverity: map[models.Severity]int{
				models.SeverityHigh: 1,
			},
			ByCategory: map[string]int{
				"Test": 1,
			},
		},
	}

	data, err := reporter.Generate(result)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify it's valid JSON
	var decoded models.ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Generated data is not valid JSON: %v", err)
	}

	if decoded.Target.ImageName != "test:latest" {
		t.Errorf("Expected image name 'test:latest', got %s", decoded.Target.ImageName)
	}
	if len(decoded.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(decoded.Findings))
	}
}

func TestJSONReporterGeneratePretty(t *testing.T) {
	reporter := NewJSONReporter(true)

	result := &models.ScanResult{
		Target: models.ScanTarget{
			ImageName: "test:latest",
		},
		Findings: []models.Finding{},
		Summary: models.Summary{
			TotalFindings: 0,
			BySeverity:    map[models.Severity]int{},
			ByCategory:    map[string]int{},
		},
	}

	data, err := reporter.Generate(result)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Pretty formatted JSON should contain newlines
	dataStr := string(data)
	if len(dataStr) < 10 {
		t.Error("Expected pretty formatted JSON to have reasonable length")
	}
}

func TestJSONReporterWriteToFile(t *testing.T) {
	reporter := NewJSONReporter(true)

	result := &models.ScanResult{
		Target: models.ScanTarget{
			ImageName: "test:latest",
		},
		Findings: []models.Finding{
			{ID: "F1", Title: "Finding 1", Severity: models.SeverityCritical},
		},
		Summary: models.Summary{
			TotalFindings: 1,
			BySeverity: map[models.Severity]int{
				models.SeverityCritical: 1,
			},
		},
	}

	tmpfile := "/tmp/test-report.json"
	defer os.Remove(tmpfile)

	err := reporter.WriteToFile(result, tmpfile)
	if err != nil {
		t.Fatalf("Expected no error writing file, got %v", err)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}

	var decoded models.ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("File contains invalid JSON: %v", err)
	}

	if decoded.Summary.TotalFindings != 1 {
		t.Errorf("Expected 1 finding in file, got %d", decoded.Summary.TotalFindings)
	}
}
