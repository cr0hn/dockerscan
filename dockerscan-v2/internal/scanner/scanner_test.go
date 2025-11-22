package scanner

import (
	"context"
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

// MockScanner for testing
type MockScanner struct {
	BaseScanner
	findings []models.Finding
	err      error
}

func (m *MockScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()
	if registry == nil {
		t.Fatal("Expected registry to be created")
	}
	if len(registry.scanners) != 0 {
		t.Errorf("Expected empty registry, got %d scanners", len(registry.scanners))
	}
}

func TestRegisterScanner(t *testing.T) {
	registry := NewRegistry()

	scanner := &MockScanner{
		BaseScanner: NewBaseScanner("test", "Test scanner", true),
		findings: []models.Finding{
			{ID: "TEST-001", Title: "Test finding", Severity: models.SeverityHigh},
		},
	}

	registry.Register(scanner)

	if len(registry.scanners) != 1 {
		t.Errorf("Expected 1 scanner, got %d", len(registry.scanners))
	}
}

func TestGetScanner(t *testing.T) {
	registry := NewRegistry()

	scanner := &MockScanner{
		BaseScanner: NewBaseScanner("test-scanner", "Test scanner", true),
	}
	registry.Register(scanner)

	// Test getting existing scanner
	retrieved, err := registry.Get("test-scanner")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if retrieved.Name() != "test-scanner" {
		t.Errorf("Expected scanner name 'test-scanner', got %s", retrieved.Name())
	}

	// Test getting non-existent scanner
	_, err = registry.Get("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent scanner")
	}
}

func TestListScanners(t *testing.T) {
	registry := NewRegistry()

	scanner1 := &MockScanner{
		BaseScanner: NewBaseScanner("scanner1", "Scanner 1", true),
	}
	scanner2 := &MockScanner{
		BaseScanner: NewBaseScanner("scanner2", "Scanner 2", true),
	}

	registry.Register(scanner1)
	registry.Register(scanner2)

	scanners := registry.List()
	if len(scanners) != 2 {
		t.Errorf("Expected 2 scanners, got %d", len(scanners))
	}
}

func TestScanAll(t *testing.T) {
	registry := NewRegistry()

	scanner1 := &MockScanner{
		BaseScanner: NewBaseScanner("scanner1", "Scanner 1", true),
		findings: []models.Finding{
			{ID: "F1", Severity: models.SeverityCritical},
		},
	}
	scanner2 := &MockScanner{
		BaseScanner: NewBaseScanner("scanner2", "Scanner 2", true),
		findings: []models.Finding{
			{ID: "F2", Severity: models.SeverityHigh},
			{ID: "F3", Severity: models.SeverityMedium},
		},
	}

	registry.Register(scanner1)
	registry.Register(scanner2)

	target := models.ScanTarget{ImageName: "test:latest"}
	findings, stats, err := registry.ScanAll(context.Background(), target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(findings))
	}
	if stats["scanner1"] != 1 {
		t.Errorf("Expected scanner1 to have 1 finding, got %d", stats["scanner1"])
	}
	if stats["scanner2"] != 2 {
		t.Errorf("Expected scanner2 to have 2 findings, got %d", stats["scanner2"])
	}
}

func TestScanAllWithDisabledScanner(t *testing.T) {
	registry := NewRegistry()

	enabledScanner := &MockScanner{
		BaseScanner: NewBaseScanner("enabled", "Enabled scanner", true),
		findings: []models.Finding{
			{ID: "F1", Severity: models.SeverityCritical},
		},
	}
	disabledScanner := &MockScanner{
		BaseScanner: NewBaseScanner("disabled", "Disabled scanner", false),
		findings: []models.Finding{
			{ID: "F2", Severity: models.SeverityHigh},
		},
	}

	registry.Register(enabledScanner)
	registry.Register(disabledScanner)

	target := models.ScanTarget{ImageName: "test:latest"}
	findings, stats, err := registry.ScanAll(context.Background(), target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding (only from enabled scanner), got %d", len(findings))
	}
	if stats["enabled"] != 1 {
		t.Errorf("Expected enabled scanner to have 1 finding, got %d", stats["enabled"])
	}
	if _, exists := stats["disabled"]; exists {
		t.Error("Expected disabled scanner to not appear in stats")
	}
}

func TestBaseScanner(t *testing.T) {
	base := NewBaseScanner("test", "Test description", true)

	if base.Name() != "test" {
		t.Errorf("Expected name 'test', got %s", base.Name())
	}
	if base.Description() != "Test description" {
		t.Errorf("Expected description 'Test description', got %s", base.Description())
	}
	if !base.Enabled() {
		t.Error("Expected scanner to be enabled")
	}
}

func TestBaseScannerDisabled(t *testing.T) {
	base := NewBaseScanner("disabled", "Disabled scanner", false)

	if base.Enabled() {
		t.Error("Expected scanner to be disabled")
	}
}
