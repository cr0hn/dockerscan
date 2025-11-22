package cis

import (
	"context"
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func TestNewCISScanner(t *testing.T) {
	scanner := NewCISScanner()
	if scanner == nil {
		t.Fatal("Expected scanner to be created")
	}
	if scanner.Name() != "cis-benchmark" {
		t.Errorf("Expected name 'cis-benchmark', got %s", scanner.Name())
	}
	if !scanner.Enabled() {
		t.Error("Expected scanner to be enabled")
	}
}

func TestCISScanner_Scan(t *testing.T) {
	scanner := NewCISScanner()
	target := models.ScanTarget{
		ImageName: "nginx:latest",
	}

	findings, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected CIS scanner to return findings")
	}

	// Verify findings have required fields
	for _, finding := range findings {
		if finding.ID == "" {
			t.Error("Finding should have an ID")
		}
		if finding.Title == "" {
			t.Error("Finding should have a title")
		}
		if finding.Category != "CIS-Benchmark" {
			t.Errorf("Expected category 'CIS-Benchmark', got %s", finding.Category)
		}
		if finding.Source != "cis-benchmark" {
			t.Errorf("Expected source 'cis-benchmark', got %s", finding.Source)
		}
	}
}

func TestCISScanner_CheckImageUser(t *testing.T) {
	scanner := NewCISScanner()
	target := models.ScanTarget{
		ImageName: "test:latest",
	}

	findings := scanner.checkImageUser(target)
	if len(findings) == 0 {
		t.Error("Expected checkImageUser to return findings")
	}

	// Should have CIS-4.1 finding
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-4.1" {
			found = true
			if finding.Severity != models.SeverityHigh {
				t.Errorf("Expected HIGH severity for CIS-4.1, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected to find CIS-4.1 check")
	}
}

func TestCISScanner_CheckHealthcheck(t *testing.T) {
	scanner := NewCISScanner()
	target := models.ScanTarget{ImageName: "test:latest"}

	findings := scanner.checkHealthcheck(target)
	if len(findings) == 0 {
		t.Error("Expected checkHealthcheck to return findings")
	}

	// Should have CIS-4.6 finding
	for _, finding := range findings {
		if finding.ID == "CIS-4.6" {
			if finding.Severity != models.SeverityLow {
				t.Errorf("Expected LOW severity for HEALTHCHECK, got %s", finding.Severity)
			}
		}
	}
}

func TestCISScanner_CheckPrivilegedContainers(t *testing.T) {
	scanner := NewCISScanner()
	target := models.ScanTarget{}

	findings := scanner.checkPrivilegedContainers(target)
	if len(findings) == 0 {
		t.Error("Expected checkPrivilegedContainers to return findings")
	}

	// Should be critical severity
	for _, finding := range findings {
		if finding.ID == "CIS-5.3" {
			if finding.Severity != models.SeverityCritical {
				t.Errorf("Expected CRITICAL severity for privileged containers, got %s",
					finding.Severity)
			}
		}
	}
}

func TestCISScanner_CheckCapabilities(t *testing.T) {
	scanner := NewCISScanner()
	target := models.ScanTarget{}

	findings := scanner.checkCapabilities(target)
	if len(findings) == 0 {
		t.Error("Expected checkCapabilities to return findings")
	}

	// Should check for dangerous capabilities
	dangerousCaps := map[string]bool{
		"CAP_SYS_ADMIN":      false,
		"CAP_NET_ADMIN":      false,
		"CAP_SYS_MODULE":     false,
		"CAP_DAC_READ_SEARCH": false,
		"CAP_SYS_PTRACE":     false,
	}

	for _, finding := range findings {
		if metadata, ok := finding.Metadata["capability"]; ok {
			if cap, ok := metadata.(string); ok {
				dangerousCaps[cap] = true
			}
		}
	}

	// Verify we checked for at least some dangerous capabilities
	foundCount := 0
	for _, found := range dangerousCaps {
		if found {
			foundCount++
		}
	}
	if foundCount == 0 {
		t.Error("Expected to check for dangerous capabilities")
	}
}

func TestCISScanner_CheckHostNetwork(t *testing.T) {
	scanner := NewCISScanner()
	target := models.ScanTarget{}

	findings := scanner.checkHostNetwork(target)
	if len(findings) == 0 {
		t.Error("Expected checkHostNetwork to return findings")
	}

	for _, finding := range findings {
		if finding.ID == "CIS-5.9" {
			if finding.Severity != models.SeverityHigh {
				t.Errorf("Expected HIGH severity for host network, got %s", finding.Severity)
			}
		}
	}
}

func TestCISScanner_CheckReadOnlyRootFS(t *testing.T) {
	scanner := NewCISScanner()
	target := models.ScanTarget{}

	findings := scanner.checkReadOnlyRootFS(target)
	if len(findings) == 0 {
		t.Error("Expected checkReadOnlyRootFS to return findings")
	}

	for _, finding := range findings {
		if finding.ID == "CIS-5.12" {
			if finding.Severity != models.SeverityMedium {
				t.Errorf("Expected MEDIUM severity for read-only root FS, got %s",
					finding.Severity)
			}
		}
	}
}
