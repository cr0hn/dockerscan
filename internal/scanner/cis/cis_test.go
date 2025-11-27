package cis

import (
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

func TestNewCISScanner(t *testing.T) {
	// Test with nil client (should work for basic initialization)
	scanner := NewCISScanner(nil)
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

func TestCISScanner_CheckImageUser(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test with root user (empty string defaults to root)
	info := &docker.ImageInfo{
		User: "",
	}

	findings := scanner.checkImageUser(info)
	if len(findings) == 0 {
		t.Error("Expected checkImageUser to return findings for root user")
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

	// Test with explicit root user
	info.User = "root"
	findings = scanner.checkImageUser(info)
	found = false
	for _, finding := range findings {
		if finding.ID == "CIS-4.1" {
			found = true
		}
	}
	if !found {
		t.Error("Expected CIS-4.1 finding for root user")
	}

	// Test with UID 0
	info.User = "0"
	findings = scanner.checkImageUser(info)
	found = false
	for _, finding := range findings {
		if finding.ID == "CIS-4.1" {
			found = true
		}
	}
	if !found {
		t.Error("Expected CIS-4.1 finding for UID 0")
	}

	// Test with non-root user
	info.User = "appuser"
	findings = scanner.checkImageUser(info)
	for _, finding := range findings {
		if finding.ID == "CIS-4.1" {
			t.Error("Should not report CIS-4.1 when non-root user is set")
		}
	}
}

func TestCISScanner_CheckHealthcheck(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test without healthcheck
	info := &docker.ImageInfo{
		Healthcheck: nil,
	}

	findings := scanner.checkHealthcheck(info)
	if len(findings) == 0 {
		t.Error("Expected checkHealthcheck to return findings when no healthcheck")
	}

	// Should have CIS-4.6 finding
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-4.6" {
			found = true
			if finding.Severity != models.SeverityLow {
				t.Errorf("Expected LOW severity for HEALTHCHECK, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected to find CIS-4.6 check")
	}

	// Test with healthcheck
	info.Healthcheck = &docker.HealthcheckConfig{
		Test: []string{"CMD", "curl", "-f", "http://localhost/"},
	}
	findings = scanner.checkHealthcheck(info)
	for _, finding := range findings {
		if finding.ID == "CIS-4.6" {
			t.Error("Should not report CIS-4.6 when healthcheck is defined")
		}
	}
}

func TestCISScanner_CheckImageTag(t *testing.T) {
	scanner := NewCISScanner(nil)
	info := &docker.ImageInfo{}

	// Test with latest tag
	findings := scanner.checkImageTag("nginx:latest", info)
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-4.7" {
			found = true
			if finding.Severity != models.SeverityMedium {
				t.Errorf("Expected MEDIUM severity for latest tag, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected CIS-4.7 finding for :latest tag")
	}

	// Test without tag (implies latest)
	findings = scanner.checkImageTag("nginx", info)
	found = false
	for _, finding := range findings {
		if finding.ID == "CIS-4.7" {
			found = true
		}
	}
	if !found {
		t.Error("Expected CIS-4.7 finding for image without tag")
	}

	// Test with specific version
	findings = scanner.checkImageTag("nginx:1.25.3", info)
	for _, finding := range findings {
		if finding.ID == "CIS-4.7" {
			t.Error("Should not report CIS-4.7 for specific version tag")
		}
	}

	// Test with digest
	findings = scanner.checkImageTag("nginx@sha256:abc123", info)
	for _, finding := range findings {
		if finding.ID == "CIS-4.7" {
			t.Error("Should not report CIS-4.7 for image with digest")
		}
	}
}

func TestCISScanner_CheckExposedPorts(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test with privileged ports (with /tcp protocol)
	info := &docker.ImageInfo{
		ExposedPorts: []string{"80/tcp", "443/tcp"},
	}

	findings := scanner.checkExposedPorts(info)
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-5.7" {
			found = true
			if finding.Severity != models.SeverityMedium {
				t.Errorf("Expected MEDIUM severity for privileged ports, got %s", finding.Severity)
			}
			// Verify both ports are detected
			metadata := finding.Metadata
			if privPorts, ok := metadata["privileged_ports"].([]string); ok {
				if len(privPorts) != 2 {
					t.Errorf("Expected 2 privileged ports, got %d", len(privPorts))
				}
			}
		}
	}
	if !found {
		t.Error("Expected CIS-5.7 finding for privileged ports")
	}

	// Test with privileged port using /udp protocol
	info.ExposedPorts = []string{"53/udp", "8080/tcp"}
	findings = scanner.checkExposedPorts(info)
	found = false
	for _, finding := range findings {
		if finding.ID == "CIS-5.7" {
			found = true
			metadata := finding.Metadata
			if privPorts, ok := metadata["privileged_ports"].([]string); ok {
				if len(privPorts) != 1 {
					t.Errorf("Expected 1 privileged port (53/udp), got %d", len(privPorts))
				}
			}
		}
	}
	if !found {
		t.Error("Expected CIS-5.7 finding for privileged UDP port")
	}

	// Test with port without protocol specified
	info.ExposedPorts = []string{"22", "1024"}
	findings = scanner.checkExposedPorts(info)
	found = false
	for _, finding := range findings {
		if finding.ID == "CIS-5.7" {
			found = true
			metadata := finding.Metadata
			if privPorts, ok := metadata["privileged_ports"].([]string); ok {
				if len(privPorts) != 1 {
					t.Errorf("Expected 1 privileged port (22), got %d: %v", len(privPorts), privPorts)
				}
			}
		}
	}
	if !found {
		t.Error("Expected CIS-5.7 finding for privileged port without protocol")
	}

	// Test with non-privileged port
	info.ExposedPorts = []string{"8080/tcp"}
	findings = scanner.checkExposedPorts(info)
	for _, finding := range findings {
		if finding.ID == "CIS-5.7" {
			t.Error("Should not report CIS-5.7 for non-privileged ports")
		}
	}

	// Test with many ports (should trigger info warning)
	info.ExposedPorts = []string{"8080/tcp", "8081/tcp", "8082/tcp", "8083/tcp", "8084/tcp", "8085/tcp"}
	findings = scanner.checkExposedPorts(info)
	foundInfo := false
	for _, finding := range findings {
		if finding.ID == "CIS-5.7-INFO" {
			foundInfo = true
		}
	}
	if !foundInfo {
		t.Error("Expected CIS-5.7-INFO finding for many exposed ports")
	}

	// Test with invalid port formats (should be skipped gracefully)
	info.ExposedPorts = []string{"invalid/tcp", "not-a-port", "12345/tcp"}
	findings = scanner.checkExposedPorts(info)
	// Should not crash and should only detect valid non-privileged port
	for _, finding := range findings {
		if finding.ID == "CIS-5.7" {
			t.Error("Should not report CIS-5.7 for invalid or non-privileged ports")
		}
	}

	// Test edge cases: port 1023 (privileged) vs 1024 (non-privileged)
	info.ExposedPorts = []string{"1023/tcp", "1024/tcp"}
	findings = scanner.checkExposedPorts(info)
	found = false
	for _, finding := range findings {
		if finding.ID == "CIS-5.7" {
			found = true
			metadata := finding.Metadata
			if privPorts, ok := metadata["privileged_ports"].([]string); ok {
				if len(privPorts) != 1 || privPorts[0] != "1023/tcp" {
					t.Errorf("Expected only port 1023/tcp to be privileged, got %v", privPorts)
				}
			}
		}
	}
	if !found {
		t.Error("Expected CIS-5.7 finding for port 1023 (privileged boundary)")
	}
}

func TestCISScanner_CheckADDInstruction(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test with ADD instruction (user-level ADD, not internal docker ADD file:)
	history := []docker.HistoryEntry{
		{CreatedBy: "/bin/sh -c #(nop) ADD https://example.com/file.tar.gz /app/"},
		{CreatedBy: "/bin/sh -c npm install"},
	}

	findings := scanner.checkADDInstruction(history)
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-4.9" {
			found = true
			if finding.Severity != models.SeverityLow {
				t.Errorf("Expected LOW severity for ADD instruction, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected CIS-4.9 finding for ADD instruction")
	}

	// Test without ADD instruction
	history = []docker.HistoryEntry{
		{CreatedBy: "/bin/sh -c COPY . /app"},
		{CreatedBy: "/bin/sh -c npm install"},
	}
	findings = scanner.checkADDInstruction(history)
	for _, finding := range findings {
		if finding.ID == "CIS-4.9" {
			t.Error("Should not report CIS-4.9 when only COPY is used")
		}
	}

	// Test with nil history
	findings = scanner.checkADDInstruction(nil)
	if len(findings) != 0 {
		t.Error("Should return empty findings for nil history")
	}
}

func TestCISScanner_CheckUpdateInstructions(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test with apt-get update alone
	history := []docker.HistoryEntry{
		{CreatedBy: "/bin/sh -c apt-get update"},
		{CreatedBy: "/bin/sh -c apt-get install -y curl"},
	}

	findings := scanner.checkUpdateInstructions(history)
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-4.7-UPDATE" {
			found = true
		}
	}
	if !found {
		t.Error("Expected CIS-4.7-UPDATE finding for apt-get update without install")
	}

	// Test with combined update and install
	history = []docker.HistoryEntry{
		{CreatedBy: "/bin/sh -c apt-get update && apt-get install -y curl"},
	}
	findings = scanner.checkUpdateInstructions(history)
	for _, finding := range findings {
		if finding.ID == "CIS-4.7-UPDATE" {
			t.Error("Should not report CIS-4.7-UPDATE when update and install are combined")
		}
	}
}

func TestCISScanner_CheckSecretsInHistory(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test with secret in history
	history := []docker.HistoryEntry{
		{CreatedBy: "/bin/sh -c export PASSWORD=mypassword123"},
		{CreatedBy: "/bin/sh -c npm install"},
	}

	findings := scanner.checkSecretsInHistory(history)
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-4.10-HISTORY" {
			found = true
			if finding.Severity != models.SeverityHigh {
				t.Errorf("Expected HIGH severity for secrets in history, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected CIS-4.10-HISTORY finding for secret in history")
	}

	// Test without secrets
	history = []docker.HistoryEntry{
		{CreatedBy: "/bin/sh -c apt-get update"},
		{CreatedBy: "/bin/sh -c npm install"},
	}
	findings = scanner.checkSecretsInHistory(history)
	for _, finding := range findings {
		if finding.ID == "CIS-4.10-HISTORY" {
			t.Error("Should not report CIS-4.10-HISTORY when no secrets present")
		}
	}
}

func TestCISScanner_CheckEnvironmentVariables(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test with sensitive env vars
	info := &docker.ImageInfo{
		Env: map[string]string{
			"PATH":         "/usr/bin",
			"API_KEY":      "secret123",
			"PASSWORD":     "mypassword",
			"NORMAL_VAR":   "normalvalue",
		},
	}

	findings := scanner.checkEnvironmentVariables(info)
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-ENV-SECRETS" {
			found = true
			if finding.Severity != models.SeverityLow {
				t.Errorf("Expected LOW severity for env secrets, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected CIS-ENV-SECRETS finding for sensitive env vars")
	}

	// Test without sensitive env vars
	info.Env = map[string]string{
		"PATH":   "/usr/bin",
		"EDITOR": "vim",
	}
	findings = scanner.checkEnvironmentVariables(info)
	for _, finding := range findings {
		if finding.ID == "CIS-ENV-SECRETS" {
			t.Error("Should not report CIS-ENV-SECRETS when no sensitive vars present")
		}
	}
}

func TestCISScanner_CheckVolumes(t *testing.T) {
	scanner := NewCISScanner(nil)

	// Test with sensitive volumes
	info := &docker.ImageInfo{
		Volumes: []string{"/etc/config", "/var/run/docker.sock"},
	}

	findings := scanner.checkVolumes(info)
	found := false
	for _, finding := range findings {
		if finding.ID == "CIS-VOLUMES-SENSITIVE" {
			found = true
			if finding.Severity != models.SeverityMedium {
				t.Errorf("Expected MEDIUM severity for sensitive volumes, got %s", finding.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected CIS-VOLUMES-SENSITIVE finding for sensitive volume paths")
	}

	// Test with non-sensitive volumes
	info.Volumes = []string{"/data", "/app/logs"}
	findings = scanner.checkVolumes(info)
	for _, finding := range findings {
		if finding.ID == "CIS-VOLUMES-SENSITIVE" {
			t.Error("Should not report CIS-VOLUMES-SENSITIVE for non-sensitive paths")
		}
	}

	// Test with no volumes
	info.Volumes = []string{}
	findings = scanner.checkVolumes(info)
	if len(findings) != 0 {
		t.Error("Should return empty findings for no volumes")
	}
}

func TestExtractBaseImage(t *testing.T) {
	tests := []struct {
		name      string
		createdBy string
		expected  string
	}{
		{"FROM instruction", "FROM nginx:1.25", "nginx:1.25"},
		{"FROM with AS", "FROM golang:1.21 AS builder", "golang:1.21"},
		{"No FROM", "/bin/sh -c npm install", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBaseImage(tt.createdBy)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
