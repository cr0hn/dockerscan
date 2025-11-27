package models

import (
	"testing"
	"time"
)

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		expected string
	}{
		{"Critical", SeverityCritical, "CRITICAL"},
		{"High", SeverityHigh, "HIGH"},
		{"Medium", SeverityMedium, "MEDIUM"},
		{"Low", SeverityLow, "LOW"},
		{"Info", SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.severity) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, string(tt.severity))
			}
		})
	}
}

func TestScanTarget(t *testing.T) {
	target := ScanTarget{
		ImageName:   "nginx:latest",
		ImageID:     "sha256:abc123",
		ContainerID: "container123",
		RegistryURL: "docker.io",
	}

	if target.ImageName != "nginx:latest" {
		t.Errorf("Expected ImageName 'nginx:latest', got %s", target.ImageName)
	}
	if target.ImageID != "sha256:abc123" {
		t.Errorf("Expected ImageID 'sha256:abc123', got %s", target.ImageID)
	}
}

func TestFinding(t *testing.T) {
	finding := Finding{
		ID:          "TEST-001",
		Title:       "Test Finding",
		Description: "This is a test",
		Severity:    SeverityHigh,
		Category:    "Test",
		Source:      "test-scanner",
		Remediation: "Fix it",
		References:  []string{"https://example.com"},
		Location: &Location{
			File:  "Dockerfile",
			Layer: "layer1",
			Line:  10,
		},
		Metadata: map[string]interface{}{
			"key": "value",
		},
	}

	if finding.ID != "TEST-001" {
		t.Errorf("Expected ID 'TEST-001', got %s", finding.ID)
	}
	if finding.Severity != SeverityHigh {
		t.Errorf("Expected severity HIGH, got %s", finding.Severity)
	}
	if finding.Location.File != "Dockerfile" {
		t.Errorf("Expected location file 'Dockerfile', got %s", finding.Location.File)
	}
}

func TestScanResult(t *testing.T) {
	start := time.Now()
	end := start.Add(5 * time.Second)

	result := ScanResult{
		Target: ScanTarget{
			ImageName: "test:latest",
		},
		StartTime: start,
		EndTime:   end,
		Duration:  end.Sub(start).String(),
		Findings: []Finding{
			{ID: "F1", Severity: SeverityCritical, Category: "Security"},
			{ID: "F2", Severity: SeverityHigh, Category: "Security"},
			{ID: "F3", Severity: SeverityMedium, Category: "Config"},
		},
		Summary: Summary{
			TotalFindings: 3,
			BySeverity: map[Severity]int{
				SeverityCritical: 1,
				SeverityHigh:     1,
				SeverityMedium:   1,
			},
			ByCategory: map[string]int{
				"Security": 2,
				"Config":   1,
			},
		},
		ScannerStats: map[string]int{
			"cis": 2,
			"secrets": 1,
		},
	}

	if result.Summary.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", result.Summary.TotalFindings)
	}
	if result.Summary.BySeverity[SeverityCritical] != 1 {
		t.Errorf("Expected 1 critical finding, got %d", result.Summary.BySeverity[SeverityCritical])
	}
	if result.Summary.ByCategory["Security"] != 2 {
		t.Errorf("Expected 2 security findings, got %d", result.Summary.ByCategory["Security"])
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		ID:              "CVE-2024-12345",
		PackageName:     "openssl",
		InstalledVersion: "1.0.1",
		FixedVersion:    "1.1.1",
		Severity:        SeverityCritical,
		Description:     "Critical vulnerability",
		CVSSScore:       9.8,
	}

	if vuln.ID != "CVE-2024-12345" {
		t.Errorf("Expected CVE-2024-12345, got %s", vuln.ID)
	}
	if vuln.CVSSScore != 9.8 {
		t.Errorf("Expected CVSS score 9.8, got %f", vuln.CVSSScore)
	}
}

func TestSecret(t *testing.T) {
	secret := Secret{
		Type:     "AWS_ACCESS_KEY",
		Value:    "AKIA1234567890ABCDEF",
		Location: "/root/.aws/credentials",
		Entropy:  4.8,
	}

	if secret.Type != "AWS_ACCESS_KEY" {
		t.Errorf("Expected type AWS_ACCESS_KEY, got %s", secret.Type)
	}
	if secret.Entropy != 4.8 {
		t.Errorf("Expected entropy 4.8, got %f", secret.Entropy)
	}
}

func TestImageInfo(t *testing.T) {
	created := time.Now()
	info := ImageInfo{
		ID:           "sha256:abc123",
		Name:         "nginx",
		Tag:          "latest",
		Size:         123456789,
		Created:      created,
		Architecture: "amd64",
		OS:           "linux",
		Layers:       []string{"layer1", "layer2"},
		ExposedPorts: []string{"80/tcp", "443/tcp"},
		Environment: map[string]string{
			"PATH": "/usr/local/bin",
		},
		User:       "nginx",
		WorkingDir: "/app",
		Entrypoint: []string{"/docker-entrypoint.sh"},
		Cmd:        []string{"nginx", "-g", "daemon off;"},
		Labels: map[string]string{
			"maintainer": "test@example.com",
		},
	}

	if info.Name != "nginx" {
		t.Errorf("Expected name 'nginx', got %s", info.Name)
	}
	if len(info.ExposedPorts) != 2 {
		t.Errorf("Expected 2 exposed ports, got %d", len(info.ExposedPorts))
	}
	if info.Environment["PATH"] != "/usr/local/bin" {
		t.Errorf("Expected PATH env var, got %s", info.Environment["PATH"])
	}
}

func TestExtractBaseImage(t *testing.T) {
	tests := []struct {
		name        string
		instruction string
		expected    string
	}{
		{
			name:        "Simple FROM",
			instruction: "FROM ubuntu:20.04",
			expected:    "ubuntu:20.04",
		},
		{
			name:        "FROM with platform flag",
			instruction: "FROM --platform=linux/amd64 ubuntu:20.04",
			expected:    "ubuntu:20.04",
		},
		{
			name:        "FROM with AS alias",
			instruction: "FROM ubuntu:20.04 AS builder",
			expected:    "ubuntu:20.04",
		},
		{
			name:        "FROM with platform and AS",
			instruction: "FROM --platform=$TARGETPLATFORM golang:1.21 AS build",
			expected:    "golang:1.21",
		},
		{
			name:        "Lowercase from",
			instruction: "from nginx:alpine",
			expected:    "nginx:alpine",
		},
		{
			name:        "FROM with multiple flags",
			instruction: "FROM --platform=linux/arm64 --network=host alpine:3.18",
			expected:    "alpine:3.18",
		},
		{
			name:        "FROM with shell command prefix",
			instruction: "/bin/sh -c #(nop) FROM ubuntu:20.04",
			expected:    "ubuntu:20.04",
		},
		{
			name:        "FROM with docker buildkit prefix",
			instruction: "#(nop) FROM --platform=linux/amd64 node:18-alpine",
			expected:    "node:18-alpine",
		},
		{
			name:        "Empty string",
			instruction: "",
			expected:    "",
		},
		{
			name:        "No FROM keyword",
			instruction: "RUN apt-get update",
			expected:    "",
		},
		{
			name:        "FROM without image",
			instruction: "FROM",
			expected:    "",
		},
		{
			name:        "FROM with only flags",
			instruction: "FROM --platform=linux/amd64",
			expected:    "",
		},
		{
			name:        "Image with registry",
			instruction: "FROM gcr.io/distroless/base:latest",
			expected:    "gcr.io/distroless/base:latest",
		},
		{
			name:        "Image with port in registry",
			instruction: "FROM localhost:5000/myimage:v1.0",
			expected:    "localhost:5000/myimage:v1.0",
		},
		{
			name:        "Image with digest",
			instruction: "FROM alpine@sha256:abc123def456",
			expected:    "alpine@sha256:abc123def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractBaseImage(tt.instruction)
			if result != tt.expected {
				t.Errorf("ExtractBaseImage(%q) = %q, expected %q", tt.instruction, result, tt.expected)
			}
		})
	}
}

func TestExtractLastBaseImage(t *testing.T) {
	tests := []struct {
		name     string
		history  []string
		expected string
	}{
		{
			name: "Single stage build",
			history: []string{
				"RUN apt-get update",
				"COPY . /app",
				"FROM ubuntu:20.04",
			},
			expected: "ubuntu:20.04",
		},
		{
			name: "Multi-stage build - last is runtime",
			history: []string{
				"COPY --from=builder /app/binary /app/binary",
				"FROM alpine:3.18",
				"RUN go build -o /app/binary",
				"FROM golang:1.21 AS builder",
			},
			expected: "alpine:3.18",
		},
		{
			name: "Multi-stage with platform flags",
			history: []string{
				"CMD [\"npm\", \"start\"]",
				"FROM --platform=linux/amd64 node:18-alpine",
				"RUN go build",
				"FROM --platform=linux/amd64 golang:1.21 AS builder",
			},
			expected: "node:18-alpine",
		},
		{
			name: "History with shell prefixes",
			history: []string{
				"/bin/sh -c npm install",
				"/bin/sh -c #(nop) FROM node:18-alpine",
				"/bin/sh -c go build",
				"/bin/sh -c #(nop) FROM golang:1.21 AS builder",
			},
			expected: "node:18-alpine",
		},
		{
			name:     "Empty history",
			history:  []string{},
			expected: "",
		},
		{
			name: "No FROM statements",
			history: []string{
				"RUN apt-get update",
				"COPY . /app",
				"CMD [\"/app/start\"]",
			},
			expected: "",
		},
		{
			name: "Three stage build",
			history: []string{
				"ENTRYPOINT [\"/app/server\"]",
				"FROM alpine:3.18",
				"COPY --from=builder /app/binary /app/binary",
				"FROM ubuntu:20.04 AS builder",
				"COPY --from=deps /app/node_modules /app/node_modules",
				"FROM node:18 AS deps",
			},
			expected: "alpine:3.18",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractLastBaseImage(tt.history)
			if result != tt.expected {
				t.Errorf("ExtractLastBaseImage() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
