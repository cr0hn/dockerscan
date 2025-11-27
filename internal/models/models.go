package models

import (
	"strings"
	"time"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ScanTarget represents what to scan
type ScanTarget struct {
	ImageName      string
	ImageID        string
	ContainerID    string
	RegistryURL    string
	LocalImagePath string
}

// Finding represents a security issue discovered
type Finding struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    Severity               `json:"severity"`
	Category    string                 `json:"category"`
	Source      string                 `json:"source"`
	Remediation string                 `json:"remediation,omitempty"`
	References  []string               `json:"references,omitempty"`
	Location    *Location              `json:"location,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Location describes where the finding was discovered
type Location struct {
	File      string `json:"file,omitempty"`
	Layer     string `json:"layer,omitempty"`
	Line      int    `json:"line,omitempty"`
	Component string `json:"component,omitempty"`
}

// ScanResult contains all findings from a scan
type ScanResult struct {
	Target       ScanTarget         `json:"target"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      time.Time          `json:"end_time"`
	Duration     string             `json:"duration"`
	Findings     []Finding          `json:"findings"`
	Summary      Summary            `json:"summary"`
	ScannerStats map[string]int     `json:"scanner_stats"`
	Metadata     map[string]string  `json:"metadata,omitempty"`
}

// Summary provides quick statistics
type Summary struct {
	TotalFindings int              `json:"total_findings"`
	BySeverity    map[Severity]int `json:"by_severity"`
	ByCategory    map[string]int   `json:"by_category"`
	// Note: Passed/Failed fields removed - security scanners report problems, not passes
}

// Vulnerability represents a CVE or security vulnerability
type Vulnerability struct {
	ID              string   `json:"id"`
	PackageName     string   `json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion    string   `json:"fixed_version,omitempty"`
	Severity        Severity `json:"severity"`
	Description     string   `json:"description"`
	References      []string `json:"references,omitempty"`
	CVSSScore       float64  `json:"cvss_score,omitempty"`
}

// Secret represents sensitive data found
type Secret struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Location string `json:"location"`
	Entropy  float64 `json:"entropy,omitempty"`
}

// ImageInfo contains metadata about the Docker image
type ImageInfo struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Tag           string            `json:"tag"`
	Size          int64             `json:"size"`
	Created       time.Time         `json:"created"`
	Author        string            `json:"author,omitempty"`
	Architecture  string            `json:"architecture"`
	OS            string            `json:"os"`
	Layers        []string          `json:"layers"`
	ExposedPorts  []string          `json:"exposed_ports"`
	Environment   map[string]string `json:"environment"`
	User          string            `json:"user,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	Entrypoint    []string          `json:"entrypoint,omitempty"`
	Cmd           []string          `json:"cmd,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// DockerfileInstruction represents a parsed Dockerfile instruction
type DockerfileInstruction struct {
	Command string
	Args    []string
	Raw     string
}

// ExtractBaseImage extracts the base image from a Dockerfile FROM instruction.
// It handles various FROM statement formats:
// - FROM ubuntu:20.04
// - FROM --platform=linux/amd64 ubuntu:20.04
// - FROM ubuntu:20.04 AS builder
// - FROM --platform=$TARGETPLATFORM golang:1.21 AS build
//
// Returns the image:tag portion, or empty string if not found.
func ExtractBaseImage(instruction string) string {
	if instruction == "" {
		return ""
	}

	// Split into fields
	fields := strings.Fields(instruction)
	if len(fields) < 2 {
		return ""
	}

	// Find FROM keyword (case-insensitive)
	fromIndex := -1
	for i, field := range fields {
		if strings.EqualFold(field, "FROM") {
			fromIndex = i
			break
		}
	}

	if fromIndex == -1 || fromIndex+1 >= len(fields) {
		return ""
	}

	// Skip any flags after FROM (flags start with --)
	imageIndex := fromIndex + 1
	for imageIndex < len(fields) && strings.HasPrefix(fields[imageIndex], "--") {
		imageIndex++
	}

	// Check we have an image name
	if imageIndex >= len(fields) {
		return ""
	}

	image := fields[imageIndex]

	// Remove 'AS alias' suffix if present
	// The image should not start with these keywords
	if strings.EqualFold(image, "AS") {
		return ""
	}

	return strings.TrimSpace(image)
}

// ExtractLastBaseImage finds the last FROM instruction in a list of history entries.
// In multi-stage builds, the last FROM represents the final runtime image.
// History is typically in reverse order (newest first), so we search from the end.
func ExtractLastBaseImage(historyEntries []string) string {
	var lastImage string

	// Process history from oldest to newest to find the last FROM
	for i := len(historyEntries) - 1; i >= 0; i-- {
		entry := historyEntries[i]
		if strings.Contains(strings.ToUpper(entry), "FROM") {
			if img := ExtractBaseImage(entry); img != "" {
				lastImage = img
			}
		}
	}

	return lastImage
}
