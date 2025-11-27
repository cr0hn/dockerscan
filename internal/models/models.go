package models

import "time"

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
