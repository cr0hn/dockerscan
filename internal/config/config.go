package config

import (
	"fmt"
	"runtime"
)

const (
	// Version is the application version
	Version = "2.0.5"

	// Author is the creator
	Author = "Daniel Garcia (cr0hn)"

	// Website is the author's website
	Website = "https://cr0hn.com"

	// Repository is the project repository
	Repository = "https://github.com/cr0hn/dockerscan"

	// CVE Database URLs
	DefaultCVEDBURL       = "https://raw.githubusercontent.com/cr0hn/dockerscan/master/data/latest.db.gz"
	DefaultCVEChecksumURL = "https://raw.githubusercontent.com/cr0hn/dockerscan/master/data/latest.db.gz.sha256"
)

// Config holds application configuration
type Config struct {
	// Scanners to enable
	EnabledScanners []string

	// Output format (json, sarif)
	OutputFormat string

	// Output file path
	OutputFile string

	// Verbosity level
	Verbose bool

	// Show only critical/high severity
	OnlyCritical bool

	// Parallel scan workers
	Workers int
}

// NewDefaultConfig creates default configuration
func NewDefaultConfig() *Config {
	return &Config{
		EnabledScanners: []string{
			"cis-benchmark",
			"secrets",
			"supply-chain",
			"vulnerabilities",
			"runtime-security",
		},
		OutputFormat: "json",
		Workers:      runtime.NumCPU(),
	}
}

// Banner returns the application banner
func Banner() string {
	return `
╔════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                        ║
║   ██████╗  ██████╗  ██████╗██╗  ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗  ║
║   ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║  ║
║   ██║  ██║██║   ██║██║     █████╔╝ █████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║  ║
║   ██║  ██║██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║  ║
║   ██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║███████║╚██████╗██║  ██║██║ ╚████║  ║
║   ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ║
║                                                                                        ║
║                        Advanced Docker Security Scanner v2.0.0                         ║
║                                                                                        ║
║   Author:     Daniel Garcia (cr0hn)                                                    ║
║   Website:    https://cr0hn.com                                                        ║
║   Repository: https://github.com/cr0hn/dockerscan                                      ║
║                                                                                        ║
║   The most comprehensive Docker security analysis tool                                 ║
║   • CIS Docker Benchmark v1.7.0                                                        ║
║   • Supply Chain Attack Detection                                                      ║
║   • CVE & Vulnerability Scanning                                                       ║
║   • Secrets Detection (AWS, GCP, Azure, API Keys, JWT, etc.)                           ║
║   • Runtime Security Analysis                                                          ║
║   • SARIF & JSON Reporting                                                             ║
║                                                                                        ║
╚════════════════════════════════════════════════════════════════════════════════════════╝
`
}

// ShortBanner returns a compact banner
func ShortBanner() string {
	return fmt.Sprintf("DockerScan v%s by %s | %s\n", Version, Author, Website)
}
