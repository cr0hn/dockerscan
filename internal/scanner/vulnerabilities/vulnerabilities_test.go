package vulnerabilities

import (
	"context"
	"testing"

	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

func TestCompareVersion(t *testing.T) {
	scanner := &VulnerabilityScanner{}

	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int // -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
	}{
		// Basic version comparisons
		{"equal versions", "1.0.0", "1.0.0", 0},
		{"less than", "1.0.0", "2.0.0", -1},
		{"greater than", "2.0.0", "1.0.0", 1},
		{"minor version less", "1.0.0", "1.1.0", -1},
		{"minor version greater", "1.1.0", "1.0.0", 1},
		{"patch version less", "1.0.0", "1.0.1", -1},
		{"patch version greater", "1.0.1", "1.0.0", 1},

		// Pre-release version comparisons (the main bug fix)
		{"rc less than final", "1.0.0rc1", "1.0.0", -1},
		{"beta less than final", "1.0.0beta", "1.0.0", -1},
		{"alpha less than final", "1.0.0alpha", "1.0.0", -1},
		{"final greater than rc", "1.0.0", "1.0.0rc1", 1},
		{"final greater than beta", "1.0.0", "1.0.0beta", 1},
		{"final greater than alpha", "1.0.0", "1.0.0alpha", 1},

		// Pre-release ordering
		{"alpha less than beta", "1.0.0alpha", "1.0.0beta", -1},
		{"beta less than rc", "1.0.0beta", "1.0.0rc", -1},
		{"alpha less than rc", "1.0.0alpha", "1.0.0rc", -1},
		{"rc1 less than rc2", "1.0.0rc1", "1.0.0rc2", -1},

		// Debian epoch handling (multi-digit)
		{"single digit epoch", "1:1.2.3", "1.2.3", 0},
		{"double digit epoch", "10:1.2.3", "1.2.3", 0},
		{"triple digit epoch", "100:1.2.3", "1.2.3", 0},
		{"epoch doesn't affect comparison", "100:1.2.3", "1:1.2.3", 0},

		// Debian revision handling
		{"debian revision removed", "1.2.3-4", "1.2.3", 0},
		{"debian revision with epoch", "1:1.2.3-4", "1.2.3", 0},

		// Ubuntu revision handling
		{"ubuntu revision", "1.2.3-4ubuntu1", "1.2.3", 0}, // ubuntu revision removed

		// OpenSSL versions (from vulnerability database)
		{"openssl heartbleed vulnerable", "1.0.1e", "1.0.1g", -1},
		{"openssl heartbleed fixed", "1.0.1g", "1.0.1f", 1},

		// Version with 'v' prefix
		{"v prefix removed", "v1.0.0", "1.0.0", 0},
		{"V prefix removed", "V1.0.0", "1.0.0", 0},

		// Complex version comparisons
		{"missing parts treated as zero", "1.0", "1.0.0", 0},
		{"more parts in v1", "1.0.0.1", "1.0.0", 1},
		{"more parts in v2", "1.0.0", "1.0.0.1", -1},

		// Real-world examples from vulnerability database
		{"bash shellshock vulnerable", "4.2", "4.3", -1},
		{"bash shellshock patched", "4.3", "4.2", 1},
		{"glibc vulnerable", "2.20", "2.23", -1},
		{"curl vulnerable", "8.0.0", "8.4.0", -1},

		// Edge cases
		{"empty vs version", "", "1.0.0", -1},
		{"version vs empty", "1.0.0", "", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.compareVersion(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("compareVersion(%q, %q) = %d, expected %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

func TestCleanVersion(t *testing.T) {
	scanner := &VulnerabilityScanner{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no changes needed", "1.2.3", "1.2.3"},
		{"remove v prefix", "v1.2.3", "1.2.3"},
		{"remove V prefix", "V1.2.3", "1.2.3"},
		{"remove single digit epoch", "1:1.2.3", "1.2.3"},
		{"remove double digit epoch", "10:1.2.3", "1.2.3"},
		{"remove triple digit epoch", "100:1.2.3", "1.2.3"},
		{"remove large epoch", "9999:1.2.3", "1.2.3"},
		{"remove debian revision", "1.2.3-4", "1.2.3"},
		{"remove epoch and revision", "1:1.2.3-4", "1.2.3"},
		{"keep non-numeric suffix", "1.2.3rc1", "1.2.3rc1"},
		{"complex debian version", "10:1.2.3-4ubuntu1", "1.2.3"},
		{"trim whitespace", "  1.2.3  ", "1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.cleanVersion(tt.input)
			if result != tt.expected {
				t.Errorf("cleanVersion(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractNumber(t *testing.T) {
	scanner := &VulnerabilityScanner{}

	tests := []struct {
		name          string
		input         string
		expectedNum   int
		expectedFound bool
	}{
		{"simple number", "123", 123, true},
		{"number with suffix", "123abc", 123, true},
		{"zero", "0", 0, true},
		{"no number", "abc", 0, false},
		{"empty string", "", 0, false},
		{"number at start", "5beta", 5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			num, found := scanner.extractNumber(tt.input)
			if num != tt.expectedNum || found != tt.expectedFound {
				t.Errorf("extractNumber(%q) = (%d, %v), expected (%d, %v)",
					tt.input, num, found, tt.expectedNum, tt.expectedFound)
			}
		})
	}
}

func TestExtractSuffix(t *testing.T) {
	scanner := &VulnerabilityScanner{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no suffix", "123", ""},
		{"alpha suffix", "1alpha", "alpha"},
		{"beta suffix", "2beta", "beta"},
		{"rc suffix", "3rc1", "rc1"},
		{"only suffix", "alpha", "alpha"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.extractSuffix(tt.input)
			if result != tt.expected {
				t.Errorf("extractSuffix(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCompareSuffix(t *testing.T) {
	scanner := &VulnerabilityScanner{}

	tests := []struct {
		name     string
		s1       string
		s2       string
		hasNum1  bool
		hasNum2  bool
		expected int
	}{
		// Pre-release vs final
		{"rc vs final", "rc1", "", true, true, -1},
		{"beta vs final", "beta", "", true, true, -1},
		{"alpha vs final", "alpha", "", true, true, -1},
		{"final vs rc", "", "rc1", true, true, 1},
		{"final vs beta", "", "beta", true, true, 1},

		// Pre-release ordering
		{"alpha vs beta", "alpha", "beta", true, true, -1},
		{"beta vs rc", "beta", "rc", true, true, -1},
		{"alpha vs rc", "alpha", "rc", true, true, -1},

		// Same type pre-release
		{"rc1 vs rc2", "rc1", "rc2", true, true, -1},
		{"beta1 vs beta2", "beta1", "beta2", true, true, -1},

		// Post-release
		{"final vs post", "", "post1", true, true, -1},
		{"post vs final", "post1", "", true, true, 1},

		// Equal
		{"equal empty", "", "", true, true, 0},
		{"equal rc", "rc1", "rc1", true, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.compareSuffix(tt.s1, tt.s2, tt.hasNum1, tt.hasNum2)
			if result != tt.expected {
				t.Errorf("compareSuffix(%q, %q) = %d, expected %d", tt.s1, tt.s2, result, tt.expected)
			}
		})
	}
}

func TestIsVersionVulnerable(t *testing.T) {
	scanner := &VulnerabilityScanner{}

	tests := []struct {
		name             string
		installedVersion string
		affectedVersions string
		fixedVersion     string
		expected         bool
	}{
		// Range-based vulnerabilities
		{
			name:             "within range and below fixed",
			installedVersion: "1.0.1e",
			affectedVersions: "1.0.1-1.0.1f",
			fixedVersion:     "1.0.1g",
			expected:         true,
		},
		{
			name:             "below range",
			installedVersion: "1.0.0",
			affectedVersions: "1.0.1-1.0.1f",
			fixedVersion:     "1.0.1g",
			expected:         false,
		},
		{
			name:             "above range but below fixed",
			installedVersion: "1.0.2",
			affectedVersions: "1.0.1-1.0.1f",
			fixedVersion:     "1.0.1g",
			expected:         false,
		},
		{
			name:             "at or above fixed version",
			installedVersion: "1.0.1g",
			affectedVersions: "1.0.1-1.0.1f",
			fixedVersion:     "1.0.1g",
			expected:         false,
		},
		{
			name:             "above fixed version",
			installedVersion: "1.0.2",
			affectedVersions: "1.0.1-1.0.1f",
			fixedVersion:     "1.0.1g",
			expected:         false,
		},

		// Simple fixed version (no range)
		{
			name:             "below fixed, no range",
			installedVersion: "1.0.0",
			affectedVersions: "",
			fixedVersion:     "1.0.1",
			expected:         true,
		},
		{
			name:             "at fixed, no range",
			installedVersion: "1.0.1",
			affectedVersions: "",
			fixedVersion:     "1.0.1",
			expected:         false,
		},
		{
			name:             "above fixed, no range",
			installedVersion: "1.0.2",
			affectedVersions: "",
			fixedVersion:     "1.0.1",
			expected:         false,
		},

		// Pre-release versions
		{
			name:             "rc version vulnerable",
			installedVersion: "1.0.0rc1",
			affectedVersions: "1.0.0rc1-1.0.0rc2",
			fixedVersion:     "1.0.0",
			expected:         true,
		},
		{
			name:             "final version not vulnerable when rc was",
			installedVersion: "1.0.0",
			affectedVersions: "1.0.0rc1-1.0.0rc2",
			fixedVersion:     "1.0.0",
			expected:         false,
		},

		// Real-world examples from vulnerability database
		{
			name:             "openssl heartbleed vulnerable",
			installedVersion: "1.0.1e",
			affectedVersions: "1.0.1-1.0.1f",
			fixedVersion:     "1.0.1g",
			expected:         true,
		},
		{
			name:             "openssl heartbleed fixed",
			installedVersion: "1.0.1g",
			affectedVersions: "1.0.1-1.0.1f",
			fixedVersion:     "1.0.1g",
			expected:         false,
		},
		{
			name:             "bash shellshock vulnerable",
			installedVersion: "4.2",
			affectedVersions: "3.0-4.3",
			fixedVersion:     "4.3",
			expected:         true,
		},
		{
			name:             "bash shellshock fixed",
			installedVersion: "4.3",
			affectedVersions: "3.0-4.3",
			fixedVersion:     "4.3",
			expected:         false,
		},

		// Minimum version only (no max range)
		{
			name:             "above minimum, below fixed",
			installedVersion: "2.5",
			affectedVersions: "2.0",
			fixedVersion:     "3.0",
			expected:         true,
		},
		{
			name:             "below minimum",
			installedVersion: "1.5",
			affectedVersions: "2.0",
			fixedVersion:     "3.0",
			expected:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isVersionVulnerable(tt.installedVersion, tt.affectedVersions, tt.fixedVersion)
			if result != tt.expected {
				t.Errorf("isVersionVulnerable(%q, %q, %q) = %v, expected %v",
					tt.installedVersion, tt.affectedVersions, tt.fixedVersion, result, tt.expected)
			}
		})
	}
}

func TestIsBaseImageVulnerable(t *testing.T) {
	scanner := &VulnerabilityScanner{}

	tests := []struct {
		name      string
		baseImage string
		pattern   string
		expected  bool
	}{
		{"ubuntu 14.04 vulnerable", "ubuntu:14.04", "ubuntu:16.04", true},
		{"ubuntu 16.04 equal", "ubuntu:16.04", "ubuntu:16.04", true},
		{"ubuntu 18.04 not vulnerable", "ubuntu:18.04", "ubuntu:16.04", false},
		{"debian 8 vulnerable", "debian:8", "debian:9", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isBaseImageVulnerable(tt.baseImage, tt.pattern)
			if result != tt.expected {
				t.Errorf("isBaseImageVulnerable(%q, %q) = %v, expected %v",
					tt.baseImage, tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestCheckVulnerablePackages_NoDB(t *testing.T) {
	// Test that checkVulnerablePackages handles nil database gracefully
	scanner := NewVulnerabilityScanner(nil, nil)

	packages := []docker.PackageInfo{
		{
			Name:    "openssl",
			Version: "1.0.1e",
			Source:  "dpkg",
		},
	}

	// Should not panic when no DB - returns nil or empty slice
	findings := scanner.checkVulnerablePackages(context.Background(), packages)
	// Without a database, no findings should be returned
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings without DB, got %d", len(findings))
	}
}
