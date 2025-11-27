package vulnerabilities

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cr0hn/dockerscan/v2/internal/cvedb"
	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

// VulnerabilityScanner detects CVEs and security vulnerabilities
type VulnerabilityScanner struct {
	scanner.BaseScanner
	dockerClient *docker.Client
	cveDB        *cvedb.CVEDB // External CVE database
}

// NewVulnerabilityScanner creates a new vulnerability scanner
func NewVulnerabilityScanner(dockerClient *docker.Client, db *cvedb.CVEDB) *VulnerabilityScanner {
	return &VulnerabilityScanner{
		BaseScanner: scanner.NewBaseScanner(
			"vulnerabilities",
			"CVE detection using external vulnerability database",
			true,
		),
		dockerClient: dockerClient,
		cveDB:        db,
	}
}

// Scan performs vulnerability scanning
func (s *VulnerabilityScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding
	var packages []docker.PackageInfo
	var history []docker.HistoryEntry
	var imageInfo *docker.ImageInfo

	// Get installed packages from the image (non-fatal if fails)
	pkgs, err := s.dockerClient.ListPackages(ctx, target.ImageName)
	if err == nil {
		packages = pkgs
	}
	// Continue even if package listing fails

	// Get image history to detect base image (non-fatal if fails)
	hist, err := s.dockerClient.GetImageHistory(ctx, target.ImageName)
	if err == nil {
		history = hist
	}

	// Get image info for OS detection (required)
	info, err := s.dockerClient.InspectImage(ctx, target.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}
	imageInfo = info

	// Check for vulnerable packages with actual version comparison
	if len(packages) > 0 {
		findings = append(findings, s.checkVulnerablePackages(ctx, packages)...)
	}

	// Check base image from history
	findings = append(findings, s.checkBaseImage(history, imageInfo)...)

	// Check for EOL images
	findings = append(findings, s.checkEOLImages(history, imageInfo)...)

	// Check for specific 2024 CVEs based on actual components
	findings = append(findings, s.check2024CVEs(packages, imageInfo)...)

	return findings, nil
}

// checkVulnerablePackages checks installed packages against vulnerability database
func (s *VulnerabilityScanner) checkVulnerablePackages(ctx context.Context, packages []docker.PackageInfo) []models.Finding {
	var findings []models.Finding

	// Skip if no database
	if s.cveDB == nil {
		return findings
	}

	// Convert to cvedb.PackageInfo
	pkgInfos := make([]cvedb.PackageInfo, len(packages))
	for i, p := range packages {
		pkgInfos[i] = cvedb.PackageInfo{
			Name:    p.Name,
			Version: p.Version,
			Source:  p.Source,
		}
	}

	// Query database
	cvesByPkg, err := s.cveDB.QueryByPackages(pkgInfos)
	if err != nil {
		return findings
	}

	// Check each package
	for _, pkg := range packages {
		cves := cvesByPkg[pkg.Name]
		for _, cve := range cves {
			// Use existing version comparison logic
			if s.isVersionVulnerable(pkg.Version, cve.VersionStart+"-"+cve.VersionEnd, cve.FixedVersion) {
				finding := models.Finding{
					ID:          cve.CVEID + "-" + pkg.Name,
					Title:       fmt.Sprintf("%s in %s %s", cve.CVEID, pkg.Name, pkg.Version),
					Description: cve.Description,
					Severity:    models.Severity(cve.Severity),
					Category:    "Vulnerabilities",
					Source:      s.Name(),
					Remediation: fmt.Sprintf("Upgrade %s to version %s or later", pkg.Name, cve.FixedVersion),
					References:  cve.References,
					Metadata: map[string]interface{}{
						"cve_id":          cve.CVEID,
						"package_name":    pkg.Name,
						"package_version": pkg.Version,
						"fixed_version":   cve.FixedVersion,
						"cvss_score":      cve.CVSSScore,
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkBaseImage detects the base image from history
func (s *VulnerabilityScanner) checkBaseImage(history []docker.HistoryEntry, imageInfo *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	// Parse history to find FROM instruction
	baseImage := s.detectBaseImageFromHistory(history)

	if baseImage == "" {
		// Try to detect from image tags
		if len(imageInfo.RepoTags) > 0 {
			tag := imageInfo.RepoTags[0]
			if strings.Contains(tag, ":") {
				parts := strings.Split(tag, ":")
				if len(parts) >= 2 {
					baseImage = parts[0]
				}
			}
		}
	}

	if baseImage != "" {
		// Check if base image is known to be vulnerable
		vulnerableBaseImages := map[string]VulnerableBaseImage{
			"ubuntu:14.04": {
				Name:        "ubuntu:14.04",
				Reason:      "Ubuntu 14.04 reached end-of-life in April 2019",
				Severity:    models.SeverityHigh,
				Replacement: "ubuntu:22.04 or ubuntu:24.04",
			},
			"ubuntu:16.04": {
				Name:        "ubuntu:16.04",
				Reason:      "Ubuntu 16.04 reached end-of-life in April 2021",
				Severity:    models.SeverityHigh,
				Replacement: "ubuntu:22.04 or ubuntu:24.04",
			},
			"debian:7": {
				Name:        "debian:7 (wheezy)",
				Reason:      "Debian 7 reached end-of-life in May 2018",
				Severity:    models.SeverityHigh,
				Replacement: "debian:12 (bookworm) or debian:11 (bullseye)",
			},
			"debian:8": {
				Name:        "debian:8 (jessie)",
				Reason:      "Debian 8 reached end-of-life in June 2020",
				Severity:    models.SeverityHigh,
				Replacement: "debian:12 (bookworm) or debian:11 (bullseye)",
			},
			"centos:6": {
				Name:        "centos:6",
				Reason:      "CentOS 6 reached end-of-life in November 2020",
				Severity:    models.SeverityCritical,
				Replacement: "rockylinux:9 or almalinux:9",
			},
			"centos:7": {
				Name:        "centos:7",
				Reason:      "CentOS 7 reached end-of-life in June 2024",
				Severity:    models.SeverityHigh,
				Replacement: "rockylinux:9 or almalinux:9",
			},
			"centos:8": {
				Name:        "centos:8",
				Reason:      "CentOS 8 reached end-of-life in December 2021",
				Severity:    models.SeverityHigh,
				Replacement: "rockylinux:9 or almalinux:9",
			},
		}

		// Check exact match first
		if vulnBase, exists := vulnerableBaseImages[baseImage]; exists {
			finding := models.Finding{
				ID:          "VULN-BASE-IMAGE-EOL",
				Title:       fmt.Sprintf("End-of-life base image: %s", vulnBase.Name),
				Description: fmt.Sprintf("%s. This image no longer receives security updates and contains unpatched vulnerabilities.", vulnBase.Reason),
				Severity:    vulnBase.Severity,
				Category:    "Vulnerability",
				Source:      "vulnerabilities",
				Remediation: fmt.Sprintf("Update base image to %s and rebuild the container.", vulnBase.Replacement),
				Metadata: map[string]interface{}{
					"base_image":  vulnBase.Name,
					"status":      "end-of-life",
					"replacement": vulnBase.Replacement,
				},
			}
			findings = append(findings, finding)
		} else {
			// Check partial matches
			for pattern, vulnBase := range vulnerableBaseImages {
				if strings.HasPrefix(baseImage, strings.Split(pattern, ":")[0]) {
					// Additional version check
					if s.isBaseImageVulnerable(baseImage, pattern) {
						finding := models.Finding{
							ID:          "VULN-BASE-IMAGE-EOL",
							Title:       fmt.Sprintf("Potentially outdated base image: %s", baseImage),
							Description: fmt.Sprintf("Base image appears to be based on %s. %s", vulnBase.Name, vulnBase.Reason),
							Severity:    models.SeverityMedium,
							Category:    "Vulnerability",
							Source:      "vulnerabilities",
							Remediation: fmt.Sprintf("Verify base image version and consider updating to %s.", vulnBase.Replacement),
							Metadata: map[string]interface{}{
								"base_image":  baseImage,
								"status":      "potentially-outdated",
								"replacement": vulnBase.Replacement,
							},
						}
						findings = append(findings, finding)
						break
					}
				}
			}
		}
	}

	return findings
}

// checkEOLImages checks for end-of-life distributions
func (s *VulnerabilityScanner) checkEOLImages(history []docker.HistoryEntry, imageInfo *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	// Map of EOL distributions with versions
	eolDistros := map[string]EOLInfo{
		"node:10": {
			Name:        "Node.js 10",
			EOLDate:     "2021-04-30",
			Risk:        "Node.js 10 no longer receives security updates",
			Replacement: "node:20 or node:18 LTS",
			Severity:    models.SeverityCritical,
		},
		"node:12": {
			Name:        "Node.js 12",
			EOLDate:     "2022-04-30",
			Risk:        "Node.js 12 no longer receives security updates",
			Replacement: "node:20 or node:18 LTS",
			Severity:    models.SeverityHigh,
		},
		"node:14": {
			Name:        "Node.js 14",
			EOLDate:     "2023-04-30",
			Risk:        "Node.js 14 no longer receives security updates",
			Replacement: "node:20 or node:18 LTS",
			Severity:    models.SeverityHigh,
		},
		"node:16": {
			Name:        "Node.js 16",
			EOLDate:     "2023-09-11",
			Risk:        "Node.js 16 no longer receives security updates",
			Replacement: "node:20 or node:22 LTS",
			Severity:    models.SeverityMedium,
		},
		"python:2.7": {
			Name:        "Python 2.7",
			EOLDate:     "2020-01-01",
			Risk:        "Python 2.7 reached end-of-life and contains numerous unpatched vulnerabilities",
			Replacement: "python:3.12 or python:3.11",
			Severity:    models.SeverityCritical,
		},
		"python:3.6": {
			Name:        "Python 3.6",
			EOLDate:     "2021-12-23",
			Risk:        "Python 3.6 no longer receives security updates",
			Replacement: "python:3.12 or python:3.11",
			Severity:    models.SeverityHigh,
		},
		"python:3.7": {
			Name:        "Python 3.7",
			EOLDate:     "2023-06-27",
			Risk:        "Python 3.7 no longer receives security updates",
			Replacement: "python:3.12 or python:3.11",
			Severity:    models.SeverityMedium,
		},
	}

	// Detect base image from history
	baseImage := s.detectBaseImageFromHistory(history)

	// Also check image repo tags (e.g., "node:16-alpine")
	imageTags := ""
	if imageInfo != nil && len(imageInfo.RepoTags) > 0 {
		imageTags = strings.Join(imageInfo.RepoTags, " ")
	}

	// Check against EOL distros - search in both base image and image tags
	for pattern, eolInfo := range eolDistros {
		lowerPattern := strings.ToLower(pattern)
		if strings.Contains(strings.ToLower(baseImage), lowerPattern) ||
			strings.Contains(strings.ToLower(imageTags), lowerPattern) {
			finding := models.Finding{
				ID:          fmt.Sprintf("VULN-EOL-%s", strings.ToUpper(strings.ReplaceAll(pattern, ":", "-"))),
				Title:       fmt.Sprintf("End-of-life runtime detected: %s", eolInfo.Name),
				Description: fmt.Sprintf("%s (EOL: %s). This version contains known unpatched security vulnerabilities.", eolInfo.Risk, eolInfo.EOLDate),
				Severity:    eolInfo.Severity,
				Category:    "Vulnerability",
				Source:      "vulnerabilities",
				Remediation: fmt.Sprintf("Upgrade to %s and rebuild the image.", eolInfo.Replacement),
				References: []string{
					"https://endoflife.date/",
				},
				Metadata: map[string]interface{}{
					"component":   eolInfo.Name,
					"eol_date":    eolInfo.EOLDate,
					"replacement": eolInfo.Replacement,
					"detected_in": imageTags,
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// check2024CVEs checks for specific 2024 CVEs based on installed components
func (s *VulnerabilityScanner) check2024CVEs(packages []docker.PackageInfo, imageInfo *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	// Create package map for quick lookup
	packageMap := make(map[string]docker.PackageInfo)
	for _, pkg := range packages {
		packageMap[pkg.Name] = pkg
	}

	// CVE-2024-21626: runc container escape
	// Check if runc is installed and version is vulnerable
	if runcPkg, exists := packageMap["runc"]; exists {
		if s.compareVersion(runcPkg.Version, "1.1.12") < 0 {
			finding := models.Finding{
				ID:          "CVE-2024-21626",
				Title:       "Critical runc vulnerability - Container Escape (CVE-2024-21626)",
				Description: fmt.Sprintf("runc version %s is vulnerable to container escape (CVE-2024-21626). An attacker can escape the container and gain access to the host system. Versions before 1.1.12 are affected.", runcPkg.Version),
				Severity:    models.SeverityCritical,
				Category:    "Vulnerability",
				Source:      "vulnerabilities",
				Remediation: "Update runc to version 1.1.12 or later. Update Docker Engine to latest version.",
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
					"https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv",
				},
				Metadata: map[string]interface{}{
					"cvss_score":        8.6,
					"cve_id":            "CVE-2024-21626",
					"component":         "runc",
					"installed_version": runcPkg.Version,
					"fixed_version":     "1.1.12",
				},
			}
			findings = append(findings, finding)
		}
	}

	// CVE-2024-23651, CVE-2024-23652, CVE-2024-23653: BuildKit vulnerabilities
	// Check if buildkit or docker-buildx is installed
	if buildkitPkg, exists := packageMap["buildkit"]; exists {
		if s.compareVersion(buildkitPkg.Version, "0.12.5") < 0 {
			// CVE-2024-23651: Cache poisoning
			finding1 := models.Finding{
				ID:          "CVE-2024-23651",
				Title:       "BuildKit cache poisoning vulnerability (CVE-2024-23651)",
				Description: fmt.Sprintf("BuildKit version %s is vulnerable to cache poisoning which can lead to remote code execution during image build. Versions before 0.12.5 are affected.", buildkitPkg.Version),
				Severity:    models.SeverityCritical,
				Category:    "Vulnerability",
				Source:      "vulnerabilities",
				Remediation: "Update BuildKit to version 0.12.5 or later. Update Docker to version 25.0.2 or later.",
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2024-23651",
					"https://github.com/moby/buildkit/security/advisories/GHSA-m3r6-h7wv-7xxv",
				},
				Metadata: map[string]interface{}{
					"cvss_score":        9.1,
					"cve_id":            "CVE-2024-23651",
					"component":         "buildkit",
					"installed_version": buildkitPkg.Version,
					"fixed_version":     "0.12.5",
				},
			}
			findings = append(findings, finding1)

			// CVE-2024-23652: Race condition
			finding2 := models.Finding{
				ID:          "CVE-2024-23652",
				Title:       "BuildKit race condition vulnerability (CVE-2024-23652)",
				Description: fmt.Sprintf("BuildKit version %s has a race condition that can lead to unauthorized access to build secrets. Versions before 0.12.5 are affected.", buildkitPkg.Version),
				Severity:    models.SeverityHigh,
				Category:    "Vulnerability",
				Source:      "vulnerabilities",
				Remediation: "Update BuildKit to version 0.12.5 or later.",
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2024-23652",
					"https://github.com/moby/buildkit/security/advisories/GHSA-4v98-7qmw-rqr8",
				},
				Metadata: map[string]interface{}{
					"cvss_score":        7.5,
					"cve_id":            "CVE-2024-23652",
					"component":         "buildkit",
					"installed_version": buildkitPkg.Version,
					"fixed_version":     "0.12.5",
				},
			}
			findings = append(findings, finding2)

			// CVE-2024-23653: Privilege escalation
			finding3 := models.Finding{
				ID:          "CVE-2024-23653",
				Title:       "BuildKit privilege escalation vulnerability (CVE-2024-23653)",
				Description: fmt.Sprintf("BuildKit version %s is vulnerable to privilege escalation attacks. Versions before 0.12.5 are affected.", buildkitPkg.Version),
				Severity:    models.SeverityHigh,
				Category:    "Vulnerability",
				Source:      "vulnerabilities",
				Remediation: "Update BuildKit to version 0.12.5 or later.",
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2024-23653",
					"https://github.com/moby/buildkit/security/advisories/GHSA-wr6v-9f75-vh2g",
				},
				Metadata: map[string]interface{}{
					"cvss_score":        7.8,
					"cve_id":            "CVE-2024-23653",
					"component":         "buildkit",
					"installed_version": buildkitPkg.Version,
					"fixed_version":     "0.12.5",
				},
			}
			findings = append(findings, finding3)
		}
	}

	// Note: CVE-2024-8695, CVE-2024-8696, and CVE-2025-9074 affect Docker Desktop specifically,
	// which is not part of the image itself but the host system. These would need to be checked
	// separately through Docker daemon version detection.

	return findings
}

// detectBaseImageFromHistory parses image history to find the FROM instruction
func (s *VulnerabilityScanner) detectBaseImageFromHistory(history []docker.HistoryEntry) string {
	// Convert history entries to strings for processing
	historyStrings := make([]string, len(history))
	for i, entry := range history {
		historyStrings[i] = entry.CreatedBy
	}

	// Use the shared helper function to extract the last base image
	// This handles multi-stage builds and platform flags correctly
	return models.ExtractLastBaseImage(historyStrings)
}

// isVersionVulnerable checks if a version is vulnerable
// A package is vulnerable if it's within the affected version range AND below the fixed version
func (s *VulnerabilityScanner) isVersionVulnerable(installedVersion, affectedVersions, fixedVersion string) bool {
	inAffectedRange := false
	belowFixedVersion := false

	// Parse version ranges (e.g., "1.0.1-1.0.1f" or "2.0-2.14.1")
	if affectedVersions != "" && strings.Contains(affectedVersions, "-") {
		parts := strings.Split(affectedVersions, "-")
		if len(parts) == 2 {
			minVersion := strings.TrimSpace(parts[0])
			maxVersion := strings.TrimSpace(parts[1])

			// Check if installed version is within vulnerable range
			if s.compareVersion(installedVersion, minVersion) >= 0 &&
				s.compareVersion(installedVersion, maxVersion) <= 0 {
				inAffectedRange = true
			}
		}
	} else if affectedVersions != "" {
		// If no range specified, treat as minimum version
		if s.compareVersion(installedVersion, affectedVersions) >= 0 {
			inAffectedRange = true
		}
	} else {
		// No affected versions specified, assume all versions before fix are affected
		inAffectedRange = true
	}

	// Check if version is less than fixed version
	if fixedVersion != "" {
		if s.compareVersion(installedVersion, fixedVersion) < 0 {
			belowFixedVersion = true
		}
	} else {
		// No fixed version specified, so can't determine if fixed
		belowFixedVersion = true
	}

	// Vulnerable if in affected range AND below fixed version
	return inAffectedRange && belowFixedVersion
}

// isBaseImageVulnerable checks if a base image version is vulnerable
func (s *VulnerabilityScanner) isBaseImageVulnerable(baseImage, pattern string) bool {
	// Extract version from base image (e.g., ubuntu:16.04 -> 16.04)
	imageParts := strings.Split(baseImage, ":")
	if len(imageParts) < 2 {
		return false
	}

	patternParts := strings.Split(pattern, ":")
	if len(patternParts) < 2 {
		return false
	}

	imageVersion := imageParts[1]
	patternVersion := patternParts[1]

	// Simple version comparison
	return s.compareVersion(imageVersion, patternVersion) <= 0
}

// compareVersion compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func (s *VulnerabilityScanner) compareVersion(v1, v2 string) int {
	// Clean version strings
	v1 = s.cleanVersion(v1)
	v2 = s.cleanVersion(v2)

	if v1 == v2 {
		return 0
	}

	// Split by dots and compare each part
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 string
		if i < len(parts1) {
			p1 = parts1[i]
		} else {
			p1 = "0"
		}
		if i < len(parts2) {
			p2 = parts2[i]
		} else {
			p2 = "0"
		}

		// Extract numeric part
		n1, hasNum1 := s.extractNumber(p1)
		n2, hasNum2 := s.extractNumber(p2)

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}

		// If numbers are equal, compare suffix using semantic versioning rules
		s1 := s.extractSuffix(p1)
		s2 := s.extractSuffix(p2)

		if s1 != s2 {
			// Apply semantic version suffix ordering
			cmp := s.compareSuffix(s1, s2, hasNum1, hasNum2)
			if cmp != 0 {
				return cmp
			}
		}
	}

	return 0
}

// cleanVersion removes common version prefixes
func (s *VulnerabilityScanner) cleanVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")

	// Remove Debian/Ubuntu epoch (e.g., "1:1.2.3-4" or "100:1.2.3-4" -> "1.2.3-4")
	// Epochs can be any number of digits, so we check if the part before ":" is all digits
	if idx := strings.Index(version, ":"); idx > 0 {
		epochPart := version[:idx]
		if _, err := strconv.Atoi(epochPart); err == nil {
			version = version[idx+1:]
		}
	}

	// Remove Debian/Ubuntu revision (e.g., "1.2.3-4" or "1.2.3-4ubuntu1" -> "1.2.3")
	if idx := strings.LastIndex(version, "-"); idx > 0 {
		// Check if it's a Debian/Ubuntu revision
		suffix := version[idx+1:]
		// Pure numeric (Debian) or starts with numeric (Ubuntu)
		if _, err := strconv.Atoi(suffix); err == nil {
			version = version[:idx]
		} else if len(suffix) > 0 && suffix[0] >= '0' && suffix[0] <= '9' {
			// Ubuntu-style revision (e.g., "4ubuntu1")
			version = version[:idx]
		}
	}

	return version
}

// extractNumber extracts the numeric part from a version component
// Returns the number and a boolean indicating if a number was found
func (s *VulnerabilityScanner) extractNumber(part string) (int, bool) {
	numRegex := regexp.MustCompile(`^\d+`)
	numStr := numRegex.FindString(part)
	if numStr == "" {
		return 0, false
	}
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, false
	}
	return num, true
}

// extractSuffix extracts the non-numeric suffix from a version component
func (s *VulnerabilityScanner) extractSuffix(part string) string {
	numRegex := regexp.MustCompile(`^\d+`)
	return numRegex.ReplaceAllString(part, "")
}

// compareSuffix compares version suffixes using semantic versioning rules
// Pre-release versions (alpha, beta, rc) are considered LESS than final releases
// Returns: -1 if s1 < s2, 0 if s1 == s2, 1 if s1 > s2
func (s *VulnerabilityScanner) compareSuffix(s1, s2 string, hasNum1, hasNum2 bool) int {
	// Normalize suffixes to lowercase for comparison
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	// Define pre-release suffix order (lower index = earlier/lesser version)
	preReleaseSuffixes := []string{"alpha", "a", "beta", "b", "rc", "pre", "preview"}

	// Helper to get pre-release priority (returns -1 if not a pre-release)
	getPriority := func(suffix string) int {
		for i, pre := range preReleaseSuffixes {
			if strings.HasPrefix(suffix, pre) {
				return i
			}
		}
		return -1
	}

	priority1 := getPriority(s1)
	priority2 := getPriority(s2)

	// Case 1: Both are pre-release suffixes
	if priority1 >= 0 && priority2 >= 0 {
		if priority1 < priority2 {
			return -1
		}
		if priority1 > priority2 {
			return 1
		}
		// Same type of pre-release, compare lexicographically
		if s1 < s2 {
			return -1
		}
		if s1 > s2 {
			return 1
		}
		return 0
	}

	// Case 2: Only s1 is a pre-release (s1 < s2)
	if priority1 >= 0 && priority2 < 0 {
		// s1 is pre-release, s2 is either final or post-release
		if s2 == "" {
			// s2 is final release (no suffix), s1 is pre-release
			return -1
		}
		// s2 has a suffix but not pre-release (e.g., "post", "patch", etc.)
		// Pre-release comes before final, which comes before post-release
		return -1
	}

	// Case 3: Only s2 is a pre-release (s1 > s2)
	if priority1 < 0 && priority2 >= 0 {
		// s2 is pre-release, s1 is either final or post-release
		if s1 == "" {
			// s1 is final release (no suffix), s2 is pre-release
			return 1
		}
		// s1 has a suffix but not pre-release
		return 1
	}

	// Case 4: Neither is a pre-release suffix
	// Check for empty suffix (final release)
	if s1 == "" && s2 != "" {
		// s1 is final, s2 has some suffix (post-release)
		// Final comes before post-release
		return -1
	}
	if s1 != "" && s2 == "" {
		// s2 is final, s1 has some suffix (post-release)
		return 1
	}

	// Both are either final (both empty) or both post-release
	// Use lexicographic comparison
	if s1 < s2 {
		return -1
	}
	if s1 > s2 {
		return 1
	}
	return 0
}

// VulnerabilityInfo represents a vulnerability entry
type VulnerabilityInfo struct {
	CVEID            string
	Description      string
	AffectedVersions string
	FixedVersion     string
	Severity         models.Severity
	CVSSScore        float64
	References       []string
}

// VulnerableBaseImage represents a vulnerable base image
type VulnerableBaseImage struct {
	Name        string
	Reason      string
	Severity    models.Severity
	Replacement string
}

// EOLInfo represents end-of-life information
type EOLInfo struct {
	Name        string
	EOLDate     string
	Risk        string
	Replacement string
	Severity    models.Severity
}
