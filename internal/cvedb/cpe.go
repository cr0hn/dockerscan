package cvedb

import (
	"fmt"
	"regexp"
	"strings"
)

// ParseCPE23 parses a CPE 2.3 format string
// Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
// Example: cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
func ParseCPE23(cpe string) (vendor, product, version string, err error) {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return "", "", "", fmt.Errorf("invalid CPE format: must start with 'cpe:2.3:'")
	}

	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return "", "", "", fmt.Errorf("invalid CPE format: not enough fields")
	}

	// parts[0] = "cpe"
	// parts[1] = "2.3"
	// parts[2] = part (a=application, h=hardware, o=os)
	// parts[3] = vendor
	// parts[4] = product
	// parts[5] = version

	vendor = parts[3]
	product = parts[4]
	if len(parts) > 5 {
		version = parts[5]
	}

	// Unescape CPE encoded characters
	vendor = unescapeCPE(vendor)
	product = unescapeCPE(product)
	version = unescapeCPE(version)

	return vendor, product, version, nil
}

// unescapeCPE unescapes CPE special characters
// CPE uses \: for literal colons, etc.
func unescapeCPE(s string) string {
	s = strings.ReplaceAll(s, "\\:", ":")
	s = strings.ReplaceAll(s, "\\-", "-")
	s = strings.ReplaceAll(s, "\\.", ".")
	return s
}

// NormalizePackageName normalizes package names for matching
// Handles common patterns like:
//   - "libssl1.1" -> "ssl"
//   - "python3-requests" -> "requests"
//   - "lib64foo" -> "foo"
//   - "foo-dev" -> "foo"
//   - "foo-doc" -> "foo"
func NormalizePackageName(name string) string {
	// Remove common prefixes
	prefixes := []string{
		"lib64",
		"lib32",
		"lib",
		"python3-",
		"python2-",
		"python-",
		"perl-",
		"ruby-",
		"go-",
		"node-",
		"php-",
	}

	normalized := name
	for _, prefix := range prefixes {
		if strings.HasPrefix(normalized, prefix) {
			normalized = strings.TrimPrefix(normalized, prefix)
			break
		}
	}

	// Remove version suffixes (e.g., "ssl1.1" -> "ssl")
	versionPattern := regexp.MustCompile(`\d+(\.\d+)*$`)
	normalized = versionPattern.ReplaceAllString(normalized, "")

	// Remove common suffixes
	suffixes := []string{
		"-dev",
		"-devel",
		"-doc",
		"-docs",
		"-common",
		"-utils",
		"-bin",
		"-tools",
		"-data",
		"-dbg",
		"-debug",
	}

	for _, suffix := range suffixes {
		if strings.HasSuffix(normalized, suffix) {
			normalized = strings.TrimSuffix(normalized, suffix)
			break
		}
	}

	return normalized
}

// GetCommonAliases returns common aliases for a package name
// This helps match packages against CPE product names
func GetCommonAliases(pkgName string) []string {
	aliases := []string{pkgName}

	// Add normalized version
	normalized := NormalizePackageName(pkgName)
	if normalized != pkgName {
		aliases = append(aliases, normalized)
	}

	// Common special cases
	specialCases := map[string][]string{
		"openssl":     {"ssl", "libssl"},
		"libssl":      {"openssl", "ssl"},
		"libssl1.1":   {"openssl", "ssl"},
		"libssl3":     {"openssl", "ssl"},
		"nginx":       {"nginx", "nginx-core"},
		"nginx-core":  {"nginx"},
		"apache2":     {"httpd", "apache"},
		"httpd":       {"apache", "apache2"},
		"postgresql":  {"postgres", "pgsql"},
		"mariadb":     {"mysql"},
		"curl":        {"libcurl", "curl"},
		"libcurl":     {"curl"},
		"zlib":        {"zlib1g", "libz"},
		"zlib1g":      {"zlib", "libz"},
	}

	if extraAliases, ok := specialCases[pkgName]; ok {
		aliases = append(aliases, extraAliases...)
	}

	// Also check normalized name
	if extraAliases, ok := specialCases[normalized]; ok {
		aliases = append(aliases, extraAliases...)
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, alias := range aliases {
		if !seen[alias] {
			seen[alias] = true
			unique = append(unique, alias)
		}
	}

	return unique
}
