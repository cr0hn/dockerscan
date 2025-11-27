package cvedb

import (
	"testing"
)

func TestParseCPE23(t *testing.T) {
	tests := []struct {
		name            string
		cpe             string
		expectedVendor  string
		expectedProduct string
		expectedVersion string
		expectError     bool
	}{
		{
			name:            "Valid nginx CPE",
			cpe:             "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
			expectedVendor:  "nginx",
			expectedProduct: "nginx",
			expectedVersion: "1.18.0",
			expectError:     false,
		},
		{
			name:            "Valid openssl CPE",
			cpe:             "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
			expectedVendor:  "openssl",
			expectedProduct: "openssl",
			expectedVersion: "1.1.1k",
			expectError:     false,
		},
		{
			name:        "Invalid CPE format",
			cpe:         "invalid-cpe-string",
			expectError: true,
		},
		{
			name:        "Too few fields",
			cpe:         "cpe:2.3:a:vendor",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, product, version, err := ParseCPE23(tt.cpe)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if vendor != tt.expectedVendor {
				t.Errorf("Expected vendor %s, got %s", tt.expectedVendor, vendor)
			}

			if product != tt.expectedProduct {
				t.Errorf("Expected product %s, got %s", tt.expectedProduct, product)
			}

			if version != tt.expectedVersion {
				t.Errorf("Expected version %s, got %s", tt.expectedVersion, version)
			}
		})
	}
}

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "libssl with version",
			input:    "libssl1.1",
			expected: "ssl",
		},
		{
			name:     "python package",
			input:    "python3-requests",
			expected: "requests",
		},
		{
			name:     "lib64 prefix",
			input:    "lib64foo",
			expected: "foo",
		},
		{
			name:     "dev suffix",
			input:    "nginx-dev",
			expected: "nginx",
		},
		{
			name:     "simple package",
			input:    "nginx",
			expected: "nginx",
		},
		{
			name:     "lib with version and suffix",
			input:    "libcurl4-dev",
			expected: "curl4", // Version in middle is preserved, only trailing versions removed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePackageName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetCommonAliases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "openssl has multiple aliases",
			input:    "openssl",
			expected: []string{"openssl", "ssl", "libssl"},
		},
		{
			name:     "libssl1.1 normalizes to ssl",
			input:    "libssl1.1",
			expected: []string{"libssl1.1", "ssl", "openssl"}, // Normalized version is "ssl"
		},
		{
			name:     "nginx has core alias",
			input:    "nginx",
			expected: []string{"nginx", "nginx-core"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aliases := GetCommonAliases(tt.input)

			// Check that all expected aliases are present
			for _, expected := range tt.expected {
				found := false
				for _, alias := range aliases {
					if alias == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected alias %s not found in %v", expected, aliases)
				}
			}
		})
	}
}
