package secrets

import (
	"context"
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func TestNewSecretsScanner(t *testing.T) {
	scanner := NewSecretsScanner()
	if scanner == nil {
		t.Fatal("Expected scanner to be created")
	}
	if scanner.Name() != "secrets" {
		t.Errorf("Expected name 'secrets', got %s", scanner.Name())
	}
	if !scanner.Enabled() {
		t.Error("Expected scanner to be enabled")
	}
	if len(scanner.patterns) == 0 {
		t.Error("Expected patterns to be initialized")
	}
}

func TestSecretsScanner_InitializePatterns(t *testing.T) {
	scanner := NewSecretsScanner()

	expectedPatterns := []string{
		"AWS_ACCESS_KEY",
		"AWS_SECRET_KEY",
		"GCP_API_KEY",
		"GITHUB_TOKEN",
		"OPENAI_API_KEY",
		"ANTHROPIC_KEY",
		"SLACK_TOKEN",
		"JWT_TOKEN",
		"RSA_PRIVATE_KEY",
	}

	for _, patternName := range expectedPatterns {
		if _, exists := scanner.patterns[patternName]; !exists {
			t.Errorf("Expected pattern %s to be initialized", patternName)
		}
	}
}

func TestSecretsScanner_Scan(t *testing.T) {
	scanner := NewSecretsScanner()
	target := models.ScanTarget{
		ImageName: "test:latest",
	}

	findings, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should find some findings from the example env vars
	if len(findings) == 0 {
		t.Error("Expected to find some secrets in example data")
	}
}

func TestSecretsScanner_CalculateEntropy(t *testing.T) {
	scanner := NewSecretsScanner()

	tests := []struct {
		name     string
		input    string
		minEntropy float64
		maxEntropy float64
	}{
		{"Empty string", "", 0.0, 0.0},
		{"Low entropy", "aaaaaaa", 0.0, 0.1},
		{"Medium entropy", "abc123", 1.0, 3.0},
		{"High entropy", "Kj8#mP2$xQ9@", 3.0, 5.0},
		{"Very high entropy", "A3k$9mP#2xQ@7zB!5nC&", 3.5, 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := scanner.calculateEntropy(tt.input)
			if entropy < tt.minEntropy || entropy > tt.maxEntropy {
				t.Errorf("Entropy for '%s' should be between %f and %f, got %f",
					tt.input, tt.minEntropy, tt.maxEntropy, entropy)
			}
		})
	}
}

func TestSecretsScanner_GetSeverityForSecretType(t *testing.T) {
	scanner := NewSecretsScanner()

	criticalTypes := []string{
		"AWS_ACCESS_KEY",
		"AWS_SECRET_KEY",
		"RSA_PRIVATE_KEY",
		"GCP_SERVICE_ACCOUNT",
	}

	for _, secretType := range criticalTypes {
		severity := scanner.getSeverityForSecretType(secretType)
		if severity != models.SeverityCritical {
			t.Errorf("Expected CRITICAL severity for %s, got %s", secretType, severity)
		}
	}

	// Test non-critical type
	severity := scanner.getSeverityForSecretType("SOME_OTHER_KEY")
	if severity != models.SeverityHigh {
		t.Errorf("Expected HIGH severity for unknown type, got %s", severity)
	}
}

func TestSecretsScanner_RedactSecret(t *testing.T) {
	scanner := NewSecretsScanner()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Short secret", "abc", "***REDACTED***"},
		{"Medium secret", "abcdefgh", "***REDACTED***"},
		{"Long secret", "abcdefghijklmnop", "abcd***REDACTED***mnop"},
		{"AWS key", "AKIAIOSFODNN7EXAMPLE", "AKIA***REDACTED***MPLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redacted := scanner.redactSecret(tt.input)
			if redacted != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, redacted)
			}
		})
	}
}

func TestSecretsScanner_PatternMatching(t *testing.T) {
	scanner := NewSecretsScanner()

	tests := []struct {
		patternName string
		testString  string
		shouldMatch bool
	}{
		{"AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS_ACCESS_KEY", "not-a-key", false},
		{"GITHUB_TOKEN", "ghp_123456789012345678901234567890123456", true},
		{"GITHUB_TOKEN", "not-a-token", false},
		{"JWT_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", true},
		{"RSA_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"OPENAI_API_KEY", "sk-123456789012345678901234567890123456789012345678", true},
	}

	for _, tt := range tests {
		t.Run(tt.patternName+"_"+tt.testString, func(t *testing.T) {
			pattern, exists := scanner.patterns[tt.patternName]
			if !exists {
				t.Fatalf("Pattern %s not found", tt.patternName)
			}

			matches := pattern.MatchString(tt.testString)
			if matches != tt.shouldMatch {
				t.Errorf("Pattern %s matching '%s': expected %v, got %v",
					tt.patternName, tt.testString, tt.shouldMatch, matches)
			}
		})
	}
}
