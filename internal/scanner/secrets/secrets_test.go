package secrets

import (
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

func TestNewSecretsScanner(t *testing.T) {
	scanner := NewSecretsScanner(nil)
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
	scanner := NewSecretsScanner(nil)

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
		"STRIPE_KEY",
		"SENDGRID_KEY",
		"POSTGRES_URL",
		"MONGODB_URL",
	}

	for _, patternName := range expectedPatterns {
		if _, exists := scanner.patterns[patternName]; !exists {
			t.Errorf("Expected pattern %s to be initialized", patternName)
		}
	}
}

func TestSecretsScanner_CalculateEntropy(t *testing.T) {
	scanner := NewSecretsScanner(nil)

	tests := []struct {
		name       string
		input      string
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
	scanner := NewSecretsScanner(nil)

	criticalTypes := []string{
		"AWS_ACCESS_KEY",
		"AWS_SECRET_KEY",
		"RSA_PRIVATE_KEY",
		"GCP_SERVICE_ACCOUNT",
		"OPENSSH_PRIVATE_KEY",
		"AZURE_CLIENT_SECRET",
	}

	for _, secretType := range criticalTypes {
		severity := scanner.getSeverityForSecretType(secretType)
		if severity != models.SeverityCritical {
			t.Errorf("Expected CRITICAL severity for %s, got %s", secretType, severity)
		}
	}

	// Test high severity types
	highTypes := []string{
		"GITHUB_TOKEN",
		"SLACK_TOKEN",
		"STRIPE_KEY",
		"OPENAI_API_KEY",
	}

	for _, secretType := range highTypes {
		severity := scanner.getSeverityForSecretType(secretType)
		if severity != models.SeverityHigh {
			t.Errorf("Expected HIGH severity for %s, got %s", secretType, severity)
		}
	}

	// Test unknown type defaults to medium
	severity := scanner.getSeverityForSecretType("SOME_UNKNOWN_KEY")
	if severity != models.SeverityMedium {
		t.Errorf("Expected MEDIUM severity for unknown type, got %s", severity)
	}
}

func TestSecretsScanner_RedactSecret(t *testing.T) {
	scanner := NewSecretsScanner(nil)

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
	scanner := NewSecretsScanner(nil)

	tests := []struct {
		patternName string
		testString  string
		shouldMatch bool
	}{
		// AWS patterns
		{"AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS_ACCESS_KEY", "not-a-key", false},
		{"AWS_ACCESS_KEY", "AKIA1234567890123456", true},

		// GitHub tokens
		{"GITHUB_TOKEN", "ghp_123456789012345678901234567890123456", true},
		{"GITHUB_TOKEN", "not-a-token", false},
		{"GITHUB_OAUTH", "gho_123456789012345678901234567890123456", true},

		// GitLab tokens
		{"GITLAB_TOKEN", "glpat-12345678901234567890", true},
		{"GITLAB_TOKEN", "not-gitlab", false},

		// JWT
		{"JWT_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", true},
		{"JWT_TOKEN", "not.a.jwt", false},

		// Private keys
		{"RSA_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"OPENSSH_PRIVATE_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"EC_PRIVATE_KEY", "-----BEGIN EC PRIVATE KEY-----", true},
		{"DSA_PRIVATE_KEY", "-----BEGIN DSA PRIVATE KEY-----", true},

		// OpenAI
		{"OPENAI_API_KEY", "sk-123456789012345678901234567890123456789012345678", true},
		{"OPENAI_API_KEY", "not-openai-key", false},

		// Stripe - using obviously fake test values
		{"STRIPE_KEY", "sk_test_FAKE00000000000000000000", true},
		{"STRIPE_KEY", "pk_live_FAKE00000000000000000000", true},
		{"STRIPE_KEY", "not-stripe-key", false},

		// Slack - using obviously fake test values
		{"SLACK_TOKEN", "xoxb-0000000000-0000000000-FAKEFAKEFAKEFAKEFAKEFAKE", true},
		{"SLACK_TOKEN", "not-slack-token", false},

		// SendGrid
		{"SENDGRID_KEY", "SG.1234567890123456789012.12345678901234567890123456789012345678901234", true},

		// Google API
		{"GCP_API_KEY", "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe", true},
		{"GCP_API_KEY", "not-google-key", false},

		// Database URLs
		{"POSTGRES_URL", "postgresql://user:pass@localhost:5432/mydb", true},
		{"MYSQL_URL", "mysql://user:pass@localhost:3306/mydb", true},
		{"MONGODB_URL", "mongodb://user:pass@localhost:27017/mydb", true},
		{"MONGODB_URL", "mongodb+srv://user:pass@cluster.mongodb.net/mydb", true},

		// Docker auth
		{"DOCKER_AUTH", `"auth": "dXNlcjpwYXNz"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.patternName+"_"+tt.testString[:min(20, len(tt.testString))], func(t *testing.T) {
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

func TestSecretsScanner_EntropyThreshold(t *testing.T) {
	scanner := NewSecretsScanner(nil)

	// Test that high-entropy strings are detected
	highEntropyStrings := []string{
		"a9f8g7h6j5k4l3m2n1o0p9q8r7s6t5u4",
		"xK9mLpQrStUvWxYz1234567890AbCdEf",
	}

	for _, s := range highEntropyStrings {
		entropy := scanner.calculateEntropy(s)
		if entropy <= 4.0 {
			t.Errorf("Expected high entropy (>4.0) for '%s', got %f", s, entropy)
		}
	}

	// Test that low-entropy strings have low entropy
	lowEntropyStrings := []string{
		"aaaaaaaaaaa",
		"123123123123",
	}

	for _, s := range lowEntropyStrings {
		entropy := scanner.calculateEntropy(s)
		if entropy > 3.0 {
			t.Errorf("Expected low entropy (<3.0) for '%s', got %f", s, entropy)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
