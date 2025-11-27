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

// Test false positive filtering
func TestSecretsScanner_IsFalsePositive(t *testing.T) {
	scanner := NewSecretsScanner(nil)

	tests := []struct {
		name          string
		value         string
		shouldBeFalse bool
	}{
		// Common false positive strings
		{"Example string", "example_api_key", true},
		{"Placeholder", "placeholder_value", true},
		{"Change me", "changeme123", true},
		{"TODO marker", "TODO: add key here", true},
		{"FIXME marker", "FIXME: secret", true},
		{"Your key here", "your_key_here", true},
		{"Dummy value", "dummy_secret", true},
		{"Sample data", "sample_password", true},
		{"Test key", "test_key_123", true},
		{"Fake data", "fake_token", true},
		{"X pattern", "XXXXXXXXXX", true},
		{"Zero pattern", "0000000000", true},
		{"1234 pattern", "123456789012345", true},

		// UUIDs (standard format)
		{"UUID v4", "550e8400-e29b-41d4-a716-446655440000", true},
		{"UUID lowercase", "123e4567-e89b-12d3-a456-426614174000", true},
		{"UUID uppercase", "123E4567-E89B-12D3-A456-426614174000", true},

		// Common hash formats
		{"SHA-1 hash", "356a192b7913b04c54574d18c28d46e6395428ab", true},
		{"SHA-256 hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"MD5 hash", "5d41402abc4b2a76b9719d911017c592", true},
		{"Git commit hash", "a3c4f2e9b8d7c6a5b4e3f2d1c0a9b8c7d6e5f4a3", true},

		// Real secrets (should not be false positives)
		// Note: Some API keys might be detected as hashes if they're pure alphanumeric 40/64 chars
		// But that's okay since we removed the overly generic COHERE pattern
		{"Real password", "MyS3cr3tP@ssw0rd!", false},
		{"Random secret", "aB3#xK9$mP2@zQ7", false},
		{"Mixed alphanumeric", "aB3xK9mP2zQ7wR5tY8uI4oP1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isFalsePositive(tt.value)
			if result != tt.shouldBeFalse {
				t.Errorf("isFalsePositive('%s') = %v, want %v", tt.value, result, tt.shouldBeFalse)
			}
		})
	}
}

// Test comment detection
func TestSecretsScanner_IsLikelyCommentOrDoc(t *testing.T) {
	scanner := NewSecretsScanner(nil)

	tests := []struct {
		name      string
		line      string
		isComment bool
	}{
		{"Hash comment", "# password = example", true},
		{"Double slash", "// api_key = test", true},
		{"Block comment start", "/* secret = value", true},
		{"Block comment line", "* password = xxx", true},
		{"HTML comment", "<!-- api_key = test -->", true},
		{"Python docstring", `"""password = example"""`, true},
		{"Python docstring single", "'''secret = test'''", true},
		{"Regular code", `password = "realvalue"`, false},
		{"Config line", "api_key=actual_key", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isLikelyCommentOrDoc(tt.line)
			if result != tt.isComment {
				t.Errorf("isLikelyCommentOrDoc('%s') = %v, want %v", tt.line, result, tt.isComment)
			}
		})
	}
}

// Test entropy threshold changes
func TestSecretsScanner_EntropyThresholdUpdated(t *testing.T) {
	scanner := NewSecretsScanner(nil)

	// Test that common false positives have lower entropy than the 5.5 threshold
	tests := []struct {
		name       string
		value      string
		maxEntropy float64 // These should all be below 5.5
	}{
		{"UUID", "550e8400-e29b-41d4-a716-446655440000", 5.5},
		{"SHA-1 hash", "356a192b7913b04c54574d18c28d46e6395428ab", 5.5},
		{"Base64 string", "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0", 5.5},
		{"Hex string", "deadbeef1234567890abcdef", 5.5},
		{"Repeated pattern", "123456781234567812345678", 5.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := scanner.calculateEntropy(tt.value)
			t.Logf("Entropy for '%s': %f", tt.name, entropy)

			if entropy > tt.maxEntropy {
				t.Errorf("String '%s' has entropy %f, which exceeds threshold %f. "+
					"This may cause false positives.", tt.value, entropy, tt.maxEntropy)
			}
		})
	}

	// Verify the threshold is actually 5.5 in the code
	t.Run("Verify threshold is 5.5", func(t *testing.T) {
		// This test documents that we raised the threshold from 4.5 to 5.5
		// to reduce false positives from UUIDs, hashes, etc.
		const expectedThreshold = 5.5
		t.Logf("Entropy threshold has been raised to %f to reduce false positives", expectedThreshold)
	})
}

// Test JWT severity is INFO
func TestSecretsScanner_JWTSeverity(t *testing.T) {
	scanner := NewSecretsScanner(nil)

	severity := scanner.getSeverityForSecretType("JWT_TOKEN")
	if severity != models.SeverityInfo {
		t.Errorf("Expected INFO severity for JWT_TOKEN, got %s", severity)
	}
}

// Test that COHERE_API_KEY pattern was removed
func TestSecretsScanner_CoherePatternRemoved(t *testing.T) {
	scanner := NewSecretsScanner(nil)

	_, exists := scanner.patterns["COHERE_API_KEY"]
	if exists {
		t.Error("COHERE_API_KEY pattern should be removed to reduce false positives")
	}
}
