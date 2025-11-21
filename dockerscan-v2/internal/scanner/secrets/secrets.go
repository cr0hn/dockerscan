package secrets

import (
	"context"
	"fmt"
	"math"
	"regexp"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
)

// SecretsScanner detects sensitive data in Docker images
type SecretsScanner struct {
	scanner.BaseScanner
	patterns map[string]*regexp.Regexp
}

// NewSecretsScanner creates a new secrets scanner with modern patterns (2024)
func NewSecretsScanner() *SecretsScanner {
	s := &SecretsScanner{
		BaseScanner: scanner.NewBaseScanner(
			"secrets",
			"Advanced secrets detection in images (AWS, GCP, Azure, API keys, JWT, etc.)",
			true,
		),
		patterns: make(map[string]*regexp.Regexp),
	}

	s.initializePatterns()
	return s
}

func (s *SecretsScanner) initializePatterns() {
	patterns := map[string]string{
		// AWS
		"AWS_ACCESS_KEY":        `AKIA[0-9A-Z]{16}`,
		"AWS_SECRET_KEY":        `(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`,
		"AWS_MWS_KEY":           `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,

		// GCP
		"GCP_API_KEY":           `AIza[0-9A-Za-z\-_]{35}`,
		"GCP_SERVICE_ACCOUNT":   `"type": "service_account"`,

		// Azure
		"AZURE_CLIENT_SECRET":   `[a-zA-Z0-9~_\.-]{34}`,

		// GitHub
		"GITHUB_TOKEN":          `ghp_[0-9a-zA-Z]{36}`,
		"GITHUB_OAUTH":          `gho_[0-9a-zA-Z]{36}`,
		"GITHUB_APP_TOKEN":      `(ghu|ghs)_[0-9a-zA-Z]{36}`,
		"GITHUB_REFRESH_TOKEN":  `ghr_[0-9a-zA-Z]{76}`,

		// GitLab
		"GITLAB_TOKEN":          `glpat-[0-9a-zA-Z\-_]{20}`,

		// Slack
		"SLACK_TOKEN":           `xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}`,
		"SLACK_WEBHOOK":         `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`,

		// Stripe
		"STRIPE_KEY":            `(sk|pk)_(test|live)_[0-9a-zA-Z]{24,99}`,
		"STRIPE_RESTRICTED":     `rk_(test|live)_[0-9a-zA-Z]{24}`,

		// SendGrid
		"SENDGRID_KEY":          `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`,

		// Twilio
		"TWILIO_API_KEY":        `SK[0-9a-fA-F]{32}`,
		"TWILIO_SID":            `AC[a-zA-Z0-9_\-]{32}`,

		// MailChimp
		"MAILCHIMP_KEY":         `[0-9a-f]{32}-us[0-9]{1,2}`,

		// OpenAI
		"OPENAI_API_KEY":        `sk-[A-Za-z0-9]{48}`,

		// Anthropic
		"ANTHROPIC_KEY":         `sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{95}`,

		// JWT
		"JWT_TOKEN":             `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`,

		// Private Keys
		"RSA_PRIVATE_KEY":       `-----BEGIN RSA PRIVATE KEY-----`,
		"OPENSSH_PRIVATE_KEY":   `-----BEGIN OPENSSH PRIVATE KEY-----`,
		"DSA_PRIVATE_KEY":       `-----BEGIN DSA PRIVATE KEY-----`,
		"EC_PRIVATE_KEY":        `-----BEGIN EC PRIVATE KEY-----`,
		"PGP_PRIVATE_KEY":       `-----BEGIN PGP PRIVATE KEY BLOCK-----`,

		// Certificates
		"CERTIFICATE":           `-----BEGIN CERTIFICATE-----`,

		// Database URLs
		"POSTGRES_URL":          `postgresql://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\.\-]+:[0-9]+/[a-zA-Z0-9_]+`,
		"MYSQL_URL":             `mysql://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\.\-]+:[0-9]+/[a-zA-Z0-9_]+`,
		"MONGODB_URL":           `mongodb(\+srv)?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\.\-]+`,

		// Docker
		"DOCKER_AUTH":           `"auth"\s*:\s*"[A-Za-z0-9+/=]+"`,

		// Generic Password Patterns
		"PASSWORD_IN_URL":       `[a-zA-Z]{3,10}://[^:]+:[^@]+@`,
		"PASSWORD_ASSIGNMENT":   `(?i)(password|passwd|pwd|secret|api_key|apikey|access_token)\s*[=:]\s*['"][^'"]{8,}['"]`,
	}

	for name, pattern := range patterns {
		s.patterns[name] = regexp.MustCompile(pattern)
	}
}

// Scan performs secrets detection
func (s *SecretsScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// In a real implementation, this would:
	// 1. Extract all layers from the image
	// 2. Scan files in each layer
	// 3. Scan environment variables
	// 4. Scan image history/metadata

	// For demonstration, let's create some example findings
	findings = append(findings, s.scanEnvironmentVars(target)...)
	findings = append(findings, s.scanImageLayers(target)...)

	return findings, nil
}

func (s *SecretsScanner) scanEnvironmentVars(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// This would scan actual environment variables from image metadata
	// Placeholder example
	envVars := []string{
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"DATABASE_URL=postgresql://user:password123@localhost:5432/mydb",
		"API_TOKEN=sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567",
	}

	for _, env := range envVars {
		for secretType, pattern := range s.patterns {
			if pattern.MatchString(env) {
				match := pattern.FindString(env)

				finding := models.Finding{
					ID:          fmt.Sprintf("SECRET-%s", secretType),
					Title:       fmt.Sprintf("Sensitive data detected: %s", secretType),
					Description: fmt.Sprintf("Found potential %s in environment variable. Storing secrets in environment variables is insecure and violates security best practices.", secretType),
					Severity:    s.getSeverityForSecretType(secretType),
					Category:    "Secrets",
					Source:      "secrets",
					Remediation: "Use secrets management systems like Docker Secrets, Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager, or environment-specific secret stores. Never commit secrets to images.",
					References: []string{
						"https://docs.docker.com/engine/swarm/secrets/",
						"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
					},
					Location: &models.Location{
						Component: "environment_variables",
					},
					Metadata: map[string]interface{}{
						"secret_type": secretType,
						"match":       s.redactSecret(match),
						"entropy":     s.calculateEntropy(match),
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (s *SecretsScanner) scanImageLayers(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// This would scan actual layer contents
	// Placeholder example showing detection in common files
	commonSecretFiles := []string{
		".env",
		".aws/credentials",
		".ssh/id_rsa",
		"config/secrets.yml",
		".docker/config.json",
	}

	for _, file := range commonSecretFiles {
		finding := models.Finding{
			ID:          "SECRET-FILE",
			Title:       fmt.Sprintf("Sensitive file detected: %s", file),
			Description: fmt.Sprintf("File '%s' typically contains sensitive data and should not be included in Docker images.", file),
			Severity:    models.SeverityHigh,
			Category:    "Secrets",
			Source:      "secrets",
			Remediation: "Remove sensitive files from the image. Use .dockerignore to prevent accidental inclusion. Mount secrets at runtime instead.",
			Location: &models.Location{
				File: file,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// calculateEntropy calculates Shannon entropy to detect high-entropy strings
// High entropy (> 4.5) often indicates encrypted data or secrets
func (s *SecretsScanner) calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count character frequencies
	frequencies := make(map[rune]int)
	for _, char := range data {
		frequencies[char]++
	}

	// Calculate Shannon entropy
	var entropy float64
	length := float64(len(data))

	for _, count := range frequencies {
		freq := float64(count) / length
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

func (s *SecretsScanner) getSeverityForSecretType(secretType string) models.Severity {
	highSeverityTypes := map[string]bool{
		"AWS_ACCESS_KEY":      true,
		"AWS_SECRET_KEY":      true,
		"RSA_PRIVATE_KEY":     true,
		"OPENSSH_PRIVATE_KEY": true,
		"GCP_SERVICE_ACCOUNT": true,
		"AZURE_CLIENT_SECRET": true,
	}

	if highSeverityTypes[secretType] {
		return models.SeverityCritical
	}

	return models.SeverityHigh
}

func (s *SecretsScanner) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***REDACTED***"
	}
	// Show first and last 4 characters
	return secret[:4] + "***REDACTED***" + secret[len(secret)-4:]
}
