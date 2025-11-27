package secrets

import (
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

// SecretsScanner detects sensitive data in Docker images
type SecretsScanner struct {
	scanner.BaseScanner
	patterns     map[string]*regexp.Regexp
	dockerClient *docker.Client
}

// NewSecretsScanner creates a new secrets scanner with modern patterns (2024)
func NewSecretsScanner(dockerClient *docker.Client) *SecretsScanner {
	s := &SecretsScanner{
		BaseScanner: scanner.NewBaseScanner(
			"secrets",
			"Advanced secrets detection in images (AWS, GCP, Azure, API keys, JWT, etc.)",
			true,
		),
		patterns:     make(map[string]*regexp.Regexp),
		dockerClient: dockerClient,
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
		"AWS_SESSION_TOKEN":     `(?i)aws(.{0,20})?session(.{0,20})?token['"]?\s*[:=]\s*['"][A-Za-z0-9+/]{100,}['"]`,

		// GCP
		"GCP_API_KEY":           `AIza[0-9A-Za-z\-_]{35}`,
		"GCP_SERVICE_ACCOUNT":   `"type":\s*"service_account"`,
		"GCP_OAUTH_TOKEN":       `ya29\.[0-9A-Za-z\-_]+`,

		// Azure
		"AZURE_CLIENT_SECRET":   `(?i)azure(.{0,20})?['"][0-9a-zA-Z~_\.-]{34}['"]`,
		"AZURE_CONNECTION_STR":  `(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey|BlobEndpoint)=`,
		"AZURE_STORAGE_KEY":     `(?i)DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/]{88}==`,

		// GitHub
		"GITHUB_TOKEN":          `ghp_[0-9a-zA-Z]{36}`,
		"GITHUB_OAUTH":          `gho_[0-9a-zA-Z]{36}`,
		"GITHUB_APP_TOKEN":      `(ghu|ghs)_[0-9a-zA-Z]{36}`,
		"GITHUB_REFRESH_TOKEN":  `ghr_[0-9a-zA-Z]{76}`,
		"GITHUB_FINE_GRAINED":   `github_pat_[0-9a-zA-Z_]{82}`,

		// GitLab
		"GITLAB_TOKEN":          `glpat-[0-9a-zA-Z\-_]{20}`,
		"GITLAB_RUNNER_TOKEN":   `glrt-[0-9a-zA-Z\-_]{20}`,
		"GITLAB_PIPELINE_TOKEN": `glptt-[0-9a-zA-Z\-_]{40}`,

		// Bitbucket
		"BITBUCKET_CLIENT_ID":     `(?i)bitbucket(.{0,20})?['"][0-9a-zA-Z]{32}['"]`,
		"BITBUCKET_CLIENT_SECRET": `(?i)bitbucket(.{0,20})?secret['"]?\s*[:=]\s*['"][0-9a-zA-Z]{64}['"]`,

		// Slack
		"SLACK_TOKEN":           `xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}`,
		"SLACK_WEBHOOK":         `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`,
		"SLACK_BOT_TOKEN":       `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`,

		// Stripe
		"STRIPE_KEY":            `(sk|pk)_(test|live)_[0-9a-zA-Z]{24,99}`,
		"STRIPE_RESTRICTED":     `rk_(test|live)_[0-9a-zA-Z]{24}`,
		"STRIPE_WEBHOOK_SECRET": `whsec_[0-9a-zA-Z]{32,}`,

		// PayPal
		"PAYPAL_CLIENT_ID":     `(?i)paypal(.{0,20})?['"][0-9a-zA-Z\-_]{80}['"]`,
		"PAYPAL_CLIENT_SECRET": `(?i)paypal(.{0,20})?secret['"]?\s*[:=]\s*['"][0-9a-zA-Z\-_]{80}['"]`,

		// Square
		"SQUARE_ACCESS_TOKEN": `sq0atp-[0-9A-Za-z\-_]{22}`,
		"SQUARE_OAUTH_SECRET": `sq0csp-[0-9A-Za-z\-_]{43}`,

		// SendGrid
		"SENDGRID_KEY":          `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`,

		// Twilio
		"TWILIO_API_KEY":        `SK[0-9a-fA-F]{32}`,
		"TWILIO_SID":            `AC[a-zA-Z0-9_\-]{32}`,
		"TWILIO_AUTH_TOKEN":     `(?i)twilio(.{0,20})?auth(.{0,20})?token['"]?\s*[:=]\s*['"][a-zA-Z0-9]{32}['"]`,

		// MailChimp
		"MAILCHIMP_KEY":         `[0-9a-f]{32}-us[0-9]{1,2}`,

		// Mailgun
		"MAILGUN_API_KEY":       `key-[0-9a-zA-Z]{32}`,

		// OpenAI
		"OPENAI_API_KEY":        `sk-[A-Za-z0-9]{48}`,
		"OPENAI_ORG_KEY":        `sk-org-[A-Za-z0-9]{48}`,

		// Anthropic
		"ANTHROPIC_KEY":         `sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{95}`,

		// Hugging Face
		"HUGGINGFACE_TOKEN":     `hf_[A-Za-z0-9]{34}`,

		// Cohere
		"COHERE_API_KEY":        `[a-zA-Z0-9]{40}`,

		// JWT
		"JWT_TOKEN":             `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`,

		// OAuth
		"OAUTH_ACCESS_TOKEN":    `(?i)oauth(.{0,20})?token['"]?\s*[:=]\s*['"][a-zA-Z0-9\-_]{20,}['"]`,
		"BEARER_TOKEN":          `(?i)bearer\s+[a-zA-Z0-9\-_\.=]+`,

		// Private Keys
		"RSA_PRIVATE_KEY":       `-----BEGIN RSA PRIVATE KEY-----`,
		"OPENSSH_PRIVATE_KEY":   `-----BEGIN OPENSSH PRIVATE KEY-----`,
		"DSA_PRIVATE_KEY":       `-----BEGIN DSA PRIVATE KEY-----`,
		"EC_PRIVATE_KEY":        `-----BEGIN EC PRIVATE KEY-----`,
		"PGP_PRIVATE_KEY":       `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		"PRIVATE_KEY":           `-----BEGIN PRIVATE KEY-----`,
		"ENCRYPTED_PRIVATE_KEY": `-----BEGIN ENCRYPTED PRIVATE KEY-----`,

		// Certificates
		"CERTIFICATE":           `-----BEGIN CERTIFICATE-----`,
		"CERTIFICATE_REQUEST":   `-----BEGIN CERTIFICATE REQUEST-----`,

		// Database URLs
		"POSTGRES_URL":          `postgresql://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+/[a-zA-Z0-9_\-]+`,
		"MYSQL_URL":             `mysql://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+/[a-zA-Z0-9_\-]+`,
		"MONGODB_URL":           `mongodb(\+srv)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-\,]+`,
		"REDIS_URL":             `redis://[a-zA-Z0-9_\-]*:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+`,
		"SQLSERVER_URL":         `mssql://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+:[0-9]+`,

		// Docker
		"DOCKER_AUTH":           `"auth"\s*:\s*"[A-Za-z0-9+/=]+"`,
		"DOCKER_CONFIG":         `"auths"\s*:\s*\{`,

		// Heroku
		"HEROKU_API_KEY":        `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,

		// NPM
		"NPM_TOKEN":             `npm_[a-zA-Z0-9]{36}`,

		// PyPI
		"PYPI_TOKEN":            `pypi-[A-Za-z0-9\-_]{84,}`,

		// Generic Password Patterns
		"PASSWORD_IN_URL":       `[a-zA-Z]{3,10}://[^:\/\s]+:[^@\/\s]+@`,
		"PASSWORD_ASSIGNMENT":   `(?i)(password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|private_key)\s*[=:]\s*['"][^'"]{8,}['"]`,
		"API_KEY_ASSIGNMENT":    `(?i)api[_\-]?key\s*[=:]\s*['"][a-zA-Z0-9\-_]{16,}['"]`,
		"SECRET_KEY_ASSIGNMENT": `(?i)secret[_\-]?key\s*[=:]\s*['"][a-zA-Z0-9\-_]{16,}['"]`,
	}

	for name, pattern := range patterns {
		s.patterns[name] = regexp.MustCompile(pattern)
	}
}

// Scan performs secrets detection
func (s *SecretsScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	if s.dockerClient == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	// Scan environment variables (non-fatal if fails)
	envFindings, err := s.scanEnvironmentVars(ctx, target)
	if err == nil {
		findings = append(findings, envFindings...)
	}

	// Scan file contents (non-fatal if fails)
	fileFindings, err := s.scanFileContents(ctx, target)
	if err == nil {
		findings = append(findings, fileFindings...)
	}

	// Scan for high-entropy strings in specific files (non-fatal if fails)
	entropyFindings, err := s.scanHighEntropyStrings(ctx, target)
	if err == nil {
		findings = append(findings, entropyFindings...)
	}

	return findings, nil
}

func (s *SecretsScanner) scanEnvironmentVars(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Get image information
	imageInfo, err := s.dockerClient.InspectImage(ctx, target.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	// Check each environment variable
	for key, value := range imageInfo.Env {
		envString := fmt.Sprintf("%s=%s", key, value)

		// Check against all patterns
		for secretType, pattern := range s.patterns {
			if pattern.MatchString(envString) || pattern.MatchString(value) {
				match := pattern.FindString(envString)
				if match == "" {
					match = pattern.FindString(value)
				}

				finding := models.Finding{
					ID:          fmt.Sprintf("SECRET-%s", secretType),
					Title:       fmt.Sprintf("Sensitive data detected: %s", secretType),
					Description: fmt.Sprintf("Found potential %s in environment variable '%s'. Storing secrets in environment variables is insecure and violates security best practices. Secrets in environment variables can be exposed through process listings, container inspection, and logs.", secretType, key),
					Severity:    s.getSeverityForSecretType(secretType),
					Category:    "Secrets",
					Source:      "secrets",
					Remediation: "Use secrets management systems like Docker Secrets, Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager, or environment-specific secret stores. Never commit secrets to images or hardcode them in environment variables. Consider using runtime secret injection or external secret management services.",
					References: []string{
						"https://docs.docker.com/engine/swarm/secrets/",
						"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
						"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
					},
					Location: &models.Location{
						Component: "environment_variables",
					},
					Metadata: map[string]interface{}{
						"secret_type":      secretType,
						"env_var_name":     key,
						"match":            s.redactSecret(match),
						"entropy":          s.calculateEntropy(match),
						"detection_method": "pattern_match",
					},
				}

				findings = append(findings, finding)
				// Only report first match per environment variable
				break
			}
		}

		// Check for high-entropy values that might be secrets
		if len(value) > 16 && s.calculateEntropy(value) > 4.5 {
			// Skip if it looks like a path or common non-secret pattern
			if !strings.Contains(value, "/") && !strings.Contains(value, "\\") {
				finding := models.Finding{
					ID:          "SECRET-HIGH-ENTROPY",
					Title:       "High-entropy string detected in environment variable",
					Description: fmt.Sprintf("Environment variable '%s' contains a high-entropy string (entropy: %.2f), which may indicate a secret or encrypted data. High entropy often suggests random or encrypted data such as API keys, tokens, or passwords.", key, s.calculateEntropy(value)),
					Severity:    models.SeverityMedium,
					Category:    "Secrets",
					Source:      "secrets",
					Remediation: "Review this environment variable. If it contains sensitive data, use proper secrets management. Remove secrets from the image and inject them at runtime.",
					References: []string{
						"https://docs.docker.com/engine/swarm/secrets/",
						"https://en.wikipedia.org/wiki/Entropy_(information_theory)",
					},
					Location: &models.Location{
						Component: "environment_variables",
					},
					Metadata: map[string]interface{}{
						"env_var_name":     key,
						"entropy":          s.calculateEntropy(value),
						"value_length":     len(value),
						"match":            s.redactSecret(value),
						"detection_method": "entropy_analysis",
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func (s *SecretsScanner) scanFileContents(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Maximum file size to scan (10MB)
	const maxFileSize = 10 * 1024 * 1024
	// Maximum number of matches to prevent memory exhaustion
	const maxMatches = 10000

	// Search for patterns in file contents
	matches, err := s.dockerClient.SearchFileContent(ctx, target.ImageName, s.patterns, maxFileSize, maxMatches)
	if err != nil {
		return nil, fmt.Errorf("failed to search file content: %w", err)
	}

	// Convert matches to findings
	for _, match := range matches {
		finding := models.Finding{
			ID:          fmt.Sprintf("SECRET-%s", match.PatternName),
			Title:       fmt.Sprintf("Sensitive data detected in file: %s", match.PatternName),
			Description: fmt.Sprintf("Found potential %s in file. Secrets should never be stored in container images as they can be extracted by anyone with access to the image. This is a critical security vulnerability that can lead to unauthorized access and data breaches.", match.PatternName),
			Severity:    s.getSeverityForSecretType(match.PatternName),
			Category:    "Secrets",
			Source:      "secrets",
			Remediation: "Remove all secrets from the image. Use Docker Secrets, Kubernetes Secrets, or mount secrets at runtime. Consider using tools like git-secrets or pre-commit hooks to prevent accidental secret commits. Rotate any exposed secrets immediately.",
			References: []string{
				"https://docs.docker.com/engine/swarm/secrets/",
				"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
				"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
			},
			Location: &models.Location{
				File: match.FilePath,
				Line: match.LineNumber,
			},
			Metadata: map[string]interface{}{
				"secret_type":      match.PatternName,
				"match":            s.redactSecret(match.Match),
				"entropy":          s.calculateEntropy(match.Match),
				"detection_method": "pattern_match",
			},
		}
		findings = append(findings, finding)
	}

	// Scan for common secret files
	secretFiles := []string{
		".env",
		".env.local",
		".env.production",
		".env.development",
		".aws/credentials",
		".aws/config",
		".ssh/id_rsa",
		".ssh/id_dsa",
		".ssh/id_ecdsa",
		".ssh/id_ed25519",
		"config/secrets.yml",
		"config/secrets.yaml",
		".docker/config.json",
		".npmrc",
		".pypirc",
		".netrc",
		".git-credentials",
		"credentials.json",
		"service-account.json",
		"gcloud-service-key.json",
		"secrets.json",
		"private.key",
		"private.pem",
		"cert.key",
		"server.key",
		".pgpass",
		".my.cnf",
		"wp-config.php",
		"settings.php",
		"config.php",
	}

	err = s.dockerClient.ScanImageFiles(ctx, target.ImageName, func(info docker.FileInfo, reader io.Reader) error {
		// Check if this is a known secret file
		for _, secretFile := range secretFiles {
			if strings.HasSuffix(info.Path, secretFile) || strings.Contains(info.Path, "/"+secretFile) {
				finding := models.Finding{
					ID:          "SECRET-FILE",
					Title:       fmt.Sprintf("Sensitive file detected: %s", secretFile),
					Description: fmt.Sprintf("File '%s' typically contains sensitive data and should not be included in Docker images. These files often contain credentials, API keys, or other secrets that should be managed separately from the container image.", info.Path),
					Severity:    models.SeverityHigh,
					Category:    "Secrets",
					Source:      "secrets",
					Remediation: "Remove sensitive files from the image. Use .dockerignore to prevent accidental inclusion. Mount secrets at runtime using Docker Secrets, Kubernetes Secrets, or volume mounts. Ensure secrets are not committed to version control.",
					References: []string{
						"https://docs.docker.com/engine/reference/builder/#dockerignore-file",
						"https://docs.docker.com/engine/swarm/secrets/",
					},
					Location: &models.Location{
						File: info.Path,
					},
					Metadata: map[string]interface{}{
						"file_size":        info.Size,
						"file_mode":        info.Mode.String(),
						"detection_method": "known_secret_file",
					},
				}
				findings = append(findings, finding)
				break
			}
		}
		return nil
	})

	if err != nil {
		return findings, fmt.Errorf("failed to scan files: %w", err)
	}

	return findings, nil
}

func (s *SecretsScanner) scanHighEntropyStrings(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Entropy threshold for detecting potential secrets
	const entropyThreshold = 4.5
	const minLength = 20
	const maxLength = 200

	// Pattern to find potential secret-like strings
	// Look for alphanumeric strings that might be keys
	highEntropyPattern := regexp.MustCompile(`[A-Za-z0-9\-_\+/=]{20,200}`)
	patterns := map[string]*regexp.Regexp{
		"HIGH_ENTROPY": highEntropyPattern,
	}

	const maxFileSize = 5 * 1024 * 1024 // 5MB for entropy scanning
	const maxMatches = 10000             // Limit matches to prevent memory exhaustion

	matches, err := s.dockerClient.SearchFileContent(ctx, target.ImageName, patterns, maxFileSize, maxMatches)
	if err != nil {
		return nil, fmt.Errorf("failed to search for high entropy strings: %w", err)
	}

	// Track to avoid duplicates
	seen := make(map[string]bool)

	for _, match := range matches {
		// Skip if too short or too long
		if len(match.Match) < minLength || len(match.Match) > maxLength {
			continue
		}

		entropy := s.calculateEntropy(match.Match)
		if entropy > entropyThreshold {
			// Skip if we've seen this match before
			key := fmt.Sprintf("%s:%d", match.FilePath, match.LineNumber)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Skip if it's already detected by other patterns
			isKnownPattern := false
			for patternName, pattern := range s.patterns {
				if patternName != "HIGH_ENTROPY" && pattern.MatchString(match.Match) {
					isKnownPattern = true
					break
				}
			}
			if isKnownPattern {
				continue
			}

			finding := models.Finding{
				ID:          "SECRET-HIGH-ENTROPY-FILE",
				Title:       "High-entropy string detected in file",
				Description: fmt.Sprintf("Detected a string with high Shannon entropy (%.2f) in file, which may indicate encrypted data, API keys, tokens, or other secrets. Entropy values above %.1f typically suggest non-natural text patterns common in cryptographic material.", entropy, entropyThreshold),
				Severity:    models.SeverityMedium,
				Category:    "Secrets",
				Source:      "secrets",
				Remediation: "Review this string to determine if it contains sensitive data. If it's a secret, remove it from the image and use proper secrets management. Consider using environment-specific secret injection or external secret management services.",
				References: []string{
					"https://en.wikipedia.org/wiki/Entropy_(information_theory)",
					"https://docs.docker.com/engine/swarm/secrets/",
				},
				Location: &models.Location{
					File: match.FilePath,
					Line: match.LineNumber,
				},
				Metadata: map[string]interface{}{
					"entropy":          entropy,
					"string_length":    len(match.Match),
					"match":            s.redactSecret(match.Match),
					"detection_method": "entropy_analysis",
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
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
	// Critical severity for cloud credentials and private keys
	criticalTypes := map[string]bool{
		"AWS_ACCESS_KEY":          true,
		"AWS_SECRET_KEY":          true,
		"AWS_SESSION_TOKEN":       true,
		"RSA_PRIVATE_KEY":         true,
		"OPENSSH_PRIVATE_KEY":     true,
		"DSA_PRIVATE_KEY":         true,
		"EC_PRIVATE_KEY":          true,
		"PGP_PRIVATE_KEY":         true,
		"PRIVATE_KEY":             true,
		"ENCRYPTED_PRIVATE_KEY":   true,
		"GCP_SERVICE_ACCOUNT":     true,
		"GCP_OAUTH_TOKEN":         true,
		"AZURE_CLIENT_SECRET":     true,
		"AZURE_CONNECTION_STR":    true,
		"AZURE_STORAGE_KEY":       true,
	}

	// High severity for tokens and API keys
	highTypes := map[string]bool{
		"GITHUB_TOKEN":            true,
		"GITHUB_OAUTH":            true,
		"GITHUB_APP_TOKEN":        true,
		"GITHUB_REFRESH_TOKEN":    true,
		"GITHUB_FINE_GRAINED":     true,
		"GITLAB_TOKEN":            true,
		"STRIPE_KEY":              true,
		"OPENAI_API_KEY":          true,
		"OPENAI_ORG_KEY":          true,
		"ANTHROPIC_KEY":           true,
		"HUGGINGFACE_TOKEN":       true,
		"SLACK_TOKEN":             true,
		"SLACK_BOT_TOKEN":         true,
		"SENDGRID_KEY":            true,
		"TWILIO_API_KEY":          true,
		"TWILIO_AUTH_TOKEN":       true,
		"PAYPAL_CLIENT_ID":        true,
		"PAYPAL_CLIENT_SECRET":    true,
		"SQUARE_ACCESS_TOKEN":     true,
		"SQUARE_OAUTH_SECRET":     true,
		"NPM_TOKEN":               true,
		"PYPI_TOKEN":              true,
		"POSTGRES_URL":            true,
		"MYSQL_URL":               true,
		"MONGODB_URL":             true,
		"DOCKER_AUTH":             true,
	}

	if criticalTypes[secretType] {
		return models.SeverityCritical
	}

	if highTypes[secretType] {
		return models.SeverityHigh
	}

	// Medium for other patterns
	return models.SeverityMedium
}

func (s *SecretsScanner) redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***REDACTED***"
	}
	// Show first and last 4 characters
	return secret[:4] + "***REDACTED***" + secret[len(secret)-4:]
}
