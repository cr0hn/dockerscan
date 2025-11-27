package supplychain

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

// SupplyChainScanner detects supply chain attacks based on 2024 research
type SupplyChainScanner struct {
	scanner.BaseScanner
	dockerClient *docker.Client
}

// NewSupplyChainScanner creates a new supply chain security scanner
func NewSupplyChainScanner(dockerClient *docker.Client) *SupplyChainScanner {
	return &SupplyChainScanner{
		BaseScanner: scanner.NewBaseScanner(
			"supply-chain",
			"Supply chain attack detection (imageless containers, backdoors, crypto miners, unsigned images)",
			true,
		),
		dockerClient: dockerClient,
	}
}

// Scan performs supply chain security checks
func (s *SupplyChainScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Based on 2024 research: 4M+ malicious imageless containers found
	imagelessFindings, err := s.detectImagelessContainers(ctx, target)
	if err == nil {
		findings = append(findings, imagelessFindings...)
	}
	// Non-fatal, continue even if imageless detection fails

	// Detect cryptocurrency miners (120K+ pulls in 2024)
	minerFindings, err := s.detectCryptoMiners(ctx, target)
	if err != nil {
		// Non-fatal, log and continue
		minerFindings = []models.Finding{}
	}
	findings = append(findings, minerFindings...)

	// Check for backdoored libraries (xz-utils case March 2024)
	backdoorFindings, err := s.detectBackdoorLibraries(ctx, target)
	if err != nil {
		// Non-fatal, continue
		backdoorFindings = []models.Finding{}
	}
	findings = append(findings, backdoorFindings...)

	// Verify image signatures (Notary/Cosign)
	signatureFindings, err := s.verifyImageSignature(ctx, target)
	if err != nil {
		// Non-fatal, continue
		signatureFindings = []models.Finding{}
	}
	findings = append(findings, signatureFindings...)

	// Check for suspicious outbound connections
	connectionFindings, err := s.detectSuspiciousConnections(ctx, target)
	if err != nil {
		// Non-fatal, continue
		connectionFindings = []models.Finding{}
	}
	findings = append(findings, connectionFindings...)

	// Detect phishing content in Dockerfiles/README
	phishingFindings, err := s.scanPhishingContent(ctx, target)
	if err != nil {
		// Non-fatal, continue
		phishingFindings = []models.Finding{}
	}
	findings = append(findings, phishingFindings...)

	return findings, nil
}

// detectImagelessContainers checks for malicious imageless containers
// Based on research: 4M+ repositories in Docker Hub are imageless with malicious documentation
func (s *SupplyChainScanner) detectImagelessContainers(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Get image info to check layer count
	imageInfo, err := s.dockerClient.InspectImage(ctx, target.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	// Check if image has actual layers
	hasLayers := imageInfo.LayerCount > 0 && len(imageInfo.RootFS.Layers) > 0

	// If no layers, this is highly suspicious
	if !hasLayers {
		finding := models.Finding{
			ID:          "SUPPLY-CHAIN-001",
			Title:       "Imageless container detected (CRITICAL)",
			Description: "This container has no actual filesystem layers but may contain malicious documentation. This pattern was used in 4M+ malicious containers on Docker Hub to redirect users to phishing/malware sites.",
			Severity:    models.SeverityCritical,
			Category:    "Supply-Chain",
			Source:      "supply-chain",
			Remediation: "Do not use this image. Verify the source and check if this is the official repository. Report to Docker Hub if malicious.",
			References: []string{
				"https://thehackernews.com/2024/04/millions-of-malicious-imageless.html",
			},
			Metadata: map[string]interface{}{
				"attack_type": "imageless_container",
				"layer_count": imageInfo.LayerCount,
			},
		}
		findings = append(findings, finding)
	}

	// Warn even if very few layers (1-2 layers is suspicious for application images)
	if hasLayers && imageInfo.LayerCount <= 2 {
		finding := models.Finding{
			ID:          "SUPPLY-CHAIN-008",
			Title:       "Suspiciously minimal layer count",
			Description: fmt.Sprintf("Image has only %d layer(s), which is unusual for application containers. This may indicate an imageless attack or skeleton image.", imageInfo.LayerCount),
			Severity:    models.SeverityHigh,
			Category:    "Supply-Chain",
			Source:      "supply-chain",
			Remediation: "Verify this is a legitimate minimal image (like scratch or distroless). Inspect the image contents carefully.",
			Metadata: map[string]interface{}{
				"layer_count": imageInfo.LayerCount,
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// detectCryptoMiners identifies cryptocurrency mining malware
func (s *SupplyChainScanner) detectCryptoMiners(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Known mining pool domains and patterns to search for
	minerPatterns := map[string]*regexp.Regexp{
		"xmrig_binary":       regexp.MustCompile(`(?i)(xmrig|xmr-stak|xmr-node-proxy)`),
		"claymore":           regexp.MustCompile(`(?i)(claymore|ethman|ethdcrminer)`),
		"mining_pool":        regexp.MustCompile(`(?i)(stratum\+tcp|stratum\+ssl|pool\.):\/\/`),
		"monero_wallet":      regexp.MustCompile(`(?i)(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})`), // Monero address pattern
		"mining_config":      regexp.MustCompile(`(?i)(pool\.supportxmr\.com|xmr-eu\.dwarfpool\.com|pool\.minexmr\.com)`),
		"mining_pool_ports":  regexp.MustCompile(`:(?:3333|4444|5555|14444|14433|3357)\b`), // Common mining ports
		"crypto_miner_cmd":   regexp.MustCompile(`(?i)(minerd|cpuminer|ccminer|ethminer|cgminer|bfgminer)`),
	}

	// Search for patterns in all files
	const maxFileSize = 10 * 1024 * 1024 // Max 10MB per file
	const maxMatches = 10000             // Limit matches to prevent memory exhaustion
	matches, err := s.dockerClient.SearchFileContent(ctx, target.ImageName, minerPatterns, maxFileSize, maxMatches)
	if err != nil {
		return findings, err
	}

	// Track unique findings
	foundIndicators := make(map[string]bool)

	for _, match := range matches {
		key := fmt.Sprintf("%s:%s", match.PatternName, match.FilePath)
		if foundIndicators[key] {
			continue
		}
		foundIndicators[key] = true

		finding := models.Finding{
			ID:          "SUPPLY-CHAIN-002",
			Title:       "Cryptocurrency miner indicator detected",
			Description: fmt.Sprintf("Found cryptocurrency mining indicator '%s' in %s. Malicious actors inject crypto miners into container images to abuse compute resources.", match.PatternName, match.FilePath),
			Severity:    models.SeverityCritical,
			Category:    "Supply-Chain",
			Source:      "supply-chain",
			Remediation: "Do not use this image. It contains cryptocurrency mining malware. Report to the registry operator.",
			References: []string{
				"https://www.aquasec.com/blog/supply-chain-threats-using-container-images/",
			},
			Location: &models.Location{
				File: match.FilePath,
				Line: match.LineNumber,
			},
			Metadata: map[string]interface{}{
				"pattern":  match.PatternName,
				"match":    match.Match,
				"type":     "crypto_miner",
			},
		}
		findings = append(findings, finding)
	}

	// Also check for known miner binaries by filename
	minerBinaries := []string{
		"xmrig", "xmr-stak", "xmr-node-proxy",
		"claymore", "ethminer", "ethman",
		"minerd", "cpuminer", "ccminer",
		"cgminer", "bfgminer",
	}

	err = s.dockerClient.ScanImageFiles(ctx, target.ImageName, func(info docker.FileInfo, reader io.Reader) error {
		if info.IsDir {
			return nil
		}

		basename := filepath.Base(info.Path)
		baseLower := strings.ToLower(basename)

		for _, minerBin := range minerBinaries {
			if baseLower == minerBin || strings.Contains(baseLower, minerBin) {
				// Check if executable
				if info.Mode&0111 != 0 { // Has execute permission
					finding := models.Finding{
						ID:          "SUPPLY-CHAIN-003",
						Title:       fmt.Sprintf("Mining binary detected: %s", basename),
						Description: "Found cryptocurrency mining executable in image. This is highly suspicious and indicates a supply chain compromise.",
						Severity:    models.SeverityCritical,
						Category:    "Supply-Chain",
						Source:      "supply-chain",
						Remediation: "Remove this image immediately. Investigate how it entered your registry.",
						Location: &models.Location{
							File: info.Path,
						},
						Metadata: map[string]interface{}{
							"binary": basename,
							"mode":   info.Mode.String(),
						},
					}
					findings = append(findings, finding)
				}
			}
		}
		return nil
	})

	return findings, err
}

// detectBackdoorLibraries checks for known backdoored libraries
func (s *SupplyChainScanner) detectBackdoorLibraries(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Get installed packages
	packages, err := s.dockerClient.ListPackages(ctx, target.ImageName)
	if err != nil {
		// If we can't list packages, that's OK - may not be a standard distro
		return findings, nil
	}

	// Known backdoored libraries (based on 2024 incidents)
	suspiciousLibraries := map[string][]string{
		"xz-utils": {"5.6.0", "5.6.1"}, // Backdoored versions from March 2024
		"liblzma5": {"5.6.0", "5.6.1"},
		"xz":       {"5.6.0", "5.6.1"},
		"liblzma":  {"5.6.0", "5.6.1"},
	}

	for _, pkg := range packages {
		if versions, exists := suspiciousLibraries[pkg.Name]; exists {
			// Check if version matches any backdoored version
			for _, badVersion := range versions {
				// Check for exact match or version starting with the bad version
				if pkg.Version == badVersion || strings.HasPrefix(pkg.Version, badVersion) {
					finding := models.Finding{
						ID:          "SUPPLY-CHAIN-004",
						Title:       fmt.Sprintf("Backdoored library detected: %s %s", pkg.Name, pkg.Version),
						Description: fmt.Sprintf("Found %s version %s which is known to contain a sophisticated backdoor inserted in March 2024. This backdoor (CVE-2024-3094) allowed SSH authentication bypass and infiltrated multiple Linux distributions.", pkg.Name, pkg.Version),
						Severity:    models.SeverityCritical,
						Category:    "Supply-Chain",
						Source:      "supply-chain",
						Remediation: fmt.Sprintf("Rebuild image with safe version of %s (use 5.4.x or 5.5.x). Update base image to latest security patches.", pkg.Name),
						References: []string{
							"https://www.openwall.com/lists/oss-security/2024/03/29/4",
							"https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
						},
						Metadata: map[string]interface{}{
							"package":          pkg.Name,
							"affected_version": pkg.Version,
							"package_source":   pkg.Source,
							"cve":              "CVE-2024-3094",
						},
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	// Additional check: warn about outdated xz-utils even if not the exact backdoored version
	for _, pkg := range packages {
		if strings.Contains(pkg.Name, "xz") || strings.Contains(pkg.Name, "liblzma") {
			// Parse version to check if old
			if strings.HasPrefix(pkg.Version, "5.2") || strings.HasPrefix(pkg.Version, "5.3") {
				finding := models.Finding{
					ID:          "SUPPLY-CHAIN-009",
					Title:       fmt.Sprintf("Outdated compression library: %s %s", pkg.Name, pkg.Version),
					Description: fmt.Sprintf("Found outdated version of %s (%s). Given the March 2024 xz-utils backdoor incident, it's critical to keep compression libraries up-to-date.", pkg.Name, pkg.Version),
					Severity:    models.SeverityMedium,
					Category:    "Supply-Chain",
					Source:      "supply-chain",
					Remediation: "Update to a recent, verified safe version of xz-utils (5.4.x or 5.5.x recommended).",
					Metadata: map[string]interface{}{
						"package": pkg.Name,
						"version": pkg.Version,
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// verifyImageSignature checks if image is signed with Notary/Cosign
func (s *SupplyChainScanner) verifyImageSignature(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Verify image signature using Docker client
	isSigned, digest, err := s.dockerClient.VerifyImageSignature(ctx, target.ImageName)
	if err != nil {
		// Error checking signature - report as unsigned
		finding := models.Finding{
			ID:          "SUPPLY-CHAIN-005",
			Title:       "Unable to verify image signature",
			Description: fmt.Sprintf("Failed to verify image signature: %v. This may indicate the image is not signed or signature verification is not configured.", err),
			Severity:    models.SeverityHigh,
			Category:    "Supply-Chain",
			Source:      "supply-chain",
			Remediation: "Enable Docker Content Trust or use Cosign to sign images. Use 'DOCKER_CONTENT_TRUST=1' to enforce signature verification.",
			References: []string{
				"https://docs.docker.com/engine/security/trust/",
				"https://github.com/sigstore/cosign",
			},
			Metadata: map[string]interface{}{
				"error": err.Error(),
			},
		}
		findings = append(findings, finding)
		return findings, nil
	}

	if !isSigned {
		finding := models.Finding{
			ID:          "SUPPLY-CHAIN-005",
			Title:       "Image is not digitally signed",
			Description: "This image does not have a digital signature or content digest. Unsigned images cannot be verified for authenticity and may have been tampered with. Supply chain attacks often target unsigned images.",
			Severity:    models.SeverityHigh,
			Category:    "Supply-Chain",
			Source:      "supply-chain",
			Remediation: "Enable Docker Content Trust or use Cosign to sign images. Use 'DOCKER_CONTENT_TRUST=1' to enforce signature verification. For production, only use signed images from trusted sources.",
			References: []string{
				"https://docs.docker.com/engine/security/trust/",
				"https://github.com/sigstore/cosign",
			},
			Metadata: map[string]interface{}{
				"signed": false,
			},
		}
		findings = append(findings, finding)
	} else {
		// Image is signed - good! But report as info
		finding := models.Finding{
			ID:          "SUPPLY-CHAIN-010",
			Title:       "Image signature verified",
			Description: fmt.Sprintf("Image has a valid content digest: %s. This provides supply chain integrity verification.", digest),
			Severity:    models.SeverityInfo,
			Category:    "Supply-Chain",
			Source:      "supply-chain",
			Metadata: map[string]interface{}{
				"signed": true,
				"digest": digest,
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// detectSuspiciousConnections identifies malicious network behavior
func (s *SupplyChainScanner) detectSuspiciousConnections(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Patterns for suspicious domains and IPs
	suspiciousPatterns := map[string]*regexp.Regexp{
		"pastebin":         regexp.MustCompile(`(?i)pastebin\.com`),
		"discord_webhook":  regexp.MustCompile(`(?i)discord\.com/api/webhooks|discord\.gg`),
		"transfer_sh":      regexp.MustCompile(`(?i)transfer\.sh`),
		"tor_onion":        regexp.MustCompile(`(?i)\.onion\b`),
		"ngrok_tunnel":     regexp.MustCompile(`(?i)ngrok\.io|ngrok-free\.app`),
		"telegram_bot":     regexp.MustCompile(`(?i)api\.telegram\.org/bot`),
		"mining_pool_1":    regexp.MustCompile(`(?i)supportxmr\.com|dwarfpool\.com|nanopool\.org`),
		"mining_pool_2":    regexp.MustCompile(`(?i)f2pool\.com|minergate\.com|nicehash\.com`),
		"mining_pool_3":    regexp.MustCompile(`(?i)pool\.hashvault\.pro|moneroocean\.stream`),
		"raw_github":       regexp.MustCompile(`(?i)raw\.githubusercontent\.com/[^/]+/[^/]+/(?:master|main)/`), // Suspicious if downloading scripts
		"suspicious_ip":    regexp.MustCompile(`(?:curl|wget|http[s]?://).*(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[\d\.]+`), // Internal IPs in download commands
	}

	// Search for patterns in all files
	const maxFileSize = 5 * 1024 * 1024 // Max 5MB per file
	const maxMatches = 10000            // Limit matches to prevent memory exhaustion
	matches, err := s.dockerClient.SearchFileContent(ctx, target.ImageName, suspiciousPatterns, maxFileSize, maxMatches)
	if err != nil {
		return findings, nil // Non-fatal
	}

	// Track unique findings
	foundIndicators := make(map[string]bool)

	for _, match := range matches {
		key := fmt.Sprintf("%s:%s", match.PatternName, match.FilePath)
		if foundIndicators[key] {
			continue
		}
		foundIndicators[key] = true

		severity := models.SeverityHigh
		description := fmt.Sprintf("Found reference to suspicious network destination '%s' in %s. ", match.PatternName, match.FilePath)

		switch {
		case strings.Contains(match.PatternName, "mining"):
			severity = models.SeverityCritical
			description += "This domain is a known cryptocurrency mining pool, indicating potential cryptojacking malware."
		case strings.Contains(match.PatternName, "tor"):
			severity = models.SeverityCritical
			description += "This references the Tor network (.onion), commonly used for C2 communication in malware."
		case strings.Contains(match.PatternName, "webhook") || strings.Contains(match.PatternName, "telegram"):
			severity = models.SeverityHigh
			description += "This is commonly abused for data exfiltration and C2 communication in supply chain attacks."
		case strings.Contains(match.PatternName, "pastebin") || strings.Contains(match.PatternName, "transfer"):
			description += "This service is frequently abused for hosting malicious payloads and C2 commands."
		default:
			description += "This network destination is commonly abused in supply chain attacks."
		}

		finding := models.Finding{
			ID:          "SUPPLY-CHAIN-006",
			Title:       fmt.Sprintf("Suspicious network destination: %s", match.PatternName),
			Description: description,
			Severity:    severity,
			Category:    "Supply-Chain",
			Source:      "supply-chain",
			Remediation: "Investigate why this domain is referenced. Block network egress to untrusted destinations. Use network policies to restrict container communications.",
			Location: &models.Location{
				File: match.FilePath,
				Line: match.LineNumber,
			},
			Metadata: map[string]interface{}{
				"pattern": match.PatternName,
				"match":   match.Match,
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// scanPhishingContent detects phishing in documentation
func (s *SupplyChainScanner) scanPhishingContent(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Phishing indicator patterns
	phishingPatterns := map[string]*regexp.Regexp{
		"verify_account":    regexp.MustCompile(`(?i)verify\s+(your|the)\s+account`),
		"suspended":         regexp.MustCompile(`(?i)(account|service|access).*suspended`),
		"click_immediately": regexp.MustCompile(`(?i)(click|act)\s+(here\s+)?(immediately|now|urgently)`),
		"confirm_identity":  regexp.MustCompile(`(?i)confirm\s+(your\s+)?(identity|credentials)`),
		"urgent_action":     regexp.MustCompile(`(?i)urgent\s+action\s+required`),
		"account_closure":   regexp.MustCompile(`(?i)account\s+will\s+be\s+(closed|terminated|deleted)`),
		"prize_winner":      regexp.MustCompile(`(?i)(you\s+)?(won|winner|prize|lottery|inheritance)`),
		"payment_required":  regexp.MustCompile(`(?i)(urgent\s+)?payment\s+(is\s+)?(required|needed|overdue)`),
		"reset_password":    regexp.MustCompile(`(?i)reset\s+(your\s+)?password\s+(immediately|now)`),
		"suspicious_url":    regexp.MustCompile(`(?i)(bit\.ly|tinyurl|goo\.gl|t\.co)/[a-zA-Z0-9]+`), // URL shorteners in docs
	}

	// Files to scan for phishing content
	docsFiles := []string{
		"README", "README.md", "README.txt",
		"DESCRIPTION", "description.md",
		"Dockerfile", "dockerfile",
		"docker-compose.yml", "docker-compose.yaml",
	}

	// Search in known documentation files
	for _, docFile := range docsFiles {
		content, err := s.dockerClient.ExtractFile(ctx, target.ImageName, docFile)
		if err != nil {
			continue // File doesn't exist, skip
		}

		contentStr := strings.ToLower(string(content))

		for patternName, pattern := range phishingPatterns {
			if matches := pattern.FindAllStringIndex(contentStr, -1); len(matches) > 0 {
				// Count line number for first match
				firstMatch := matches[0][0]
				lineNum := strings.Count(contentStr[:firstMatch], "\n") + 1

				finding := models.Finding{
					ID:          "SUPPLY-CHAIN-007",
					Title:       "Potential phishing content in documentation",
					Description: fmt.Sprintf("Found phishing indicator '%s' in %s. This pattern is commonly used in social engineering attacks. The 2024 imageless container campaign used similar tactics in 4M+ malicious images to redirect users to phishing sites.", patternName, docFile),
					Severity:    models.SeverityHigh,
					Category:    "Supply-Chain",
					Source:      "supply-chain",
					Remediation: "Do not follow links in the documentation. Verify the image source. Report this image as potentially malicious to the registry operator.",
					Location: &models.Location{
						File: docFile,
						Line: lineNum,
					},
					Metadata: map[string]interface{}{
						"pattern":      patternName,
						"match_count":  len(matches),
					},
				}
				findings = append(findings, finding)
				break // Only report once per file
			}
		}

		// Also check for excessive external links (suspicious in imageless containers)
		urlPattern := regexp.MustCompile(`https?://[^\s\)]+`)
		urls := urlPattern.FindAll(content, -1)
		if len(urls) > 5 {
			finding := models.Finding{
				ID:          "SUPPLY-CHAIN-011",
				Title:       "Excessive external links in documentation",
				Description: fmt.Sprintf("Found %d external URLs in %s. Imageless containers often contain numerous links to redirect users to malicious sites.", len(urls), docFile),
				Severity:    models.SeverityMedium,
				Category:    "Supply-Chain",
				Source:      "supply-chain",
				Remediation: "Verify all URLs in the documentation point to legitimate sources. Be cautious of URL shorteners and unknown domains.",
				Location: &models.Location{
					File: docFile,
				},
				Metadata: map[string]interface{}{
					"url_count": len(urls),
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
