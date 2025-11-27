package cis

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

// CISScanner implements CIS Docker Benchmark v1.7.0 checks
type CISScanner struct {
	scanner.BaseScanner
	dockerClient *docker.Client
}

// NewCISScanner creates a new CIS benchmark scanner
func NewCISScanner(dockerClient *docker.Client) *CISScanner {
	return &CISScanner{
		BaseScanner: scanner.NewBaseScanner(
			"cis-benchmark",
			"CIS Docker Benchmark v1.7.0 compliance checks",
			true,
		),
		dockerClient: dockerClient,
	}
}

// Scan performs CIS benchmark checks
func (s *CISScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Get image information
	imageInfo, err := s.dockerClient.InspectImage(ctx, target.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	// Get image history for dockerfile analysis
	history, err := s.dockerClient.GetImageHistory(ctx, target.ImageName)
	if err != nil {
		// Non-fatal, continue without history
		history = nil
	}

	// Image Configuration Checks (CIS Section 4)
	// CIS 4.1: Ensure that a user for the container has been created
	findings = append(findings, s.checkImageUser(imageInfo)...)

	// CIS 4.2: Use trusted base images
	findings = append(findings, s.checkTrustedBaseImage(history)...)

	// CIS 4.3: Do not install unnecessary packages
	findings = append(findings, s.checkUnnecessaryPackages(ctx, target.ImageName)...)

	// CIS 4.5: Enable content trust
	findings = append(findings, s.checkContentTrust(ctx, target.ImageName, imageInfo)...)

	// CIS 4.6: Add HEALTHCHECK instruction
	findings = append(findings, s.checkHealthcheck(imageInfo)...)

	// CIS 4.7: Do not use update instructions alone / Avoid 'latest' tag
	findings = append(findings, s.checkImageTag(target.ImageName, imageInfo)...)
	findings = append(findings, s.checkUpdateInstructions(history)...)

	// CIS 4.8: Remove setuid and setgid permissions
	findings = append(findings, s.checkSetuidSetgid(ctx, target.ImageName)...)

	// CIS 4.9: Use COPY instead of ADD
	findings = append(findings, s.checkADDInstruction(history)...)

	// CIS 4.10: Do not store secrets in Dockerfiles
	findings = append(findings, s.checkSecrets(ctx, target.ImageName)...)
	findings = append(findings, s.checkSecretsInHistory(history)...)

	// CIS 4.11: Install verified packages only
	findings = append(findings, s.checkPackageVerification(ctx, target.ImageName)...)

	// Additional security checks
	findings = append(findings, s.checkExposedPorts(imageInfo)...)
	findings = append(findings, s.checkShellPresence(ctx, target.ImageName)...)
	findings = append(findings, s.checkWorldWritableFiles(ctx, target.ImageName)...)
	findings = append(findings, s.checkSensitiveFiles(ctx, target.ImageName)...)
	findings = append(findings, s.checkEnvironmentVariables(imageInfo)...)
	findings = append(findings, s.checkVolumes(imageInfo)...)

	return findings, nil
}

// CIS 4.1: Ensure that a user for the container has been created
func (s *CISScanner) checkImageUser(info *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	// Check if user is root or empty (defaults to root)
	if info.User == "" || info.User == "root" || info.User == "0" {
		finding := models.Finding{
			ID:          "CIS-4.1",
			Title:       "Container runs as root user",
			Description: "The image is configured to run as root (UID 0). Running containers as root increases the attack surface and a compromised container could gain full control of the host system.",
			Severity:    models.SeverityHigh,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Add a USER instruction in your Dockerfile to run as a non-root user. Example:\n  RUN useradd -r -u 1001 appuser\n  USER appuser",
			References: []string{
				"https://docs.docker.com/engine/reference/builder/#user",
				"https://www.cisecurity.org/benchmark/docker",
			},
			Metadata: map[string]interface{}{
				"current_user": info.User,
				"cis_control":  "4.1",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.2: Use trusted base images
func (s *CISScanner) checkTrustedBaseImage(history []docker.HistoryEntry) []models.Finding {
	var findings []models.Finding

	if len(history) == 0 {
		return findings
	}

	// Check the base layer (last in history)
	baseLayer := history[len(history)-1]
	baseImage := extractBaseImage(baseLayer.CreatedBy)

	trustedRegistries := []string{
		"docker.io/library/",
		"gcr.io/distroless/",
		"mcr.microsoft.com/",
		"registry.access.redhat.com/",
		"quay.io/",
	}

	isTrusted := false
	for _, registry := range trustedRegistries {
		if strings.Contains(baseImage, registry) {
			isTrusted = true
			break
		}
	}

	// Check for official Docker images
	if strings.HasPrefix(baseImage, "library/") || (!strings.Contains(baseImage, "/") && baseImage != "") {
		isTrusted = true
	}

	if !isTrusted && baseImage != "" {
		finding := models.Finding{
			ID:          "CIS-4.2",
			Title:       "Base image may not be from a trusted source",
			Description: fmt.Sprintf("The base image '%s' is not from a well-known trusted registry. Using untrusted base images can introduce supply chain vulnerabilities.", baseImage),
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Use base images from trusted sources:\n  - Official Docker Hub images (library/*)\n  - Google's distroless images (gcr.io/distroless/*)\n  - Red Hat's UBI images\n  - Microsoft's official images",
			References: []string{
				"https://docs.docker.com/docker-hub/official_images/",
				"https://github.com/GoogleContainerTools/distroless",
			},
			Metadata: map[string]interface{}{
				"base_image":  baseImage,
				"cis_control": "4.2",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.3: Do not install unnecessary packages
func (s *CISScanner) checkUnnecessaryPackages(ctx context.Context, imageName string) []models.Finding {
	var findings []models.Finding

	packages, err := s.dockerClient.ListPackages(ctx, imageName)
	if err != nil || len(packages) == 0 {
		return findings
	}

	// Check for common unnecessary packages
	unnecessaryPackages := map[string]string{
		"curl":       "Consider removing if not needed by the application",
		"wget":       "Consider removing if not needed by the application",
		"vim":        "Editor not typically needed in production containers",
		"nano":       "Editor not typically needed in production containers",
		"emacs":      "Editor not typically needed in production containers",
		"telnet":     "Insecure protocol, should not be present",
		"ftp":        "Insecure protocol, should not be present",
		"net-tools":  "Legacy networking tools, often unnecessary",
		"tcpdump":    "Debugging tool, should not be in production",
		"strace":     "Debugging tool, should not be in production",
		"gcc":        "Compiler should not be in production images",
		"g++":        "Compiler should not be in production images",
		"make":       "Build tool should not be in production images",
		"build-base": "Alpine build tools should not be in production images",
	}

	foundUnnecessary := []string{}
	for _, pkg := range packages {
		if reason, exists := unnecessaryPackages[pkg.Name]; exists {
			foundUnnecessary = append(foundUnnecessary, fmt.Sprintf("%s (%s)", pkg.Name, reason))
		}
	}

	if len(foundUnnecessary) > 0 {
		finding := models.Finding{
			ID:          "CIS-4.3",
			Title:       fmt.Sprintf("Found %d potentially unnecessary packages", len(foundUnnecessary)),
			Description: "The image contains packages that may not be necessary for the application runtime. These increase attack surface and image size.",
			Severity:    models.SeverityLow,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Review installed packages and remove those not required:\n  - Use multi-stage builds to separate build and runtime dependencies\n  - Remove debugging and build tools from production images\n  - Consider using distroless base images",
			Metadata: map[string]interface{}{
				"total_packages":        len(packages),
				"unnecessary_packages":  foundUnnecessary,
				"cis_control":           "4.3",
			},
		}
		findings = append(findings, finding)
	}

	// Check for large number of packages (indicates bloated image)
	if len(packages) > 200 {
		finding := models.Finding{
			ID:          "CIS-4.3-BLOAT",
			Title:       fmt.Sprintf("Image has %d packages installed", len(packages)),
			Description: "A large number of installed packages suggests a bloated image with unnecessary components.",
			Severity:    models.SeverityInfo,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Consider using a minimal base image like Alpine or distroless to reduce package count and attack surface.",
			Metadata: map[string]interface{}{
				"package_count": len(packages),
				"cis_control":   "4.3",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.5: Enable Content Trust for Docker
func (s *CISScanner) checkContentTrust(ctx context.Context, imageName string, info *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	signed, digest, err := s.dockerClient.VerifyImageSignature(ctx, imageName)
	if err != nil {
		// Non-fatal, continue
		return findings
	}

	if !signed {
		finding := models.Finding{
			ID:          "CIS-4.5",
			Title:       "Image is not signed or verified",
			Description: "The image does not have a verifiable signature. Unsigned images cannot be verified for authenticity and may have been tampered with.",
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Enable Docker Content Trust by setting DOCKER_CONTENT_TRUST=1 before pulling images. For custom images, sign them using Docker Content Trust or Cosign.",
			References: []string{
				"https://docs.docker.com/engine/security/trust/",
				"https://github.com/sigstore/cosign",
			},
			Metadata: map[string]interface{}{
				"cis_control": "4.5",
			},
		}
		findings = append(findings, finding)
	} else {
		// Info finding - image is signed
		finding := models.Finding{
			ID:          "CIS-4.5-PASS",
			Title:       "Image has digest/signature",
			Description: fmt.Sprintf("The image has a verifiable digest: %s", digest),
			Severity:    models.SeverityInfo,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Metadata: map[string]interface{}{
				"digest":      digest,
				"cis_control": "4.5",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.6: Add HEALTHCHECK instruction to container image
func (s *CISScanner) checkHealthcheck(info *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	if info.Healthcheck == nil {
		finding := models.Finding{
			ID:          "CIS-4.6",
			Title:       "No HEALTHCHECK instruction defined",
			Description: "The image does not define a HEALTHCHECK instruction. Without a health check, Docker has no way to determine if the container is still functioning correctly.",
			Severity:    models.SeverityLow,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Add a HEALTHCHECK instruction in your Dockerfile. Example:\n  HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\\n    CMD curl -f http://localhost:8080/health || exit 1",
			References: []string{
				"https://docs.docker.com/engine/reference/builder/#healthcheck",
			},
			Metadata: map[string]interface{}{
				"cis_control": "4.6",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.7: Do not use update instructions alone / Avoid 'latest' tag
func (s *CISScanner) checkImageTag(imageName string, info *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	// Check for 'latest' tag
	if strings.HasSuffix(imageName, ":latest") || !strings.Contains(imageName, ":") {
		finding := models.Finding{
			ID:          "CIS-4.7",
			Title:       "Image uses 'latest' tag or no specific tag",
			Description: "Using the 'latest' tag or not specifying a tag makes it unclear which exact version is deployed and can lead to inconsistent deployments across environments.",
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Always use specific, immutable version tags. Example: nginx:1.25.3 instead of nginx:latest. Consider using image digests for maximum reproducibility: nginx@sha256:abc123...",
			References: []string{
				"https://docs.docker.com/develop/dev-best-practices/",
			},
			Metadata: map[string]interface{}{
				"image_name":  imageName,
				"cis_control": "4.7",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.7: Check for update instructions alone in Dockerfile
func (s *CISScanner) checkUpdateInstructions(history []docker.HistoryEntry) []models.Finding {
	var findings []models.Finding

	if history == nil {
		return findings
	}

	// Look for apt-get update, yum update, apk update without install in same layer
	updateOnlyCommands := []string{}
	for _, entry := range history {
		cmd := strings.ToLower(entry.CreatedBy)

		// Check for package manager update commands
		hasUpdate := (strings.Contains(cmd, "apt-get") && strings.Contains(cmd, "update")) ||
			(strings.Contains(cmd, "apt") && strings.Contains(cmd, "update")) ||
			(strings.Contains(cmd, "yum") && strings.Contains(cmd, "update")) ||
			(strings.Contains(cmd, "apk") && strings.Contains(cmd, "update"))

		hasInstall := strings.Contains(cmd, "install") || strings.Contains(cmd, "add")

		if hasUpdate && !hasInstall {
			updateOnlyCommands = append(updateOnlyCommands, entry.CreatedBy)
		}
	}

	if len(updateOnlyCommands) > 0 {
		finding := models.Finding{
			ID:          "CIS-4.7-UPDATE",
			Title:       "Package manager update without install detected",
			Description: "The Dockerfile contains package manager update commands without corresponding install commands. This can cause build cache issues and unpredictable builds.",
			Severity:    models.SeverityLow,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Combine update and install in a single RUN instruction:\n  RUN apt-get update && apt-get install -y package1 package2 && apt-get clean && rm -rf /var/lib/apt/lists/*",
			Metadata: map[string]interface{}{
				"update_commands": updateOnlyCommands,
				"cis_control":     "4.7",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.8: Ensure setuid and setgid permissions are removed
func (s *CISScanner) checkSetuidSetgid(ctx context.Context, imageName string) []models.Finding {
	var findings []models.Finding

	setuidFiles := []string{}
	setgidFiles := []string{}

	err := s.dockerClient.ScanImageFiles(ctx, imageName, func(info docker.FileInfo, _ io.Reader) error {
		mode := info.Mode

		// Check for setuid (mode & 04000)
		if mode&04000 != 0 {
			setuidFiles = append(setuidFiles, info.Path)
		}

		// Check for setgid (mode & 02000)
		if mode&02000 != 0 {
			setgidFiles = append(setgidFiles, info.Path)
		}

		return nil
	})

	if err != nil {
		// Non-fatal, continue
		return findings
	}

	// Limit reported files to avoid huge output
	maxFiles := 20

	if len(setuidFiles) > 0 {
		reportedFiles := setuidFiles
		if len(reportedFiles) > maxFiles {
			reportedFiles = reportedFiles[:maxFiles]
		}

		finding := models.Finding{
			ID:          "CIS-4.8",
			Title:       fmt.Sprintf("Found %d files with setuid bit set", len(setuidFiles)),
			Description: "Files with setuid permission run with owner's privileges regardless of who executes them. These can be exploited for privilege escalation attacks.",
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Remove setuid bit from files that don't need it:\n  RUN find / -perm /4000 -type f -exec chmod u-s {} \\;\nOr remove the binaries entirely if not needed.",
			References: []string{
				"https://www.cisecurity.org/benchmark/docker",
			},
			Metadata: map[string]interface{}{
				"total_setuid_files": len(setuidFiles),
				"sample_files":       reportedFiles,
				"cis_control":        "4.8",
			},
		}
		findings = append(findings, finding)
	}

	if len(setgidFiles) > 0 {
		reportedFiles := setgidFiles
		if len(reportedFiles) > maxFiles {
			reportedFiles = reportedFiles[:maxFiles]
		}

		finding := models.Finding{
			ID:          "CIS-4.8-SETGID",
			Title:       fmt.Sprintf("Found %d files with setgid bit set", len(setgidFiles)),
			Description: "Files with setgid permission run with group's privileges regardless of who executes them. These can be exploited for privilege escalation attacks.",
			Severity:    models.SeverityLow,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Remove setgid bit from files that don't need it:\n  RUN find / -perm /2000 -type f -exec chmod g-s {} \\;",
			Metadata: map[string]interface{}{
				"total_setgid_files": len(setgidFiles),
				"sample_files":       reportedFiles,
				"cis_control":        "4.8",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.9: Ensure that COPY is used instead of ADD
func (s *CISScanner) checkADDInstruction(history []docker.HistoryEntry) []models.Finding {
	var findings []models.Finding

	if history == nil {
		return findings
	}

	addCommands := []string{}
	for _, entry := range history {
		cmd := strings.ToUpper(entry.CreatedBy)
		if strings.Contains(cmd, "ADD ") && !strings.Contains(cmd, "ADD FILE:") {
			// ADD file: is internal docker representation, skip those
			if strings.Contains(entry.CreatedBy, "ADD") {
				addCommands = append(addCommands, entry.CreatedBy)
			}
		}
	}

	if len(addCommands) > 0 {
		finding := models.Finding{
			ID:          "CIS-4.9",
			Title:       "ADD instruction used instead of COPY",
			Description: "The Dockerfile uses ADD instruction which has additional features like URL fetching and auto-extraction that can introduce security risks. COPY is more transparent and predictable.",
			Severity:    models.SeverityLow,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Replace ADD with COPY unless you specifically need ADD's features (URL fetching, tar extraction). For downloading files, use RUN with curl/wget for better control.",
			References: []string{
				"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy",
			},
			Metadata: map[string]interface{}{
				"add_commands": addCommands,
				"cis_control":  "4.9",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.10: Do not store secrets in Dockerfiles
func (s *CISScanner) checkSecrets(ctx context.Context, imageName string) []models.Finding {
	var findings []models.Finding

	// Define patterns for common secrets
	patterns := map[string]*regexp.Regexp{
		"AWS Access Key":          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"AWS Secret Key":          regexp.MustCompile(`(?i)aws_secret[_-]?access[_-]?key[\s:=]+[\w/+]{40}`),
		"Private Key":             regexp.MustCompile(`-----BEGIN (RSA |DSA )?PRIVATE KEY-----`),
		"GitHub Token":            regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		"Generic API Key":         regexp.MustCompile(`(?i)(api[_-]?key|apikey)[\s:=]+[\w-]{20,}`),
		"Generic Secret":          regexp.MustCompile(`(?i)(secret|password|passwd)[\s:=]+[\w!@#$%^&*()]{8,}`),
		"Database Connection":     regexp.MustCompile(`(?i)(mysql|postgres|mongodb)://[^:]+:[^@]+@`),
		"JSON Web Token":          regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
		"Google API Key":          regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		"Slack Token":             regexp.MustCompile(`xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}`),
		"Generic Password Hash":   regexp.MustCompile(`\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}`),
	}

	const maxFileSize = 10 * 1024 * 1024 // Max 10MB per file
	const maxMatches = 10000             // Limit matches to prevent memory exhaustion
	matches, err := s.dockerClient.SearchFileContent(ctx, imageName, patterns, maxFileSize, maxMatches)
	if err != nil {
		return findings
	}

	if len(matches) > 0 {
		// Group matches by pattern
		secretsByType := make(map[string][]string)
		for _, match := range matches {
			location := fmt.Sprintf("%s:%d", match.FilePath, match.LineNumber)
			secretsByType[match.PatternName] = append(secretsByType[match.PatternName], location)
		}

		finding := models.Finding{
			ID:          "CIS-4.10",
			Title:       fmt.Sprintf("Found %d potential secrets in image", len(matches)),
			Description: "The image contains files with patterns matching common secret formats (API keys, passwords, tokens). Storing secrets in images is a critical security risk as they can be extracted by anyone with access to the image.",
			Severity:    models.SeverityCritical,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Never store secrets in images. Use one of these alternatives:\n  - Environment variables (injected at runtime)\n  - Docker secrets (Swarm mode)\n  - Kubernetes secrets\n  - External secret management (Vault, AWS Secrets Manager)\n  - Build-time secrets with BuildKit --secret flag",
			References: []string{
				"https://docs.docker.com/engine/swarm/secrets/",
				"https://kubernetes.io/docs/concepts/configuration/secret/",
			},
			Metadata: map[string]interface{}{
				"secrets_by_type": secretsByType,
				"total_matches":   len(matches),
				"cis_control":     "4.10",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.10: Check for secrets in Dockerfile history
func (s *CISScanner) checkSecretsInHistory(history []docker.HistoryEntry) []models.Finding {
	var findings []models.Finding

	if history == nil {
		return findings
	}

	// Look for common secret patterns in build commands
	secretPatterns := []string{
		"password=", "PASSWORD=",
		"secret=", "SECRET=",
		"token=", "TOKEN=",
		"key=", "KEY=",
		"apikey=", "APIKEY=", "API_KEY=",
	}

	suspiciousCommands := []string{}
	for _, entry := range history {
		cmd := entry.CreatedBy
		for _, pattern := range secretPatterns {
			if strings.Contains(cmd, pattern) {
				suspiciousCommands = append(suspiciousCommands, cmd)
				break
			}
		}
	}

	if len(suspiciousCommands) > 0 {
		finding := models.Finding{
			ID:          "CIS-4.10-HISTORY",
			Title:       "Potential secrets found in Dockerfile history",
			Description: "The image build history contains commands with keywords suggesting secrets (password, token, key). These values may be embedded in the image layers.",
			Severity:    models.SeverityHigh,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Remove secret values from Dockerfile:\n  - Use build arguments (ARG) for build-time secrets, then unset them\n  - Use multi-stage builds and don't copy secrets to final stage\n  - Use BuildKit's --secret mount for build-time secrets\n  - Never hardcode secrets in RUN commands",
			Metadata: map[string]interface{}{
				"suspicious_commands": suspiciousCommands,
				"cis_control":         "4.10",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 4.11: Install verified packages only
func (s *CISScanner) checkPackageVerification(ctx context.Context, imageName string) []models.Finding {
	var findings []models.Finding

	// Check if GPG verification is disabled in history
	hasNoCheckGPG := false

	history, err := s.dockerClient.GetImageHistory(ctx, imageName)
	if err == nil {
		for _, entry := range history {
			cmd := strings.ToLower(entry.CreatedBy)
			if strings.Contains(cmd, "--no-check-gpg") ||
				strings.Contains(cmd, "--allow-unauthenticated") ||
				strings.Contains(cmd, "--allow-untrusted") ||
				strings.Contains(cmd, "rpm --nosignature") {
				hasNoCheckGPG = true
				break
			}
		}
	}

	if hasNoCheckGPG {
		finding := models.Finding{
			ID:          "CIS-4.11",
			Title:       "Package signature verification disabled",
			Description: "The image build process disables GPG signature verification when installing packages. This allows unsigned or tampered packages to be installed.",
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Remove flags that disable signature verification:\n  - Remove --no-check-gpg from apk commands\n  - Remove --allow-unauthenticated from apt-get commands\n  - Remove --nosignature from rpm commands\n  - Ensure package manager keys are properly configured",
			References: []string{
				"https://www.cisecurity.org/benchmark/docker",
			},
			Metadata: map[string]interface{}{
				"cis_control": "4.11",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 5.7: Do not map privileged ports
func (s *CISScanner) checkExposedPorts(info *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	privilegedPorts := []string{}
	allPorts := []string{}

	for _, port := range info.ExposedPorts {
		allPorts = append(allPorts, port)

		// Extract port number
		portNum := 0
		fmt.Sscanf(port, "%d", &portNum)
		if portNum > 0 && portNum < 1024 {
			privilegedPorts = append(privilegedPorts, port)
		}
	}

	// Check for privileged ports
	if len(privilegedPorts) > 0 {
		finding := models.Finding{
			ID:          "CIS-5.7",
			Title:       "Image exposes privileged ports (< 1024)",
			Description: fmt.Sprintf("The image exposes privileged ports which require root privileges to bind: %v. This may indicate the container needs to run as root.", privilegedPorts),
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Use non-privileged ports (>= 1024) in your application and remap them at runtime if needed. Example: Use port 8080 instead of 80, then run with -p 80:8080",
			Metadata: map[string]interface{}{
				"privileged_ports": privilegedPorts,
				"all_ports":        allPorts,
				"cis_control":      "5.7",
			},
		}
		findings = append(findings, finding)
	}

	// Report all exposed ports for review
	if len(allPorts) > 5 {
		finding := models.Finding{
			ID:          "CIS-5.7-INFO",
			Title:       "Image exposes multiple ports",
			Description: fmt.Sprintf("The image exposes %d ports. Review to ensure all are necessary: %v", len(allPorts), allPorts),
			Severity:    models.SeverityInfo,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Review all exposed ports and remove any that are not required for the application to function.",
			Metadata: map[string]interface{}{
				"port_count":  len(allPorts),
				"ports":       allPorts,
				"cis_control": "5.7",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Check for shell presence (useful for detecting distroless images)
func (s *CISScanner) checkShellPresence(ctx context.Context, imageName string) []models.Finding {
	var findings []models.Finding

	shellPaths := []string{
		"bin/sh", "bin/bash", "bin/ash", "bin/dash", "bin/zsh",
		"usr/bin/sh", "usr/bin/bash", "usr/bin/ash", "usr/bin/dash", "usr/bin/zsh",
	}

	foundShells := []string{}

	err := s.dockerClient.ScanImageFiles(ctx, imageName, func(info docker.FileInfo, _ io.Reader) error {
		for _, shell := range shellPaths {
			if info.Path == shell || strings.TrimPrefix(info.Path, "/") == shell {
				foundShells = append(foundShells, info.Path)
			}
		}
		return nil
	})

	if err != nil {
		return findings
	}

	if len(foundShells) == 0 {
		// This is actually good - distroless image
		finding := models.Finding{
			ID:          "CIS-DISTROLESS",
			Title:       "Image appears to be shell-less (distroless)",
			Description: "No common shells were found in the image. This is a security best practice as it reduces the attack surface.",
			Severity:    models.SeverityInfo,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Metadata: map[string]interface{}{
				"shells_checked": shellPaths,
			},
		}
		findings = append(findings, finding)
	} else {
		finding := models.Finding{
			ID:          "CIS-SHELL-PRESENT",
			Title:       "Image contains shell interpreters",
			Description: fmt.Sprintf("Found shell interpreters in the image: %v. Shells can be used by attackers for post-exploitation activities.", foundShells),
			Severity:    models.SeverityInfo,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Consider using distroless or scratch-based images to reduce attack surface. If shells are needed for debugging, consider multi-stage builds with a debug variant.",
			References: []string{
				"https://github.com/GoogleContainerTools/distroless",
			},
			Metadata: map[string]interface{}{
				"found_shells": foundShells,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Check for world-writable files
func (s *CISScanner) checkWorldWritableFiles(ctx context.Context, imageName string) []models.Finding {
	var findings []models.Finding

	worldWritableFiles := []string{}
	maxFiles := 50

	err := s.dockerClient.ScanImageFiles(ctx, imageName, func(info docker.FileInfo, _ io.Reader) error {
		// Skip directories and check for world-writable permission (mode & 0002)
		if !info.IsDir && info.Mode&0002 != 0 {
			worldWritableFiles = append(worldWritableFiles, info.Path)
		}
		return nil
	})

	if err != nil {
		return findings
	}

	if len(worldWritableFiles) > 0 {
		reportedFiles := worldWritableFiles
		if len(reportedFiles) > maxFiles {
			reportedFiles = reportedFiles[:maxFiles]
		}

		finding := models.Finding{
			ID:          "CIS-WORLD-WRITABLE",
			Title:       fmt.Sprintf("Found %d world-writable files", len(worldWritableFiles)),
			Description: "World-writable files can be modified by any user, potentially allowing attackers to inject malicious content or modify application behavior.",
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Remove world-writable permissions:\n  RUN find / -xdev -perm -0002 -type f -exec chmod o-w {} \\;",
			Metadata: map[string]interface{}{
				"total_files":  len(worldWritableFiles),
				"sample_files": reportedFiles,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Check for sensitive files with incorrect permissions
func (s *CISScanner) checkSensitiveFiles(ctx context.Context, imageName string) []models.Finding {
	var findings []models.Finding

	sensitiveFiles := map[string]bool{
		"etc/passwd":        false,
		"etc/shadow":        false,
		"etc/group":         false,
		"etc/gshadow":       false,
		"root/.ssh/id_rsa":  false,
		"root/.ssh/id_dsa":  false,
		"root/.bashrc":      false,
		"root/.bash_history": false,
	}

	foundIssues := []string{}

	err := s.dockerClient.ScanImageFiles(ctx, imageName, func(info docker.FileInfo, _ io.Reader) error {
		cleanPath := strings.TrimPrefix(info.Path, "/")

		if _, exists := sensitiveFiles[cleanPath]; exists {
			sensitiveFiles[cleanPath] = true

			// Check permissions
			if cleanPath == "etc/shadow" || cleanPath == "etc/gshadow" {
				// Should be readable only by root (0400 or 0000)
				if info.Mode&0077 != 0 {
					foundIssues = append(foundIssues, fmt.Sprintf("%s has overly permissive permissions (%o)", info.Path, info.Mode))
				}
			}

			// Check for SSH private keys
			if strings.Contains(cleanPath, "id_rsa") || strings.Contains(cleanPath, "id_dsa") {
				foundIssues = append(foundIssues, fmt.Sprintf("Private SSH key found: %s", info.Path))
			}
		}

		return nil
	})

	if err != nil {
		return findings
	}

	// Check if shadow file exists (it shouldn't in containers)
	if sensitiveFiles["etc/shadow"] {
		foundIssues = append(foundIssues, "/etc/shadow exists in image (indicates passwords are stored)")
	}

	if len(foundIssues) > 0 {
		finding := models.Finding{
			ID:          "CIS-SENSITIVE-FILES",
			Title:       fmt.Sprintf("Found %d sensitive file issues", len(foundIssues)),
			Description: "The image contains sensitive files with incorrect permissions or files that should not be present in container images.",
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Remove or fix sensitive files:\n  - Remove /etc/shadow if present (use /etc/passwd only)\n  - Remove SSH private keys\n  - Ensure proper permissions on sensitive files\n  - Clean bash history and other user files",
			Metadata: map[string]interface{}{
				"issues": foundIssues,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Check environment variables for sensitive data
func (s *CISScanner) checkEnvironmentVariables(info *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	sensitiveEnvVars := []string{}
	sensitiveKeywords := []string{
		"PASSWORD", "SECRET", "TOKEN", "KEY", "APIKEY", "API_KEY",
		"AWS_SECRET", "PRIVATE_KEY", "CREDENTIAL", "AUTH",
	}

	for key, value := range info.Env {
		keyUpper := strings.ToUpper(key)
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(keyUpper, keyword) {
				// Redact the value
				redacted := value
				if len(value) > 8 {
					redacted = value[:4] + "***"
				} else if value != "" {
					redacted = "***"
				}
				sensitiveEnvVars = append(sensitiveEnvVars, fmt.Sprintf("%s=%s", key, redacted))
				break
			}
		}
	}

	if len(sensitiveEnvVars) > 0 {
		finding := models.Finding{
			ID:          "CIS-ENV-SECRETS",
			Title:       fmt.Sprintf("Found %d environment variables with potentially sensitive names", len(sensitiveEnvVars)),
			Description: "The image has environment variables with names suggesting they contain sensitive data. While ENV values in images are not as dangerous as hardcoded secrets, they can still leak sensitive information.",
			Severity:    models.SeverityLow,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Do not set sensitive environment variables in Dockerfile:\n  - Inject sensitive values at runtime using --env or --env-file\n  - Use orchestrator secrets (Kubernetes secrets, Docker secrets)\n  - Use placeholder values in Dockerfile and override at runtime",
			Metadata: map[string]interface{}{
				"sensitive_vars": sensitiveEnvVars,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Check for volumes
func (s *CISScanner) checkVolumes(info *docker.ImageInfo) []models.Finding {
	var findings []models.Finding

	if len(info.Volumes) == 0 {
		// No volumes defined - this might be intentional or an oversight
		return findings
	}

	// Check for potentially sensitive volume paths
	sensitiveVolumes := []string{}
	for _, vol := range info.Volumes {
		// Volumes in sensitive paths
		if strings.HasPrefix(vol, "/etc") ||
			strings.HasPrefix(vol, "/root") ||
			strings.HasPrefix(vol, "/var/run") ||
			vol == "/tmp" {
			sensitiveVolumes = append(sensitiveVolumes, vol)
		}
	}

	if len(sensitiveVolumes) > 0 {
		finding := models.Finding{
			ID:          "CIS-VOLUMES-SENSITIVE",
			Title:       "Image defines volumes in sensitive paths",
			Description: fmt.Sprintf("The image defines VOLUME instructions for sensitive paths: %v. This can expose sensitive data or system resources.", sensitiveVolumes),
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Review volume definitions and ensure they don't expose sensitive paths. Consider using more specific mount points or removing VOLUME instructions and letting users specify mounts at runtime.",
			Metadata: map[string]interface{}{
				"sensitive_volumes": sensitiveVolumes,
				"all_volumes":       info.Volumes,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// Helper function to extract base image from history
func extractBaseImage(createdBy string) string {
	// Try to extract FROM instruction
	if strings.Contains(strings.ToUpper(createdBy), "FROM") {
		parts := strings.Fields(createdBy)
		for i, part := range parts {
			if strings.ToUpper(part) == "FROM" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}
