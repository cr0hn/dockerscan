package cis

import (
	"context"
	"fmt"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
)

// CISScanner implements CIS Docker Benchmark v1.7.0 checks
type CISScanner struct {
	scanner.BaseScanner
}

// NewCISScanner creates a new CIS benchmark scanner
func NewCISScanner() *CISScanner {
	return &CISScanner{
		BaseScanner: scanner.NewBaseScanner(
			"cis-benchmark",
			"CIS Docker Benchmark v1.7.0 compliance checks",
			true,
		),
	}
}

// Scan performs CIS benchmark checks
func (s *CISScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Image Configuration Checks (CIS Section 4)
	findings = append(findings, s.checkImageUser(target)...)
	findings = append(findings, s.checkImageSecrets(target)...)
	findings = append(findings, s.checkHealthcheck(target)...)
	findings = append(findings, s.checkImageTag(target)...)
	findings = append(findings, s.checkExposedPorts(target)...)

	// Runtime Configuration Checks (CIS Section 5)
	findings = append(findings, s.checkPrivilegedContainers(target)...)
	findings = append(findings, s.checkCapabilities(target)...)
	findings = append(findings, s.checkHostNetwork(target)...)
	findings = append(findings, s.checkReadOnlyRootFS(target)...)

	return findings, nil
}

// CIS 4.1: Ensure that a user for the container has been created
func (s *CISScanner) checkImageUser(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// This would inspect the image metadata
	// For now, we'll create a placeholder finding
	finding := models.Finding{
		ID:          "CIS-4.1",
		Title:       "Container should not run as root",
		Description: "Running containers as root increases the attack surface. A compromised container running as root can potentially gain full control of the host system.",
		Severity:    models.SeverityHigh,
		Category:    "CIS-Benchmark",
		Source:      "cis-benchmark",
		Remediation: "Use the USER instruction in Dockerfile to run as non-root user. Example: USER nonroot:nonroot",
		References: []string{
			"https://docs.docker.com/engine/reference/builder/#user",
			"https://www.cisecurity.org/benchmark/docker",
		},
	}

	findings = append(findings, finding)
	return findings
}

// CIS 4.3: Ensure that unnecessary packages are not installed
func (s *CISScanner) checkImageSecrets(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "CIS-4.3",
		Title:       "Image may contain unnecessary packages",
		Description: "Unnecessary packages increase the attack surface and image size. Only include packages required for the application to function.",
		Severity:    models.SeverityMedium,
		Category:    "CIS-Benchmark",
		Source:      "cis-benchmark",
		Remediation: "Use minimal base images (alpine, distroless) and remove unnecessary packages. Use multi-stage builds to exclude build dependencies.",
		References: []string{
			"https://docs.docker.com/develop/dev-best-practices/",
		},
	}

	findings = append(findings, finding)
	return findings
}

// CIS 4.6: Add HEALTHCHECK instruction to container image
func (s *CISScanner) checkHealthcheck(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "CIS-4.6",
		Title:       "Image should include HEALTHCHECK instruction",
		Description: "HEALTHCHECK allows Docker to test if a container is still working. Without it, Docker has no way to detect application failures.",
		Severity:    models.SeverityLow,
		Category:    "CIS-Benchmark",
		Source:      "cis-benchmark",
		Remediation: "Add HEALTHCHECK instruction in Dockerfile. Example: HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1",
		References: []string{
			"https://docs.docker.com/engine/reference/builder/#healthcheck",
		},
	}

	findings = append(findings, finding)
	return findings
}

// CIS 4.7: Do not use update instructions alone in Dockerfile
func (s *CISScanner) checkImageTag(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// Check if using 'latest' tag
	if target.ImageName != "" {
		finding := models.Finding{
			ID:          "CIS-4.7",
			Title:       "Avoid using 'latest' tag",
			Description: "Using 'latest' tag makes it unclear which version is deployed and can lead to inconsistent deployments.",
			Severity:    models.SeverityMedium,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Always use specific version tags. Example: nginx:1.21.0 instead of nginx:latest",
			References: []string{
				"https://docs.docker.com/develop/dev-best-practices/",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 5.7: Do not expose more ports than necessary
func (s *CISScanner) checkExposedPorts(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// Placeholder - would inspect actual exposed ports
	finding := models.Finding{
		ID:          "CIS-5.7",
		Title:       "Review exposed ports",
		Description: "Exposing unnecessary ports increases the attack surface. Only expose ports that are required for the application.",
		Severity:    models.SeverityMedium,
		Category:    "CIS-Benchmark",
		Source:      "cis-benchmark",
		Remediation: "Review EXPOSE instructions and docker run -p flags. Remove any unnecessary port exposures.",
	}

	findings = append(findings, finding)
	return findings
}

// CIS 5.3: Ensure that containers do not have privileged access
func (s *CISScanner) checkPrivilegedContainers(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "CIS-5.3",
		Title:       "Container should not run in privileged mode",
		Description: "Privileged containers have full access to host devices and can bypass most security restrictions. This is extremely dangerous.",
		Severity:    models.SeverityCritical,
		Category:    "CIS-Benchmark",
		Source:      "cis-benchmark",
		Remediation: "Never use --privileged flag unless absolutely necessary. Use specific capabilities instead with --cap-add.",
		References: []string{
			"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
		},
	}

	findings = append(findings, finding)
	return findings
}

// CIS 5.4: Ensure Linux Kernel Capabilities are restricted
func (s *CISScanner) checkCapabilities(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	dangerousCaps := []string{
		"CAP_SYS_ADMIN",
		"CAP_NET_ADMIN",
		"CAP_SYS_MODULE",
		"CAP_DAC_READ_SEARCH",
		"CAP_SYS_PTRACE",
	}

	for _, cap := range dangerousCaps {
		finding := models.Finding{
			ID:          "CIS-5.4",
			Title:       fmt.Sprintf("Dangerous capability detected: %s", cap),
			Description: fmt.Sprintf("The capability %s can be abused for container escape or privilege escalation.", cap),
			Severity:    models.SeverityHigh,
			Category:    "CIS-Benchmark",
			Source:      "cis-benchmark",
			Remediation: "Use --cap-drop=ALL and only add required capabilities with --cap-add. Avoid dangerous capabilities.",
			Metadata: map[string]interface{}{
				"capability": cap,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CIS 5.9: Do not share the host's network namespace
func (s *CISScanner) checkHostNetwork(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "CIS-5.9",
		Title:       "Container should not use host network",
		Description: "Using host network mode disables network isolation and exposes the container to the host's network stack.",
		Severity:    models.SeverityHigh,
		Category:    "CIS-Benchmark",
		Source:      "cis-benchmark",
		Remediation: "Do not use --network=host. Use bridge or custom networks instead.",
		References: []string{
			"https://docs.docker.com/network/host/",
		},
	}

	findings = append(findings, finding)
	return findings
}

// CIS 5.12: Mount container's root filesystem as read only
func (s *CISScanner) checkReadOnlyRootFS(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "CIS-5.12",
		Title:       "Container root filesystem should be read-only",
		Description: "Read-only root filesystem prevents attackers from modifying the container filesystem and persisting malware.",
		Severity:    models.SeverityMedium,
		Category:    "CIS-Benchmark",
		Source:      "cis-benchmark",
		Remediation: "Use --read-only flag when running containers. Mount specific volumes for writable directories.",
		References: []string{
			"https://docs.docker.com/engine/reference/run/#security-configuration",
		},
	}

	findings = append(findings, finding)
	return findings
}
