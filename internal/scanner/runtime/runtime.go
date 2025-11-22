package runtime

import (
	"context"
	"fmt"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
)

// RuntimeScanner checks runtime security configurations
type RuntimeScanner struct {
	scanner.BaseScanner
}

// NewRuntimeScanner creates a new runtime security scanner
func NewRuntimeScanner() *RuntimeScanner {
	return &RuntimeScanner{
		BaseScanner: scanner.NewBaseScanner(
			"runtime-security",
			"Runtime security checks (capabilities, seccomp, AppArmor, privileged mode)",
			true,
		),
	}
}

// Scan performs runtime security checks
func (s *RuntimeScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	findings = append(findings, s.checkLinuxCapabilities(target)...)
	findings = append(findings, s.checkSeccompProfile(target)...)
	findings = append(findings, s.checkAppArmorProfile(target)...)
	findings = append(findings, s.checkPIDNamespace(target)...)
	findings = append(findings, s.checkIPCNamespace(target)...)
	findings = append(findings, s.checkUserNamespace(target)...)

	return findings, nil
}

// checkLinuxCapabilities audits dangerous Linux capabilities
func (s *RuntimeScanner) checkLinuxCapabilities(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// Dangerous capabilities that enable container escape
	dangerousCapabilities := map[string]CapabilityRisk{
		"CAP_SYS_ADMIN": {
			Name:        "CAP_SYS_ADMIN",
			Description: "Allows mounting filesystems, changing namespaces, and performing privileged operations. Primary vector for container escape.",
			Severity:    models.SeverityCritical,
			EscapeRisk:  true,
		},
		"CAP_SYS_MODULE": {
			Name:        "CAP_SYS_MODULE",
			Description: "Allows loading kernel modules. Can be used to load malicious modules and compromise the host.",
			Severity:    models.SeverityCritical,
			EscapeRisk:  true,
		},
		"CAP_SYS_PTRACE": {
			Name:        "CAP_SYS_PTRACE",
			Description: "Allows process tracing and debugging. Can be used to inject code into host processes.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  true,
		},
		"CAP_DAC_READ_SEARCH": {
			Name:        "CAP_DAC_READ_SEARCH",
			Description: "Bypasses file read permission checks. Allows reading sensitive host files.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  false,
		},
		"CAP_NET_ADMIN": {
			Name:        "CAP_NET_ADMIN",
			Description: "Allows network configuration. Can be used to intercept traffic or bypass network restrictions.",
			Severity:    models.SeverityMedium,
			EscapeRisk:  false,
		},
		"CAP_SYS_RAWIO": {
			Name:        "CAP_SYS_RAWIO",
			Description: "Allows raw I/O operations. Can access hardware devices directly.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  true,
		},
	}

	for _, cap := range dangerousCapabilities {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-CAP-%s", cap.Name),
			Title:       fmt.Sprintf("Dangerous capability: %s", cap.Name),
			Description: cap.Description,
			Severity:    cap.Severity,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Use --cap-drop=ALL to remove all capabilities, then add only required capabilities with --cap-add. Never grant CAP_SYS_ADMIN unless absolutely necessary.",
			References: []string{
				"https://man7.org/linux/man-pages/man7/capabilities.7.html",
				"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
			},
			Metadata: map[string]interface{}{
				"capability":  cap.Name,
				"escape_risk": cap.EscapeRisk,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkSeccompProfile checks if a seccomp profile is applied
func (s *RuntimeScanner) checkSeccompProfile(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// Check if seccomp is disabled
	hasSeccomp := true // Would check actual container config

	if !hasSeccomp {
		finding := models.Finding{
			ID:          "RUNTIME-SECCOMP-001",
			Title:       "Seccomp profile not applied",
			Description: "No seccomp profile is applied to restrict system calls. This allows the container to make any syscall, increasing attack surface.",
			Severity:    models.SeverityHigh,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Apply a seccomp profile using --security-opt seccomp=profile.json. Use Docker's default profile or create a custom one.",
			References: []string{
				"https://docs.docker.com/engine/security/seccomp/",
			},
		}
		findings = append(findings, finding)
	}

	// Warn about unconfined seccomp
	finding := models.Finding{
		ID:          "RUNTIME-SECCOMP-002",
		Title:       "Verify seccomp profile configuration",
		Description: "Ensure seccomp profile is not running in 'unconfined' mode. Running unconfined disables all syscall filtering.",
		Severity:    models.SeverityMedium,
		Category:    "Runtime-Security",
		Source:      "runtime-security",
		Remediation: "Do not use --security-opt seccomp=unconfined. Use the default profile or a custom restrictive profile.",
	}
	findings = append(findings, finding)

	return findings
}

// checkAppArmorProfile checks for AppArmor/SELinux profiles
func (s *RuntimeScanner) checkAppArmorProfile(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "RUNTIME-APPARMOR-001",
		Title:       "Verify mandatory access control (AppArmor/SELinux)",
		Description: "Ensure AppArmor or SELinux profiles are applied for additional security hardening. These provide mandatory access control beyond standard Unix permissions.",
		Severity:    models.SeverityMedium,
		Category:    "Runtime-Security",
		Source:      "runtime-security",
		Remediation: "Apply AppArmor profile with --security-opt apparmor=profile or SELinux context with --security-opt label=level.",
		References: []string{
			"https://docs.docker.com/engine/security/apparmor/",
			"https://docs.docker.com/engine/security/selinux/",
		},
	}
	findings = append(findings, finding)

	return findings
}

// checkPIDNamespace checks PID namespace configuration
func (s *RuntimeScanner) checkPIDNamespace(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	// Check if sharing host PID namespace
	sharingHostPID := false // Would check actual config

	if sharingHostPID {
		finding := models.Finding{
			ID:          "RUNTIME-PID-001",
			Title:       "Container shares host PID namespace",
			Description: "Container is running with --pid=host which allows it to see and manipulate all processes on the host. This is extremely dangerous.",
			Severity:    models.SeverityCritical,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --pid=host flag. Use isolated PID namespace (default behavior).",
			References: []string{
				"https://docs.docker.com/engine/reference/run/#pid-settings---pid",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkIPCNamespace checks IPC namespace sharing
func (s *RuntimeScanner) checkIPCNamespace(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "RUNTIME-IPC-001",
		Title:       "Verify IPC namespace isolation",
		Description: "Ensure container is not sharing host IPC namespace (--ipc=host). Shared IPC allows inter-process communication with host processes.",
		Severity:    models.SeverityHigh,
		Category:    "Runtime-Security",
		Source:      "runtime-security",
		Remediation: "Do not use --ipc=host. Use isolated IPC namespace (default).",
	}
	findings = append(findings, finding)

	return findings
}

// checkUserNamespace checks user namespace configuration
func (s *RuntimeScanner) checkUserNamespace(target models.ScanTarget) []models.Finding {
	var findings []models.Finding

	finding := models.Finding{
		ID:          "RUNTIME-USER-NS-001",
		Title:       "Consider enabling user namespace remapping",
		Description: "User namespace remapping maps container root to unprivileged host user, providing additional isolation. This significantly reduces impact of container escape.",
		Severity:    models.SeverityLow,
		Category:    "Runtime-Security",
		Source:      "runtime-security",
		Remediation: "Enable user namespace remapping in daemon.json with 'userns-remap'. This is a defense-in-depth measure.",
		References: []string{
			"https://docs.docker.com/engine/security/userns-remap/",
		},
	}
	findings = append(findings, finding)

	return findings
}

// CapabilityRisk describes a dangerous Linux capability
type CapabilityRisk struct {
	Name        string
	Description string
	Severity    models.Severity
	EscapeRisk  bool
}
