package runtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/internal/scanner"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

// RuntimeScanner checks runtime security configurations
type RuntimeScanner struct {
	scanner.BaseScanner
	dockerClient *docker.Client
}

// NewRuntimeScanner creates a new runtime security scanner
func NewRuntimeScanner(dockerClient *docker.Client) *RuntimeScanner {
	return &RuntimeScanner{
		BaseScanner: scanner.NewBaseScanner(
			"runtime-security",
			"Runtime security checks (capabilities, seccomp, AppArmor, privileged mode)",
			true,
		),
		dockerClient: dockerClient,
	}
}

// Scan performs runtime security checks on running containers
func (s *RuntimeScanner) Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error) {
	var findings []models.Finding

	// Determine which containers to scan
	var containersToScan []string

	if target.ContainerID != "" {
		// Scan specific container
		containersToScan = append(containersToScan, target.ContainerID)
	} else {
		// List all running containers
		containers, err := s.dockerClient.ListContainers(ctx, false)
		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}

		for _, container := range containers {
			if container.State == "running" {
				containersToScan = append(containersToScan, container.ID)
			}
		}
	}

	// If no containers found, return empty findings
	if len(containersToScan) == 0 {
		return findings, nil
	}

	// Scan each container
	for _, containerID := range containersToScan {
		containerFindings, err := s.scanContainer(ctx, containerID)
		if err != nil {
			// Log error but continue with other containers
			findings = append(findings, models.Finding{
				ID:          "RUNTIME-ERROR-001",
				Title:       fmt.Sprintf("Failed to scan container %s", containerID[:12]),
				Description: fmt.Sprintf("Error inspecting container: %v", err),
				Severity:    models.SeverityInfo,
				Category:    "Runtime-Security",
				Source:      "runtime-security",
			})
			continue
		}
		findings = append(findings, containerFindings...)
	}

	return findings, nil
}

// scanContainer performs security checks on a single container
func (s *RuntimeScanner) scanContainer(ctx context.Context, containerID string) ([]models.Finding, error) {
	var findings []models.Finding

	// Inspect container
	container, err := s.dockerClient.InspectContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	// Perform all security checks
	findings = append(findings, s.checkPrivilegedMode(container)...)
	findings = append(findings, s.checkCapabilities(container)...)
	findings = append(findings, s.checkSeccompProfile(container)...)
	findings = append(findings, s.checkAppArmorProfile(container)...)
	findings = append(findings, s.checkNamespaces(container)...)
	findings = append(findings, s.checkReadonlyRootfs(container)...)
	findings = append(findings, s.checkSensitiveMounts(container)...)
	findings = append(findings, s.checkUserConfig(container)...)

	return findings, nil
}

// checkPrivilegedMode checks if container is running in privileged mode
func (s *RuntimeScanner) checkPrivilegedMode(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	if container.Privileged {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-PRIV-001-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' running in privileged mode", container.Name),
			Description: "Container is running with --privileged flag, which grants full host access including all Linux capabilities, device access, and ability to modify kernel parameters. This is extremely dangerous and enables trivial container escape.",
			Severity:    models.SeverityCritical,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --privileged flag. Use specific capabilities (--cap-add) and device access (--device) instead. Only use privileged mode for specific system containers that absolutely require it.",
			References: []string{
				"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
				"https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"privileged":     true,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkCapabilities audits dangerous Linux capabilities
func (s *RuntimeScanner) checkCapabilities(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	// Define dangerous capabilities
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
		"CAP_DAC_OVERRIDE": {
			Name:        "CAP_DAC_OVERRIDE",
			Description: "Bypasses file read, write, and execute permission checks.",
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
		"CAP_SYS_BOOT": {
			Name:        "CAP_SYS_BOOT",
			Description: "Allows system reboot. Can be used for denial of service.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  false,
		},
		"CAP_NET_RAW": {
			Name:        "CAP_NET_RAW",
			Description: "Allows raw socket access. Can be used for packet sniffing and spoofing.",
			Severity:    models.SeverityMedium,
			EscapeRisk:  false,
		},
	}

	// Check for dangerous capabilities in CapAdd
	for _, cap := range container.CapAdd {
		// Normalize capability name (remove CAP_ prefix if not present)
		capName := strings.ToUpper(cap)
		if !strings.HasPrefix(capName, "CAP_") {
			capName = "CAP_" + capName
		}

		if capInfo, isDangerous := dangerousCapabilities[capName]; isDangerous {
			finding := models.Finding{
				ID:          fmt.Sprintf("RUNTIME-CAP-%s-%s", capName, container.ID[:12]),
				Title:       fmt.Sprintf("Container '%s' has dangerous capability: %s", container.Name, capName),
				Description: capInfo.Description,
				Severity:    capInfo.Severity,
				Category:    "Runtime-Security",
				Source:      "runtime-security",
				Remediation: "Remove unnecessary capabilities. Use --cap-drop=ALL to remove all capabilities, then add only required capabilities with --cap-add. Never grant CAP_SYS_ADMIN unless absolutely necessary.",
				References: []string{
					"https://man7.org/linux/man-pages/man7/capabilities.7.html",
					"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
				},
				Metadata: map[string]interface{}{
					"container_id":   container.ID,
					"container_name": container.Name,
					"capability":     capName,
					"escape_risk":    capInfo.EscapeRisk,
				},
			}
			findings = append(findings, finding)
		}
	}

	// Check if capabilities are being properly dropped
	if len(container.CapDrop) == 0 && !container.Privileged {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-CAP-NODROP-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' not dropping any capabilities", container.Name),
			Description: "Container is running with default capabilities. Best practice is to drop all capabilities (--cap-drop=ALL) and only add required ones.",
			Severity:    models.SeverityLow,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Use --cap-drop=ALL to remove all capabilities, then selectively add only required capabilities with --cap-add.",
			References: []string{
				"https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkSeccompProfile validates seccomp configuration
func (s *RuntimeScanner) checkSeccompProfile(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	hasSeccomp := false
	isUnconfined := false

	// Parse SecurityOpt for seccomp profile
	for _, opt := range container.SecurityOpt {
		if strings.HasPrefix(opt, "seccomp=") {
			hasSeccomp = true
			profile := strings.TrimPrefix(opt, "seccomp=")
			if profile == "unconfined" {
				isUnconfined = true
			}
		}
	}

	// Check for unconfined seccomp (most dangerous)
	if isUnconfined {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-SECCOMP-UNCONFINED-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' running with seccomp unconfined", container.Name),
			Description: "Container is running with --security-opt seccomp=unconfined, which disables all syscall filtering. This allows the container to make any system call, significantly increasing attack surface.",
			Severity:    models.SeverityCritical,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --security-opt seccomp=unconfined. Use Docker's default seccomp profile or create a custom restrictive profile.",
			References: []string{
				"https://docs.docker.com/engine/security/seccomp/",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"seccomp_status": "unconfined",
			},
		}
		findings = append(findings, finding)
	} else if !hasSeccomp {
		// No explicit seccomp configuration (using default or none)
		// Docker's default seccomp profile is applied unless disabled
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-SECCOMP-DEFAULT-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' using default seccomp profile", container.Name),
			Description: "Container is using Docker's default seccomp profile. Consider creating a custom seccomp profile tailored to your application's needs for better security.",
			Severity:    models.SeverityInfo,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Create a custom seccomp profile that allows only the syscalls your application needs. Use --security-opt seccomp=profile.json",
			References: []string{
				"https://docs.docker.com/engine/security/seccomp/",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"seccomp_status": "default",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkAppArmorProfile validates AppArmor/SELinux configuration
func (s *RuntimeScanner) checkAppArmorProfile(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	hasAppArmor := false
	hasSELinux := false
	isUnconfined := false

	// Parse SecurityOpt for AppArmor/SELinux profiles
	for _, opt := range container.SecurityOpt {
		if strings.HasPrefix(opt, "apparmor=") {
			hasAppArmor = true
			profile := strings.TrimPrefix(opt, "apparmor=")
			if profile == "unconfined" {
				isUnconfined = true
			}
		}
		if strings.HasPrefix(opt, "label=") || strings.HasPrefix(opt, "selinux") {
			hasSELinux = true
		}
	}

	// Check for unconfined AppArmor
	if isUnconfined {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-APPARMOR-UNCONFINED-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' running with AppArmor unconfined", container.Name),
			Description: "Container is running with AppArmor disabled (unconfined). This removes mandatory access control protections.",
			Severity:    models.SeverityHigh,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --security-opt apparmor=unconfined. Use Docker's default AppArmor profile or create a custom profile.",
			References: []string{
				"https://docs.docker.com/engine/security/apparmor/",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"apparmor":       "unconfined",
			},
		}
		findings = append(findings, finding)
	} else if !hasAppArmor && !hasSELinux {
		// No explicit MAC policy
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-MAC-NONE-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' has no explicit MAC policy", container.Name),
			Description: "Container does not have an explicit AppArmor or SELinux profile configured. Mandatory Access Control provides additional security hardening beyond standard Unix permissions.",
			Severity:    models.SeverityLow,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Apply AppArmor profile with --security-opt apparmor=profile or SELinux context with --security-opt label=level.",
			References: []string{
				"https://docs.docker.com/engine/security/apparmor/",
				"https://docs.docker.com/engine/security/selinux/",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkNamespaces checks namespace isolation configuration
func (s *RuntimeScanner) checkNamespaces(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	// Check PID namespace
	if container.PidMode == "host" {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-PID-HOST-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' shares host PID namespace", container.Name),
			Description: "Container is running with --pid=host which allows it to see and manipulate all processes on the host. This is extremely dangerous and can lead to privilege escalation.",
			Severity:    models.SeverityCritical,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --pid=host flag. Use isolated PID namespace (default behavior).",
			References: []string{
				"https://docs.docker.com/engine/reference/run/#pid-settings---pid",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"pid_mode":       "host",
			},
		}
		findings = append(findings, finding)
	}

	// Check IPC namespace
	if container.IpcMode == "host" {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-IPC-HOST-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' shares host IPC namespace", container.Name),
			Description: "Container is running with --ipc=host. Shared IPC allows inter-process communication with host processes, enabling potential information disclosure and privilege escalation.",
			Severity:    models.SeverityHigh,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --ipc=host flag. Use isolated IPC namespace (default).",
			References: []string{
				"https://docs.docker.com/engine/reference/run/#ipc-settings---ipc",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"ipc_mode":       "host",
			},
		}
		findings = append(findings, finding)
	}

	// Check Network namespace
	if container.NetworkMode == "host" {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-NET-HOST-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' shares host network namespace", container.Name),
			Description: "Container is running with --network=host. This removes network isolation and allows the container to bind to any host network interface, potentially exposing services and intercepting traffic.",
			Severity:    models.SeverityHigh,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --network=host flag. Use bridge or custom network for proper isolation.",
			References: []string{
				"https://docs.docker.com/engine/reference/run/#network-settings",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"network_mode":   "host",
			},
		}
		findings = append(findings, finding)
	}

	// Check User namespace
	if container.UsernsMode == "host" {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-USERNS-HOST-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' disabled user namespace remapping", container.Name),
			Description: "Container is running with --userns=host, which disables user namespace remapping. This means container root is the same as host root, removing an important isolation layer.",
			Severity:    models.SeverityMedium,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Remove --userns=host to enable user namespace remapping. Configure daemon-level user namespace remapping for better isolation.",
			References: []string{
				"https://docs.docker.com/engine/security/userns-remap/",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"userns_mode":    "host",
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkReadonlyRootfs checks if root filesystem is read-only
func (s *RuntimeScanner) checkReadonlyRootfs(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	if !container.ReadonlyRoot {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-ROOTFS-RW-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' has writable root filesystem", container.Name),
			Description: "Container's root filesystem is writable. Using read-only root filesystem prevents modifications to the container's filesystem, making it harder for attackers to persist malware or modify system files.",
			Severity:    models.SeverityLow,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Use --read-only flag to make root filesystem read-only. Mount specific volumes with write permissions only where needed using --tmpfs or -v flags.",
			References: []string{
				"https://docs.docker.com/engine/reference/run/#security-configuration",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"readonly_rootfs": false,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// checkSensitiveMounts checks for dangerous volume mounts
func (s *RuntimeScanner) checkSensitiveMounts(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	// Define sensitive paths that should not be mounted
	sensitivePaths := map[string]MountRisk{
		"/var/run/docker.sock": {
			Path:        "/var/run/docker.sock",
			Description: "Docker socket mounted. This allows full control over Docker daemon, enabling trivial container escape and host compromise.",
			Severity:    models.SeverityCritical,
			EscapeRisk:  true,
		},
		"/proc": {
			Path:        "/proc",
			Description: "/proc mounted. This exposes kernel and process information, can be used for information gathering and potential exploitation.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  true,
		},
		"/sys": {
			Path:        "/sys",
			Description: "/sys mounted. This exposes kernel interfaces and can be used to modify kernel parameters or access hardware information.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  true,
		},
		"/": {
			Path:        "/",
			Description: "Host root filesystem mounted. This provides full access to host files and can be used for privilege escalation.",
			Severity:    models.SeverityCritical,
			EscapeRisk:  true,
		},
		"/etc": {
			Path:        "/etc",
			Description: "Host /etc mounted. This provides access to system configuration files including passwords and SSH keys.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  false,
		},
		"/root": {
			Path:        "/root",
			Description: "Host root home directory mounted. This provides access to root user's files and SSH keys.",
			Severity:    models.SeverityHigh,
			EscapeRisk:  false,
		},
		"/boot": {
			Path:        "/boot",
			Description: "Host /boot mounted. This provides access to kernel and bootloader files.",
			Severity:    models.SeverityMedium,
			EscapeRisk:  false,
		},
	}

	// Check each mount
	for _, mount := range container.Mounts {
		// Check if source matches sensitive paths
		for _, risk := range sensitivePaths {
			if strings.HasPrefix(mount.Source, risk.Path) || mount.Destination == risk.Path {
				finding := models.Finding{
					ID:          fmt.Sprintf("RUNTIME-MOUNT-%s-%s", strings.ReplaceAll(risk.Path, "/", "-"), container.ID[:12]),
					Title:       fmt.Sprintf("Container '%s' has sensitive mount: %s", container.Name, risk.Path),
					Description: risk.Description,
					Severity:    risk.Severity,
					Category:    "Runtime-Security",
					Source:      "runtime-security",
					Remediation: fmt.Sprintf("Remove mount of %s. If absolutely necessary, mount as read-only using :ro suffix.", risk.Path),
					References: []string{
						"https://docs.docker.com/storage/bind-mounts/",
						"https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
					},
					Metadata: map[string]interface{}{
						"container_id":   container.ID,
						"container_name": container.Name,
						"mount_source":   mount.Source,
						"mount_dest":     mount.Destination,
						"mount_rw":       mount.RW,
						"escape_risk":    risk.EscapeRisk,
					},
				}
				findings = append(findings, finding)
				break
			}
		}
	}

	return findings
}

// checkUserConfig checks container user configuration
func (s *RuntimeScanner) checkUserConfig(container *docker.ContainerInfo) []models.Finding {
	var findings []models.Finding

	// Check if running as root
	if container.User == "" || container.User == "root" || container.User == "0" {
		finding := models.Finding{
			ID:          fmt.Sprintf("RUNTIME-USER-ROOT-%s", container.ID[:12]),
			Title:       fmt.Sprintf("Container '%s' running as root", container.Name),
			Description: "Container is running as root user (UID 0). If an attacker compromises the application, they will have root privileges inside the container, making privilege escalation easier.",
			Severity:    models.SeverityMedium,
			Category:    "Runtime-Security",
			Source:      "runtime-security",
			Remediation: "Run container as non-root user using --user flag or USER instruction in Dockerfile. Create a dedicated user with minimal privileges.",
			References: []string{
				"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
			},
			Metadata: map[string]interface{}{
				"container_id":   container.ID,
				"container_name": container.Name,
				"user":           container.User,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// CapabilityRisk describes a dangerous Linux capability
type CapabilityRisk struct {
	Name        string
	Description string
	Severity    models.Severity
	EscapeRisk  bool
}

// MountRisk describes a dangerous mount point
type MountRisk struct {
	Path        string
	Description string
	Severity    models.Severity
	EscapeRisk  bool
}
