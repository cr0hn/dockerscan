package runtime

import (
	"strings"
	"testing"

	"github.com/cr0hn/dockerscan/v2/internal/models"
	"github.com/cr0hn/dockerscan/v2/pkg/docker"
)

// makeContainer returns a ContainerInfo with the minimum fields required so
// that ID[:12] slicing (used throughout the scanner) never panics.
func makeContainer(id, name string) *docker.ContainerInfo {
	if len(id) < 12 {
		// Pad to at least 12 chars
		id = id + strings.Repeat("0", 12-len(id))
	}
	return &docker.ContainerInfo{
		ID:   id,
		Name: name,
	}
}

// --- Basic scanner metadata ---

func TestNewRuntimeScanner_Name(t *testing.T) {
	s := NewRuntimeScanner(nil)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.Name() != "runtime-security" {
		t.Errorf("expected name 'runtime-security', got %q", s.Name())
	}
}

func TestNewRuntimeScanner_Enabled(t *testing.T) {
	s := NewRuntimeScanner(nil)
	if !s.Enabled() {
		t.Error("expected scanner to be enabled by default")
	}
}

// --- checkPrivilegedMode ---

func TestCheckPrivilegedMode(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name           string
		privileged     bool
		wantFindingID  string
		wantSeverity   models.Severity
		wantFindings   bool
	}{
		{
			name:         "privileged container triggers CRITICAL finding",
			privileged:   true,
			wantFindingID: "RUNTIME-PRIV-001",
			wantSeverity:  models.SeverityCritical,
			wantFindings:  true,
		},
		{
			name:         "non-privileged container has no finding",
			privileged:   false,
			wantFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("abc123def456ffff", "test-container")
			c.Privileged = tt.privileged

			findings := s.checkPrivilegedMode(c)

			if tt.wantFindings && len(findings) == 0 {
				t.Fatal("expected at least one finding, got none")
			}
			if !tt.wantFindings && len(findings) > 0 {
				t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
			}

			if tt.wantFindings {
				found := false
				for _, f := range findings {
					if strings.Contains(f.ID, tt.wantFindingID) {
						found = true
						if f.Severity != tt.wantSeverity {
							t.Errorf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
						}
						if f.Source != "runtime-security" {
							t.Errorf("expected source 'runtime-security', got %q", f.Source)
						}
					}
				}
				if !found {
					t.Errorf("expected finding with ID containing %q, got %+v", tt.wantFindingID, findings)
				}
			}
		})
	}
}

// --- checkCapabilities ---

func TestCheckCapabilities_DangerousCapabilities(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name         string
		capAdd       []string
		wantSeverity models.Severity
		wantFound    bool
	}{
		{
			name:         "CAP_SYS_ADMIN triggers CRITICAL",
			capAdd:       []string{"CAP_SYS_ADMIN"},
			wantSeverity: models.SeverityCritical,
			wantFound:    true,
		},
		{
			name:         "SYS_ADMIN without prefix also triggers CRITICAL",
			capAdd:       []string{"SYS_ADMIN"},
			wantSeverity: models.SeverityCritical,
			wantFound:    true,
		},
		{
			name:         "CAP_SYS_MODULE triggers CRITICAL",
			capAdd:       []string{"CAP_SYS_MODULE"},
			wantSeverity: models.SeverityCritical,
			wantFound:    true,
		},
		{
			name:         "CAP_SYS_PTRACE triggers HIGH",
			capAdd:       []string{"CAP_SYS_PTRACE"},
			wantSeverity: models.SeverityHigh,
			wantFound:    true,
		},
		{
			name:         "CAP_NET_ADMIN triggers MEDIUM",
			capAdd:       []string{"CAP_NET_ADMIN"},
			wantSeverity: models.SeverityMedium,
			wantFound:    true,
		},
		{
			name:      "safe capability produces no dangerous-cap finding",
			capAdd:    []string{"CAP_CHOWN"},
			wantFound: false,
		},
		{
			name:      "empty capAdd produces no dangerous-cap finding",
			capAdd:    []string{},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("aabbccddeeff1111", "cap-test")
			c.CapAdd = tt.capAdd
			// Set CapDrop to something so we don't add the "no drop" finding noise
			c.CapDrop = []string{"ALL"}

			findings := s.checkCapabilities(c)

			// Filter to only dangerous-cap findings (not the nodrop info)
			var capFindings []models.Finding
			for _, f := range findings {
				if strings.Contains(f.ID, "RUNTIME-CAP-") && !strings.Contains(f.ID, "NODROP") {
					capFindings = append(capFindings, f)
				}
			}

			if tt.wantFound && len(capFindings) == 0 {
				t.Fatalf("expected capability finding, got none (all findings: %+v)", findings)
			}
			if !tt.wantFound && len(capFindings) > 0 {
				t.Fatalf("expected no dangerous-cap findings, got %d: %+v", len(capFindings), capFindings)
			}

			if tt.wantFound {
				if capFindings[0].Severity != tt.wantSeverity {
					t.Errorf("expected severity %s, got %s", tt.wantSeverity, capFindings[0].Severity)
				}
				if capFindings[0].Source != "runtime-security" {
					t.Errorf("expected source 'runtime-security', got %q", capFindings[0].Source)
				}
			}
		})
	}
}

func TestCheckCapabilities_NoDropWarning(t *testing.T) {
	s := NewRuntimeScanner(nil)

	// A non-privileged container that drops nothing should get the nodrop finding
	c := makeContainer("deadbeef000011112222", "nodrop-test")
	c.CapDrop = nil
	c.Privileged = false

	findings := s.checkCapabilities(c)

	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "NODROP") {
			found = true
			if f.Severity != models.SeverityLow {
				t.Errorf("expected LOW severity for no-drop finding, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected NODROP finding when no capabilities are dropped")
	}
}

func TestCheckCapabilities_PrivilegedNoNodrop(t *testing.T) {
	s := NewRuntimeScanner(nil)

	// Privileged containers should NOT get the nodrop low-severity finding
	c := makeContainer("ffffffff000011112222", "priv-test")
	c.CapDrop = nil
	c.Privileged = true

	findings := s.checkCapabilities(c)
	for _, f := range findings {
		if strings.Contains(f.ID, "NODROP") {
			t.Error("privileged container should not produce NODROP finding")
		}
	}
}

// --- checkSeccompProfile ---

func TestCheckSeccompProfile(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name          string
		securityOpts  []string
		wantID        string
		wantSeverity  models.Severity
	}{
		{
			name:         "unconfined seccomp triggers CRITICAL",
			securityOpts: []string{"seccomp=unconfined"},
			wantID:       "RUNTIME-SECCOMP-UNCONFINED",
			wantSeverity: models.SeverityCritical,
		},
		{
			name:         "no explicit seccomp produces INFO default finding",
			securityOpts: []string{},
			wantID:       "RUNTIME-SECCOMP-DEFAULT",
			wantSeverity: models.SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("1234567890ab1234", "seccomp-test")
			c.SecurityOpt = tt.securityOpts

			findings := s.checkSeccompProfile(c)
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}

			found := false
			for _, f := range findings {
				if strings.Contains(f.ID, tt.wantID) {
					found = true
					if f.Severity != tt.wantSeverity {
						t.Errorf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
					}
				}
			}
			if !found {
				t.Errorf("expected finding with ID containing %q, got %+v", tt.wantID, findings)
			}
		})
	}
}

// --- checkNamespaces ---

func TestCheckNamespaces(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name         string
		pidMode      string
		ipcMode      string
		networkMode  string
		usernsMode   string
		wantID       string
		wantSeverity models.Severity
	}{
		{
			name:         "host PID namespace triggers CRITICAL",
			pidMode:      "host",
			wantID:       "RUNTIME-PID-HOST",
			wantSeverity: models.SeverityCritical,
		},
		{
			name:         "host IPC namespace triggers HIGH",
			ipcMode:      "host",
			wantID:       "RUNTIME-IPC-HOST",
			wantSeverity: models.SeverityHigh,
		},
		{
			name:         "host network namespace triggers HIGH",
			networkMode:  "host",
			wantID:       "RUNTIME-NET-HOST",
			wantSeverity: models.SeverityHigh,
		},
		{
			name:         "host userns triggers MEDIUM",
			usernsMode:   "host",
			wantID:       "RUNTIME-USERNS-HOST",
			wantSeverity: models.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("aabbccddeeff0011", "ns-test")
			c.PidMode = tt.pidMode
			c.IpcMode = tt.ipcMode
			c.NetworkMode = tt.networkMode
			c.UsernsMode = tt.usernsMode

			findings := s.checkNamespaces(c)
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}

			found := false
			for _, f := range findings {
				if strings.Contains(f.ID, tt.wantID) {
					found = true
					if f.Severity != tt.wantSeverity {
						t.Errorf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
					}
				}
			}
			if !found {
				t.Errorf("expected finding with ID containing %q, got %+v", tt.wantID, findings)
			}
		})
	}
}

func TestCheckNamespaces_NoIssues(t *testing.T) {
	s := NewRuntimeScanner(nil)

	c := makeContainer("aabbccddeeff0022", "ns-safe")
	// All namespace modes left empty (not "host")

	findings := s.checkNamespaces(c)
	if len(findings) != 0 {
		t.Errorf("expected no namespace findings for a safe container, got %d: %+v", len(findings), findings)
	}
}

// --- checkReadonlyRootfs ---

func TestCheckReadonlyRootfs(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name         string
		readOnly     bool
		wantFindings bool
		wantSeverity models.Severity
	}{
		{
			name:         "writable rootfs produces LOW finding",
			readOnly:     false,
			wantFindings: true,
			wantSeverity: models.SeverityLow,
		},
		{
			name:         "read-only rootfs produces no finding",
			readOnly:     true,
			wantFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("ccddaabb11223344", "rootfs-test")
			c.ReadonlyRoot = tt.readOnly

			findings := s.checkReadonlyRootfs(c)

			if tt.wantFindings && len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			if !tt.wantFindings && len(findings) > 0 {
				t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
			}

			if tt.wantFindings && findings[0].Severity != tt.wantSeverity {
				t.Errorf("expected severity %s, got %s", tt.wantSeverity, findings[0].Severity)
			}
		})
	}
}

// --- checkSensitiveMounts ---

func TestCheckSensitiveMounts(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name         string
		mounts       []docker.MountInfo
		wantFindings bool
		wantSeverity models.Severity
	}{
		{
			name: "docker socket mount triggers CRITICAL",
			mounts: []docker.MountInfo{
				{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: true},
			},
			wantFindings: true,
			wantSeverity: models.SeverityCritical,
		},
		{
			name: "host root mount triggers CRITICAL",
			mounts: []docker.MountInfo{
				{Source: "/", Destination: "/host", RW: true},
			},
			wantFindings: true,
			wantSeverity: models.SeverityCritical,
		},
		{
			name: "/proc mount triggers HIGH",
			mounts: []docker.MountInfo{
				{Source: "/proc", Destination: "/host-proc", RW: false},
			},
			wantFindings: true,
			wantSeverity: models.SeverityHigh,
		},
		{
			name: "/etc mount triggers HIGH",
			mounts: []docker.MountInfo{
				{Source: "/etc", Destination: "/host-etc", RW: true},
			},
			wantFindings: true,
			wantSeverity: models.SeverityHigh,
		},
		{
			name: "regular data volume has no findings",
			mounts: []docker.MountInfo{
				{Source: "/var/lib/docker/volumes/myapp/_data", Destination: "/data", RW: true},
			},
			wantFindings: false,
		},
		{
			name:         "no mounts has no findings",
			mounts:       []docker.MountInfo{},
			wantFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("11223344aabbccdd", "mount-test")
			c.Mounts = tt.mounts

			findings := s.checkSensitiveMounts(c)

			if tt.wantFindings && len(findings) == 0 {
				t.Fatalf("expected at least one finding, got none")
			}
			if !tt.wantFindings && len(findings) > 0 {
				t.Fatalf("expected no findings, got %d: %+v", len(findings), findings)
			}

			if tt.wantFindings && findings[0].Severity != tt.wantSeverity {
				t.Errorf("expected severity %s, got %s", tt.wantSeverity, findings[0].Severity)
			}
		})
	}
}

// --- checkUserConfig ---

func TestCheckUserConfig(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name         string
		user         string
		wantFindings bool
		wantSeverity models.Severity
	}{
		{
			name:         "empty user (defaults to root) triggers HIGH",
			user:         "",
			wantFindings: true,
			wantSeverity: models.SeverityHigh,
		},
		{
			name:         "explicit root user triggers HIGH",
			user:         "root",
			wantFindings: true,
			wantSeverity: models.SeverityHigh,
		},
		{
			name:         "UID 0 triggers HIGH",
			user:         "0",
			wantFindings: true,
			wantSeverity: models.SeverityHigh,
		},
		{
			name:         "non-root user has no findings",
			user:         "appuser",
			wantFindings: false,
		},
		{
			name:         "UID 1000 has no findings",
			user:         "1000",
			wantFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("abcdef1234567890", "user-test")
			c.User = tt.user

			findings := s.checkUserConfig(c)

			if tt.wantFindings && len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			if !tt.wantFindings && len(findings) > 0 {
				t.Fatalf("expected no findings for user %q, got %d: %+v", tt.user, len(findings), findings)
			}

			if tt.wantFindings {
				f := findings[0]
				if f.Severity != tt.wantSeverity {
					t.Errorf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
				}
				if f.Source != "runtime-security" {
					t.Errorf("expected source 'runtime-security', got %q", f.Source)
				}
			}
		})
	}
}

// --- checkAppArmorProfile ---

func TestCheckAppArmorProfile(t *testing.T) {
	s := NewRuntimeScanner(nil)

	tests := []struct {
		name         string
		securityOpts []string
		wantID       string
		wantSeverity models.Severity
	}{
		{
			name:         "apparmor=unconfined triggers HIGH",
			securityOpts: []string{"apparmor=unconfined"},
			wantID:       "RUNTIME-APPARMOR-UNCONFINED",
			wantSeverity: models.SeverityHigh,
		},
		{
			name:         "no MAC policy produces LOW finding",
			securityOpts: []string{},
			wantID:       "RUNTIME-MAC-NONE",
			wantSeverity: models.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := makeContainer("aabb1122ccdd3344", "apparmor-test")
			c.SecurityOpt = tt.securityOpts

			findings := s.checkAppArmorProfile(c)
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}

			found := false
			for _, f := range findings {
				if strings.Contains(f.ID, tt.wantID) {
					found = true
					if f.Severity != tt.wantSeverity {
						t.Errorf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
					}
				}
			}
			if !found {
				t.Errorf("expected finding with ID containing %q, got %+v", tt.wantID, findings)
			}
		})
	}
}

func TestCheckAppArmorProfile_WithSELinux(t *testing.T) {
	s := NewRuntimeScanner(nil)

	// A container with SELinux label should not get the no-MAC finding
	c := makeContainer("eeff112233445566", "selinux-test")
	c.SecurityOpt = []string{"label=level:s0:c123,c456"}

	findings := s.checkAppArmorProfile(c)
	for _, f := range findings {
		if strings.Contains(f.ID, "RUNTIME-MAC-NONE") {
			t.Error("should not report MAC-NONE when SELinux label is configured")
		}
	}
}
