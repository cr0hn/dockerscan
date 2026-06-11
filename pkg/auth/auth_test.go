package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetRegistryAuth_CLIPriority(t *testing.T) {
	// Test that CLI flags have highest priority
	tests := []struct {
		name          string
		imageName     string
		cliUser       string
		cliPass       string
		cliRegistry   string
		envUser       string
		envPass       string
		wantUsername  string
		wantPassword  string
		wantNil       bool
	}{
		{
			name:         "CLI auth for Docker Hub image",
			imageName:    "nginx:latest",
			cliUser:      "cli-user",
			cliPass:      "cli-pass",
			wantUsername: "cli-user",
			wantPassword: "cli-pass",
			wantNil:      false,
		},
		{
			name:         "CLI auth for GHCR image",
			imageName:    "ghcr.io/user/app:latest",
			cliUser:      "cli-user",
			cliPass:      "cli-pass",
			wantUsername: "cli-user",
			wantPassword: "cli-pass",
			wantNil:      false,
		},
		{
			name:         "CLI auth with specific registry match",
			imageName:    "ghcr.io/user/app:latest",
			cliUser:      "cli-user",
			cliPass:      "cli-pass",
			cliRegistry:  "ghcr.io",
			wantUsername: "cli-user",
			wantPassword: "cli-pass",
			wantNil:      false,
		},
		{
			name:        "CLI auth with registry mismatch falls back to env",
			imageName:   "ghcr.io/user/app:latest",
			cliUser:     "cli-user",
			cliPass:     "cli-pass",
			cliRegistry: "docker.io", // Wrong registry
			envUser:     "env-user",
			envPass:     "env-pass",
			wantUsername: "env-user",
			wantPassword: "env-pass",
			wantNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			if tt.envUser != "" {
				os.Setenv("DOCKER_USERNAME", tt.envUser)
				defer os.Unsetenv("DOCKER_USERNAME")
			}
			if tt.envPass != "" {
				os.Setenv("DOCKER_PASSWORD", tt.envPass)
				defer os.Unsetenv("DOCKER_PASSWORD")
			}

			authConfig := &AuthConfig{
				cliUser:     tt.cliUser,
				cliPassword: tt.cliPass,
				cliRegistry: tt.cliRegistry,
				envUser:     tt.envUser,
				envPassword: tt.envPass,
			}

			auth, err := authConfig.GetRegistryAuth(tt.imageName)
			if err != nil {
				t.Fatalf("GetRegistryAuth() error = %v", err)
			}

			if (auth == nil) != tt.wantNil {
				t.Errorf("GetRegistryAuth() auth == nil is %v, want %v", auth == nil, tt.wantNil)
				return
			}

			if !tt.wantNil {
				if auth.Username != tt.wantUsername {
					t.Errorf("GetRegistryAuth() Username = %v, want %v", auth.Username, tt.wantUsername)
				}
				if auth.Password != tt.wantPassword {
					t.Errorf("GetRegistryAuth() Password = %v, want %v", auth.Password, tt.wantPassword)
				}
			}
		})
	}
}

func TestGetRegistryAuth_EnvPriority(t *testing.T) {
	// Test that environment variables have second priority
	tests := []struct {
		name          string
		imageName     string
		envUser       string
		envPass       string
		envRegistry   string
		wantUsername  string
		wantPassword  string
		wantNil       bool
	}{
		{
			name:         "Env auth for Docker Hub",
			imageName:    "nginx:latest",
			envUser:      "env-user",
			envPass:      "env-pass",
			wantUsername: "env-user",
			wantPassword: "env-pass",
			wantNil:      false,
		},
		{
			name:         "Env auth for GHCR",
			imageName:    "ghcr.io/user/app:latest",
			envUser:      "env-user",
			envPass:      "env-pass",
			wantUsername: "env-user",
			wantPassword: "env-pass",
			wantNil:      false,
		},
		{
			name:         "Env auth with registry match",
			imageName:    "ghcr.io/user/app:latest",
			envUser:      "env-user",
			envPass:      "env-pass",
			envRegistry:  "ghcr.io",
			wantUsername: "env-user",
			wantPassword: "env-pass",
			wantNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			if tt.envUser != "" {
				os.Setenv("DOCKER_USERNAME", tt.envUser)
				defer os.Unsetenv("DOCKER_USERNAME")
			}
			if tt.envPass != "" {
				os.Setenv("DOCKER_PASSWORD", tt.envPass)
				defer os.Unsetenv("DOCKER_PASSWORD")
			}
			if tt.envRegistry != "" {
				os.Setenv("DOCKER_REGISTRY", tt.envRegistry)
				defer os.Unsetenv("DOCKER_REGISTRY")
			}

			authConfig := &AuthConfig{
				envUser:     tt.envUser,
				envPassword: tt.envPass,
				envRegistry: tt.envRegistry,
			}

			auth, err := authConfig.GetRegistryAuth(tt.imageName)
			if err != nil {
				t.Fatalf("GetRegistryAuth() error = %v", err)
			}

			if (auth == nil) != tt.wantNil {
				t.Errorf("GetRegistryAuth() auth == nil is %v, want %v", auth == nil, tt.wantNil)
				return
			}

			if !tt.wantNil {
				if auth.Username != tt.wantUsername {
					t.Errorf("GetRegistryAuth() Username = %v, want %v", auth.Username, tt.wantUsername)
				}
				if auth.Password != tt.wantPassword {
					t.Errorf("GetRegistryAuth() Password = %v, want %v", auth.Password, tt.wantPassword)
				}
			}
		})
	}
}

func TestGetRegistryAuth_ConfigFilePriority(t *testing.T) {
	// Load test config
	absPath, err := filepath.Abs("testdata/config_valid.json")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	dockerConfig, err := LoadDockerConfigFrom(absPath)
	if err != nil {
		t.Fatalf("LoadDockerConfigFrom() failed: %v", err)
	}

	tests := []struct {
		name         string
		imageName    string
		wantUsername string
		wantPassword string
		wantNil      bool
	}{
		{
			name:         "Docker Hub from config",
			imageName:    "nginx:latest",
			wantUsername: "user1",
			wantPassword: "pass1",
			wantNil:      false,
		},
		{
			name:         "GHCR from config",
			imageName:    "ghcr.io/user/app:latest",
			wantUsername: "user2",
			wantPassword: "pass2",
			wantNil:      false,
		},
		{
			name:         "Custom registry from config",
			imageName:    "myregistry.example.com/app:v1",
			wantUsername: "user3",
			wantPassword: "pass3",
			wantNil:      false,
		},
		{
			name:      "Unknown registry returns nil",
			imageName: "unknown.registry.io/app:latest",
			wantNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := &AuthConfig{
				dockerConfig: dockerConfig,
			}

			auth, err := authConfig.GetRegistryAuth(tt.imageName)
			if err != nil {
				t.Fatalf("GetRegistryAuth() error = %v", err)
			}

			if (auth == nil) != tt.wantNil {
				t.Errorf("GetRegistryAuth() auth == nil is %v, want %v", auth == nil, tt.wantNil)
				return
			}

			if !tt.wantNil {
				if auth.Username != tt.wantUsername {
					t.Errorf("GetRegistryAuth() Username = %v, want %v", auth.Username, tt.wantUsername)
				}
				if auth.Password != tt.wantPassword {
					t.Errorf("GetRegistryAuth() Password = %v, want %v", auth.Password, tt.wantPassword)
				}
			}
		})
	}
}

func TestGetRegistryAuth_RegistryTypes(t *testing.T) {
	// Test all major registry types
	tests := []struct {
		name      string
		imageName string
		cliUser   string
		cliPass   string
	}{
		{
			name:      "Docker Hub official",
			imageName: "nginx:latest",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
		{
			name:      "Docker Hub user image",
			imageName: "user/myapp:v1",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
		{
			name:      "GitHub Container Registry",
			imageName: "ghcr.io/owner/repo:tag",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
		{
			name:      "AWS ECR",
			imageName: "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest",
			cliUser:   "AWS",
			cliPass:   "testpass",
		},
		{
			name:      "Google Container Registry",
			imageName: "gcr.io/project-id/image:tag",
			cliUser:   "_json_key",
			cliPass:   "testpass",
		},
		{
			name:      "Google Artifact Registry",
			imageName: "us-docker.pkg.dev/project/repo/image:tag",
			cliUser:   "_json_key",
			cliPass:   "testpass",
		},
		{
			name:      "Azure Container Registry",
			imageName: "myregistry.azurecr.io/myapp:v1",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
		{
			name:      "Quay.io",
			imageName: "quay.io/organization/image:tag",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
		{
			name:      "GitLab Container Registry",
			imageName: "registry.gitlab.com/group/project:tag",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
		{
			name:      "Private registry with port",
			imageName: "myregistry.example.com:5000/app:latest",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
		{
			name:      "Localhost registry",
			imageName: "localhost:5000/test:latest",
			cliUser:   "testuser",
			cliPass:   "testpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := &AuthConfig{
				cliUser:     tt.cliUser,
				cliPassword: tt.cliPass,
			}

			auth, err := authConfig.GetRegistryAuth(tt.imageName)
			if err != nil {
				t.Fatalf("GetRegistryAuth() error = %v", err)
			}

			if auth == nil {
				t.Fatal("GetRegistryAuth() returned nil")
			}

			if auth.Username != tt.cliUser {
				t.Errorf("GetRegistryAuth() Username = %v, want %v", auth.Username, tt.cliUser)
			}
			if auth.Password != tt.cliPass {
				t.Errorf("GetRegistryAuth() Password = %v, want %v", auth.Password, tt.cliPass)
			}
		})
	}
}

func TestGetRegistryAuth_DockerHubAliases(t *testing.T) {
	// Load test config
	absPath, err := filepath.Abs("testdata/config_valid.json")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	dockerConfig, err := LoadDockerConfigFrom(absPath)
	if err != nil {
		t.Fatalf("LoadDockerConfigFrom() failed: %v", err)
	}

	// All these images should use the same Docker Hub credentials
	tests := []struct {
		name      string
		imageName string
	}{
		{
			name:      "nginx without prefix",
			imageName: "nginx:latest",
		},
		{
			name:      "library/nginx",
			imageName: "library/nginx:latest",
		},
		{
			name:      "user image",
			imageName: "user/myapp:v1",
		},
		{
			name:      "docker.io explicit",
			imageName: "docker.io/nginx:latest",
		},
		{
			name:      "index.docker.io explicit",
			imageName: "index.docker.io/nginx:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := &AuthConfig{
				dockerConfig: dockerConfig,
			}

			auth, err := authConfig.GetRegistryAuth(tt.imageName)
			if err != nil {
				t.Fatalf("GetRegistryAuth() error = %v", err)
			}

			if auth == nil {
				t.Fatal("GetRegistryAuth() returned nil for Docker Hub image")
			}

			// All should resolve to the same credentials
			if auth.Username != "user1" {
				t.Errorf("GetRegistryAuth() Username = %v, want user1", auth.Username)
			}
			if auth.Password != "pass1" {
				t.Errorf("GetRegistryAuth() Password = %v, want pass1", auth.Password)
			}
		})
	}
}

func TestGetRegistryAuth_NoAuth(t *testing.T) {
	// Test that public registries work without auth
	tests := []struct {
		name      string
		imageName string
	}{
		{
			name:      "Docker Hub public",
			imageName: "nginx:latest",
		},
		{
			name:      "GHCR public",
			imageName: "ghcr.io/some/public:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := &AuthConfig{
				// No credentials provided
			}

			auth, err := authConfig.GetRegistryAuth(tt.imageName)
			if err != nil {
				t.Fatalf("GetRegistryAuth() error = %v", err)
			}

			// Should return nil (not an error)
			if auth != nil {
				t.Errorf("GetRegistryAuth() should return nil for public registry without auth, got: %v", auth)
			}
		})
	}
}

func TestNewAuthConfig(t *testing.T) {
	// Test NewAuthConfig loading
	tests := []struct {
		name        string
		cliUser     string
		cliPass     string
		cliRegistry string
		envUser     string
		envPass     string
		envRegistry string
	}{
		{
			name:        "CLI only",
			cliUser:     "cli-user",
			cliPass:     "cli-pass",
			cliRegistry: "ghcr.io",
		},
		{
			name:        "Env only",
			envUser:     "env-user",
			envPass:     "env-pass",
			envRegistry: "docker.io",
		},
		{
			name:        "Both CLI and Env (CLI takes priority)",
			cliUser:     "cli-user",
			cliPass:     "cli-pass",
			envUser:     "env-user",
			envPass:     "env-pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			if tt.envUser != "" {
				os.Setenv("DOCKER_USERNAME", tt.envUser)
				defer os.Unsetenv("DOCKER_USERNAME")
			}
			if tt.envPass != "" {
				os.Setenv("DOCKER_PASSWORD", tt.envPass)
				defer os.Unsetenv("DOCKER_PASSWORD")
			}
			if tt.envRegistry != "" {
				os.Setenv("DOCKER_REGISTRY", tt.envRegistry)
				defer os.Unsetenv("DOCKER_REGISTRY")
			}

			authConfig, err := NewAuthConfig(tt.cliUser, tt.cliPass, tt.cliRegistry)
			if err != nil {
				t.Fatalf("NewAuthConfig() error = %v", err)
			}

			if authConfig == nil {
				t.Fatal("NewAuthConfig() returned nil")
			}

			// Verify CLI values
			if authConfig.cliUser != tt.cliUser {
				t.Errorf("NewAuthConfig() cliUser = %v, want %v", authConfig.cliUser, tt.cliUser)
			}
			if authConfig.cliPassword != tt.cliPass {
				t.Errorf("NewAuthConfig() cliPassword = %v, want %v", authConfig.cliPassword, tt.cliPass)
			}

			// Verify Env values
			if authConfig.envUser != tt.envUser {
				t.Errorf("NewAuthConfig() envUser = %v, want %v", authConfig.envUser, tt.envUser)
			}
			if authConfig.envPassword != tt.envPass {
				t.Errorf("NewAuthConfig() envPassword = %v, want %v", authConfig.envPassword, tt.envPass)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isValidCredStoreName
// ---------------------------------------------------------------------------

func TestIsValidCredStoreName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty string", input: "", want: false},
		{name: "osxkeychain", input: "osxkeychain", want: true},
		{name: "desktop", input: "desktop", want: true},
		{name: "alphanumeric with hyphen and underscore", input: "my-helper_2", want: true},
		{name: "path traversal dots-slash", input: "../../tmp/evil", want: false},
		{name: "space in name", input: "hello world", want: false},
		{name: "semicolon injection", input: "helper;evil", want: false},
		{name: "uppercase and digits", input: "UPPER123", want: true},
		// hyphens and underscores are allowed chars; a non-empty string of them is valid
		{name: "only hyphens and underscores", input: "-_-", want: true},
		{name: "single letter", input: "a", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidCredStoreName(tt.input)
			if got != tt.want {
				t.Errorf("isValidCredStoreName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helperServerURL
// ---------------------------------------------------------------------------

func TestHelperServerURL(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		want     string
	}{
		{
			name:     "index.docker.io returns canonical Docker Hub URL",
			registry: "index.docker.io",
			want:     "https://index.docker.io/v1/",
		},
		{
			name:     "docker.io alias returns canonical Docker Hub URL",
			registry: "docker.io",
			want:     "https://index.docker.io/v1/",
		},
		{
			name:     "registry-1.docker.io alias returns canonical Docker Hub URL",
			registry: "registry-1.docker.io",
			want:     "https://index.docker.io/v1/",
		},
		{
			name:     "ghcr.io is returned unchanged",
			registry: "ghcr.io",
			want:     "ghcr.io",
		},
		{
			name:     "private registry with port is returned unchanged",
			registry: "myregistry.example.com:5000",
			want:     "myregistry.example.com:5000",
		},
		{
			name:     "gcr.io is returned unchanged",
			registry: "gcr.io",
			want:     "gcr.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := helperServerURL(tt.registry)
			if got != tt.want {
				t.Errorf("helperServerURL(%q) = %q, want %q", tt.registry, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getFromDockerConfig — priority A → B → C fallback logic
// ---------------------------------------------------------------------------

func TestGetFromDockerConfig_Priority(t *testing.T) {
	// A nonexistent helper binary name that will never be found in PATH.
	const missingHelper = "docker-credential-nonexistent-xxxyyy"
	const missingHelperName = "nonexistent-xxxyyy"

	_ = missingHelper // referenced only for documentation clarity

	tests := []struct {
		name        string
		dockerCfg   *DockerConfig
		registry    string
		wantNil     bool
		wantErr     bool
		wantUser    string
		wantPass    string
	}{
		{
			name: "credHelpers entry with absent binary falls back to auths",
			dockerCfg: &DockerConfig{
				CredHelpers: map[string]string{
					"ghcr.io": missingHelperName,
				},
				Auths: map[string]AuthEntry{
					"ghcr.io": {Username: "authuser", Password: "authpass"},
				},
			},
			registry: "ghcr.io",
			wantNil:  false,
			wantUser: "authuser",
			wantPass: "authpass",
		},
		{
			name: "credStore with absent binary falls back to auths",
			dockerCfg: &DockerConfig{
				CredStore: missingHelperName,
				Auths: map[string]AuthEntry{
					"ghcr.io": {Username: "storeuser", Password: "storepass"},
				},
			},
			registry: "ghcr.io",
			wantNil:  false,
			wantUser: "storeuser",
			wantPass: "storepass",
		},
		{
			name: "both helpers absent and auths empty returns nil",
			dockerCfg: &DockerConfig{
				CredHelpers: map[string]string{
					"ghcr.io": missingHelperName,
				},
				CredStore: missingHelperName,
				Auths:     map[string]AuthEntry{},
			},
			registry: "ghcr.io",
			wantNil:  true,
		},
		{
			name: "nil dockerConfig returns nil without error",
			dockerCfg: nil,
			registry:  "ghcr.io",
			wantNil:   true,
		},
		{
			name: "no helpers configured uses auths directly",
			dockerCfg: &DockerConfig{
				Auths: map[string]AuthEntry{
					"myregistry.example.com": {Username: "u", Password: "p"},
				},
			},
			registry: "myregistry.example.com",
			wantNil:  false,
			wantUser: "u",
			wantPass: "p",
		},
		{
			name: "all sources empty returns nil",
			dockerCfg: &DockerConfig{
				Auths: map[string]AuthEntry{},
			},
			registry: "unknown.registry.io",
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthConfig{
				dockerConfig: tt.dockerCfg,
			}

			auth, err := ac.getFromDockerConfig(nil, tt.registry) //nolint:staticcheck
			if (err != nil) != tt.wantErr {
				t.Fatalf("getFromDockerConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (auth == nil) != tt.wantNil {
				t.Fatalf("getFromDockerConfig() auth == nil is %v, want %v", auth == nil, tt.wantNil)
			}
			if !tt.wantNil && auth != nil {
				if auth.Username != tt.wantUser {
					t.Errorf("Username = %q, want %q", auth.Username, tt.wantUser)
				}
				if auth.Password != tt.wantPass {
					t.Errorf("Password = %q, want %q", auth.Password, tt.wantPass)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// getFromCredHelper — input validation
// ---------------------------------------------------------------------------

func TestGetFromCredHelper_Validation(t *testing.T) {
	tests := []struct {
		name           string
		credStoreName  string
		wantNil        bool
		wantErr        bool
	}{
		{
			name:          "path traversal rejected with error",
			credStoreName: "../../evil",
			wantNil:       true,
			wantErr:       true,
		},
		{
			name:          "empty name rejected with error",
			credStoreName: "",
			wantNil:       true,
			wantErr:       true,
		},
		{
			name:          "binary not in PATH returns nil nil (silent fallback)",
			credStoreName: "nonexistent-helper-xxxyyy",
			wantNil:       true,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := getFromCredHelper(nil, tt.credStoreName, "ghcr.io", "ghcr.io") //nolint:staticcheck
			if (err != nil) != tt.wantErr {
				t.Fatalf("getFromCredHelper() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (auth == nil) != tt.wantNil {
				t.Errorf("getFromCredHelper() auth == nil is %v, want %v", auth == nil, tt.wantNil)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestToDockerAuthConfig (pre-existing — kept below)
// ---------------------------------------------------------------------------

func TestToDockerAuthConfig(t *testing.T) {
	tests := []struct {
		name string
		auth *RegistryAuth
	}{
		{
			name: "complete auth",
			auth: &RegistryAuth{
				Username:      "testuser",
				Password:      "testpass",
				Registry:      "ghcr.io",
				ServerAddress: "ghcr.io",
			},
		},
		{
			name: "auth with identity token",
			auth: &RegistryAuth{
				Username:      "testuser",
				IdentityToken: "token123",
				Registry:      "gcr.io",
			},
		},
		{
			name: "nil auth",
			auth: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dockerAuth := tt.auth.ToDockerAuthConfig()

			if tt.auth == nil {
				// Should return empty config
				if dockerAuth.Username != "" || dockerAuth.Password != "" {
					t.Errorf("ToDockerAuthConfig() with nil should return empty config")
				}
			} else {
				if dockerAuth.Username != tt.auth.Username {
					t.Errorf("ToDockerAuthConfig() Username = %v, want %v", dockerAuth.Username, tt.auth.Username)
				}
				if dockerAuth.Password != tt.auth.Password {
					t.Errorf("ToDockerAuthConfig() Password = %v, want %v", dockerAuth.Password, tt.auth.Password)
				}
			}
		})
	}
}
