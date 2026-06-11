package auth

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/docker/docker-credential-helpers/client"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/docker/docker/api/types/registry"
)

// RegistryAuth contains authentication credentials for a specific registry
type RegistryAuth struct {
	Username      string // Username for authentication
	Password      string // Password or token for authentication
	Registry      string // Registry hostname (e.g., "ghcr.io")
	ServerAddress string // Full server address (for Docker SDK)
	IdentityToken string // OAuth2 identity token (optional)
}

// AuthConfig holds all authentication configuration sources
type AuthConfig struct {
	cliUser      string        // Username from CLI flag
	cliPassword  string        // Password from CLI flag
	cliRegistry  string        // Registry from CLI flag
	envUser      string        // Username from environment variable
	envPassword  string        // Password from environment variable
	envRegistry  string        // Registry from environment variable
	dockerConfig *DockerConfig // Loaded from ~/.docker/config.json
}

// NewAuthConfig creates a new AuthConfig by loading from all sources
// Priority: CLI flags > Environment variables > Docker config file
//
// CLI parameters:
//   - cliUser: Username from --registry-user flag
//   - cliPass: Password from --registry-password flag
//   - cliRegistry: Registry from --registry flag
//
// Environment variables:
//   - DOCKER_USERNAME or REGISTRY_USERNAME
//   - DOCKER_PASSWORD or REGISTRY_PASSWORD
//   - DOCKER_REGISTRY or REGISTRY
//
// Docker config file:
//   - ~/.docker/config.json (or custom path via dockerConfigPath)
func NewAuthConfig(cliUser, cliPass, cliRegistry string) (*AuthConfig, error) {
	// Load environment variables
	envUser := os.Getenv("DOCKER_USERNAME")
	if envUser == "" {
		envUser = os.Getenv("REGISTRY_USERNAME")
	}

	envPassword := os.Getenv("DOCKER_PASSWORD")
	if envPassword == "" {
		envPassword = os.Getenv("REGISTRY_PASSWORD")
	}

	envRegistry := os.Getenv("DOCKER_REGISTRY")
	if envRegistry == "" {
		envRegistry = os.Getenv("REGISTRY")
	}

	// Load Docker config file
	dockerConfig, err := LoadDockerConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Docker config: %w", err)
	}

	return &AuthConfig{
		cliUser:      cliUser,
		cliPassword:  cliPass,
		cliRegistry:  cliRegistry,
		envUser:      envUser,
		envPassword:  envPassword,
		envRegistry:  envRegistry,
		dockerConfig: dockerConfig,
	}, nil
}

// GetRegistryAuth returns authentication for a specific image
// Priority: CLI > Environment > Docker config file
// Returns nil if no authentication is found (public registry)
func (ac *AuthConfig) GetRegistryAuth(imageName string) (*RegistryAuth, error) {
	return ac.GetRegistryAuthContext(context.Background(), imageName)
}

// GetRegistryAuthContext returns authentication for a specific image with context support.
// Priority: CLI > Environment > Docker config file
// Returns nil if no authentication is found (public registry)
func (ac *AuthConfig) GetRegistryAuthContext(ctx context.Context, imageName string) (*RegistryAuth, error) {
	// Extract registry from image name
	reg, err := ExtractRegistry(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract registry from image %q: %w", imageName, err)
	}

	// Normalize registry name
	reg = NormalizeRegistry(reg)

	// Priority 1: CLI flags (highest priority)
	if ac.cliUser != "" && ac.cliPassword != "" {
		// If CLI registry is specified, it must match
		if ac.cliRegistry != "" {
			cliReg := NormalizeRegistry(ac.cliRegistry)
			if cliReg != reg {
				// CLI registry doesn't match - try other sources
				return ac.getFromEnvOrConfig(ctx, reg)
			}
		}

		return &RegistryAuth{
			Username:      ac.cliUser,
			Password:      ac.cliPassword,
			Registry:      reg,
			ServerAddress: reg,
		}, nil
	}

	return ac.getFromEnvOrConfig(ctx, reg)
}

// getFromEnvOrConfig tries environment variables and then Docker config
func (ac *AuthConfig) getFromEnvOrConfig(ctx context.Context, reg string) (*RegistryAuth, error) {
	// Priority 2: Environment variables
	if ac.envUser != "" && ac.envPassword != "" {
		// If env registry is specified, it must match
		if ac.envRegistry != "" {
			envReg := NormalizeRegistry(ac.envRegistry)
			if envReg != reg {
				// Env registry doesn't match - try config file
				return ac.getFromDockerConfig(ctx, reg)
			}
		}

		return &RegistryAuth{
			Username:      ac.envUser,
			Password:      ac.envPassword,
			Registry:      reg,
			ServerAddress: reg,
		}, nil
	}

	// Priority 3: Docker config file (lowest priority)
	return ac.getFromDockerConfig(ctx, reg)
}

// getFromDockerConfig searches for credentials in ~/.docker/config.json.
// It first tries any configured credential helpers (per-registry or global),
// then falls back to the plain credentials stored in the auths section.
func (ac *AuthConfig) getFromDockerConfig(ctx context.Context, reg string) (*RegistryAuth, error) {
	if ac.dockerConfig == nil {
		// No Docker config available - return nil (not an error)
		return nil, nil
	}

	// Priority A: Per-registry credential helper (credHelpers map)
	if ac.dockerConfig.CredHelpers != nil {
		// Build list of keys to try, including Docker Hub aliases
		keysToTry := []string{reg}
		if IsDockerHub(reg) {
			keysToTry = append(keysToTry, "docker.io", "registry-1.docker.io", "index.docker.io")
		}
		for _, key := range keysToTry {
			if helperName, ok := ac.dockerConfig.CredHelpers[key]; ok {
				auth, err := getFromCredHelper(ctx, helperName, reg, helperServerURL(reg))
				if err != nil {
					return nil, err
				}
				if auth != nil {
					return auth, nil
				}
				// Helper returned no credentials — fall through to auths
				break
			}
		}
	}

	// Priority B: Global credential helper (credsStore)
	if ac.dockerConfig.CredStore != "" {
		auth, err := getFromCredHelper(ctx, ac.dockerConfig.CredStore, reg, helperServerURL(reg))
		if err != nil {
			return nil, err
		}
		if auth != nil {
			return auth, nil
		}
		// Helper returned no credentials — fall through to auths
	}

	// Priority C: Plain credentials stored in auths section
	if ac.dockerConfig.Auths == nil {
		return nil, nil
	}

	// Try to find auth entry in config
	authEntry := ac.findAuthInConfig(reg)
	if authEntry == nil {
		// No auth found - return nil (not an error)
		return nil, nil
	}

	// Decode base64 auth if present
	username := authEntry.Username
	password := authEntry.Password
	if authEntry.Auth != "" {
		var err error
		username, password, err = DecodeAuth(authEntry.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to decode auth for registry %q: %w", reg, err)
		}
	}

	// Use identity token if available
	identityToken := authEntry.IdentityToken

	return &RegistryAuth{
		Username:      username,
		Password:      password,
		Registry:      reg,
		ServerAddress: authEntry.ServerAddress,
		IdentityToken: identityToken,
	}, nil
}

// isValidCredStoreName validates that a credential store name contains only
// alphanumeric characters, hyphens, and underscores — preventing path traversal.
func isValidCredStoreName(name string) bool {
	if len(name) == 0 {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// helperServerURL returns the canonical server URL used by credential helpers
// for a given registry. Docker Hub uses "https://index.docker.io/v1/" rather
// than the normalised "index.docker.io" hostname.
func helperServerURL(reg string) string {
	if IsDockerHub(reg) {
		return "https://index.docker.io/v1/"
	}
	return reg
}

// getFromCredHelper retrieves credentials from a Docker credential helper binary.
// The binary name is "docker-credential-<credStoreName>" and must be in PATH.
// Returns nil, nil when the helper reports that no credentials exist for the given serverURL.
// Returns nil, nil (silently) when the helper binary is not found in PATH, so that
// callers can fall back to other credential sources without breaking users that
// don't have Docker Desktop or a dedicated credential helper installed.
// A 5-second timeout is enforced via ctx to prevent indefinite hangs.
func getFromCredHelper(ctx context.Context, credStoreName, registryName, serverURL string) (*RegistryAuth, error) {
	// Bug 1: validate name to prevent path traversal attacks.
	if !isValidCredStoreName(credStoreName) {
		return nil, fmt.Errorf("invalid credential store name %q: must match [a-zA-Z0-9_-]+", credStoreName)
	}

	helperName := "docker-credential-" + credStoreName

	// Bug 2 (pre-check): use exec.LookPath instead of fragile string matching.
	if _, err := exec.LookPath(helperName); err != nil {
		// Helper binary not installed — silently fall through.
		return nil, nil
	}

	// Bug 2 (timeout): enforce a 5-second deadline so the process can't hang.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type result struct {
		creds *credentials.Credentials
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		creds, err := client.Get(client.NewShellProgramFunc(helperName), serverURL)
		ch <- result{creds, err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("credential helper %q timed out for registry %q", helperName, serverURL)
	case r := <-ch:
		if r.err != nil {
			if credentials.IsErrCredentialsNotFound(r.err) {
				// The helper ran fine but has no entry for this registry — not an error.
				return nil, nil
			}
			return nil, fmt.Errorf("credential helper %q failed for registry %q: %w", helperName, serverURL, r.err)
		}
		return &RegistryAuth{
			Username:      r.creds.Username,
			Password:      r.creds.Secret,
			Registry:      registryName,
			ServerAddress: serverURL,
		}, nil
	}
}

// findAuthInConfig searches for auth entry in Docker config with multiple strategies
func (ac *AuthConfig) findAuthInConfig(reg string) *AuthEntry {
	if ac.dockerConfig == nil || ac.dockerConfig.Auths == nil {
		return nil
	}

	auths := ac.dockerConfig.Auths

	// Strategy 1: Exact match
	if entry, ok := auths[reg]; ok {
		return &entry
	}

	// Strategy 2: Try with https:// prefix
	httpsRegistry := "https://" + reg
	if entry, ok := auths[httpsRegistry]; ok {
		return &entry
	}

	// Strategy 3: Docker Hub aliases
	if IsDockerHub(reg) {
		// Try all Docker Hub aliases
		dockerHubAliases := []string{
			"https://index.docker.io/v1/",
			"index.docker.io",
			"docker.io",
			"registry-1.docker.io",
		}

		for _, alias := range dockerHubAliases {
			if entry, ok := auths[alias]; ok {
				return &entry
			}
		}
	}

	// Strategy 4: Case-insensitive match (as fallback)
	registryLower := strings.ToLower(reg)
	for key, entry := range auths {
		if strings.ToLower(key) == registryLower {
			return &entry
		}
	}

	return nil
}

// ToDockerAuthConfig converts RegistryAuth to Docker SDK AuthConfig format
func (ra *RegistryAuth) ToDockerAuthConfig() registry.AuthConfig {
	if ra == nil {
		return registry.AuthConfig{}
	}

	serverAddress := ra.ServerAddress
	if serverAddress == "" {
		serverAddress = ra.Registry
	}

	return registry.AuthConfig{
		Username:      ra.Username,
		Password:      ra.Password,
		ServerAddress: serverAddress,
		IdentityToken: ra.IdentityToken,
	}
}
