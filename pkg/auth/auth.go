package auth

import (
	"fmt"
	"os"
	"strings"

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
	cliUser     string        // Username from CLI flag
	cliPassword string        // Password from CLI flag
	cliRegistry string        // Registry from CLI flag
	envUser     string        // Username from environment variable
	envPassword string        // Password from environment variable
	envRegistry string        // Registry from environment variable
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

	// Warn about credStore (not supported yet)
	if dockerConfig != nil && dockerConfig.CredStore != "" {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: Docker credential helper '%s' detected but not supported yet.\n", dockerConfig.CredStore)
		fmt.Fprintf(os.Stderr, "   Using credentials from config.json auths section or provide credentials via CLI/env.\n")
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
	// Extract registry from image name
	registry, err := ExtractRegistry(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract registry from image %q: %w", imageName, err)
	}

	// Normalize registry name
	registry = NormalizeRegistry(registry)

	// Priority 1: CLI flags (highest priority)
	if ac.cliUser != "" && ac.cliPassword != "" {
		// If CLI registry is specified, it must match
		if ac.cliRegistry != "" {
			cliReg := NormalizeRegistry(ac.cliRegistry)
			if cliReg != registry {
				// CLI registry doesn't match - try other sources
				return ac.getFromEnvOrConfig(imageName, registry)
			}
		}

		return &RegistryAuth{
			Username:      ac.cliUser,
			Password:      ac.cliPassword,
			Registry:      registry,
			ServerAddress: registry,
		}, nil
	}

	return ac.getFromEnvOrConfig(imageName, registry)
}

// getFromEnvOrConfig tries environment variables and then Docker config
func (ac *AuthConfig) getFromEnvOrConfig(imageName, registry string) (*RegistryAuth, error) {
	// Priority 2: Environment variables
	if ac.envUser != "" && ac.envPassword != "" {
		// If env registry is specified, it must match
		if ac.envRegistry != "" {
			envReg := NormalizeRegistry(ac.envRegistry)
			if envReg != registry {
				// Env registry doesn't match - try config file
				return ac.getFromDockerConfig(imageName, registry)
			}
		}

		return &RegistryAuth{
			Username:      ac.envUser,
			Password:      ac.envPassword,
			Registry:      registry,
			ServerAddress: registry,
		}, nil
	}

	// Priority 3: Docker config file (lowest priority)
	return ac.getFromDockerConfig(imageName, registry)
}

// getFromDockerConfig searches for credentials in ~/.docker/config.json
func (ac *AuthConfig) getFromDockerConfig(imageName, registry string) (*RegistryAuth, error) {
	if ac.dockerConfig == nil || ac.dockerConfig.Auths == nil {
		// No Docker config available - return nil (not an error)
		return nil, nil
	}

	// Try to find auth entry in config
	authEntry := ac.findAuthInConfig(registry)
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
			return nil, fmt.Errorf("failed to decode auth for registry %q: %w", registry, err)
		}
	}

	// Use identity token if available
	identityToken := authEntry.IdentityToken

	return &RegistryAuth{
		Username:      username,
		Password:      password,
		Registry:      registry,
		ServerAddress: authEntry.ServerAddress,
		IdentityToken: identityToken,
	}, nil
}

// findAuthInConfig searches for auth entry in Docker config with multiple strategies
func (ac *AuthConfig) findAuthInConfig(registry string) *AuthEntry {
	if ac.dockerConfig == nil || ac.dockerConfig.Auths == nil {
		return nil
	}

	auths := ac.dockerConfig.Auths

	// Strategy 1: Exact match
	if entry, ok := auths[registry]; ok {
		return &entry
	}

	// Strategy 2: Try with https:// prefix
	httpsRegistry := "https://" + registry
	if entry, ok := auths[httpsRegistry]; ok {
		return &entry
	}

	// Strategy 3: Docker Hub aliases
	if IsDockerHub(registry) {
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
	registryLower := strings.ToLower(registry)
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
