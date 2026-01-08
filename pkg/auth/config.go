package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AuthEntry represents authentication credentials for a single registry
type AuthEntry struct {
	Auth          string `json:"auth,omitempty"`           // Base64-encoded "username:password"
	Username      string `json:"username,omitempty"`       // Plain username
	Password      string `json:"password,omitempty"`       // Plain password
	Email         string `json:"email,omitempty"`          // Optional email
	IdentityToken string `json:"identitytoken,omitempty"` // OAuth2 token
	ServerAddress string `json:"serveraddress,omitempty"` // Registry URL
}

// DockerConfig represents the structure of ~/.docker/config.json
type DockerConfig struct {
	Auths       map[string]AuthEntry `json:"auths,omitempty"`       // Registry credentials
	CredStore   string               `json:"credsStore,omitempty"`  // Credential helper name
	CredHelpers map[string]string    `json:"credHelpers,omitempty"` // Per-registry credential helpers
}

// LoadDockerConfig loads Docker configuration from the default location (~/.docker/config.json)
// Returns nil if the file doesn't exist (not an error condition)
// Returns error only for permission issues or malformed JSON
func LoadDockerConfig() (*DockerConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".docker", "config.json")
	return LoadDockerConfigFrom(configPath)
}

// LoadDockerConfigFrom loads Docker configuration from a custom path
// Returns nil if the file doesn't exist (not an error condition)
// Returns error only for permission issues or malformed JSON
func LoadDockerConfigFrom(path string) (*DockerConfig, error) {
	// Expand ~ in path
	if len(path) > 0 && path[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		path = filepath.Join(homeDir, path[1:])
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// File doesn't exist - this is NOT an error, just return nil
		return nil, nil
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Docker config from %s: %w", path, err)
	}

	// Parse JSON
	var config DockerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse Docker config from %s: %w", path, err)
	}

	return &config, nil
}
