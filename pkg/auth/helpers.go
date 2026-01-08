package auth

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/distribution/reference"
)

// DecodeAuth decodes a base64-encoded "username:password" string
// Returns username, password, error
func DecodeAuth(auth string) (string, string, error) {
	if auth == "" {
		return "", "", nil
	}

	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode auth string: %w", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid auth format: expected 'username:password'")
	}

	return parts[0], parts[1], nil
}

// ExtractRegistry extracts the registry hostname from an image name
// Examples:
//   - "nginx:latest" -> "docker.io"
//   - "ghcr.io/user/image:tag" -> "ghcr.io"
//   - "example.com:5000/repo/image" -> "example.com:5000"
//   - "localhost:5000/test" -> "localhost:5000"
func ExtractRegistry(imageName string) (string, error) {
	// Parse image reference using distribution library
	named, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return "", fmt.Errorf("failed to parse image name %q: %w", imageName, err)
	}

	// Extract domain from the parsed reference
	domain := reference.Domain(named)

	return domain, nil
}

// NormalizeRegistry normalizes registry names to their canonical forms
// This handles Docker Hub aliases and ensures consistent lookups
// Examples:
//   - "docker.io" -> "index.docker.io"
//   - "registry-1.docker.io" -> "index.docker.io"
//   - "ghcr.io" -> "ghcr.io" (unchanged)
func NormalizeRegistry(registry string) string {
	registry = strings.TrimSpace(registry)
	registry = strings.TrimPrefix(registry, "http://")
	registry = strings.TrimPrefix(registry, "https://")
	registry = strings.TrimSuffix(registry, "/")

	// Docker Hub has multiple aliases
	switch registry {
	case "docker.io", "registry-1.docker.io", "index.docker.io":
		return "index.docker.io"
	default:
		return registry
	}
}

// IsDockerHub checks if a registry is Docker Hub (any of its aliases)
func IsDockerHub(registry string) bool {
	normalized := NormalizeRegistry(registry)
	return normalized == "index.docker.io"
}
