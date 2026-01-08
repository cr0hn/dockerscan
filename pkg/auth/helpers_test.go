package auth

import (
	"testing"
)

func TestDecodeAuth(t *testing.T) {
	tests := []struct {
		name          string
		auth          string
		wantUsername  string
		wantPassword  string
		wantErr       bool
	}{
		{
			name:         "valid base64 auth",
			auth:         "dXNlcjE6cGFzczE=", // user1:pass1
			wantUsername: "user1",
			wantPassword: "pass1",
			wantErr:      false,
		},
		{
			name:         "valid auth with special chars",
			auth:         "dXNlcjI6cGFzc0AhIyQ=", // user2:pass@!#$
			wantUsername: "user2",
			wantPassword: "pass@!#$",
			wantErr:      false,
		},
		{
			name:         "empty auth string",
			auth:         "",
			wantUsername: "",
			wantPassword: "",
			wantErr:      false,
		},
		{
			name:    "invalid base64",
			auth:    "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "invalid format (no colon)",
			auth:    "dXNlcjFwYXNzMQ==", // user1pass1 (no colon)
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, password, err := DecodeAuth(tt.auth)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeAuth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if username != tt.wantUsername {
					t.Errorf("DecodeAuth() username = %v, want %v", username, tt.wantUsername)
				}
				if password != tt.wantPassword {
					t.Errorf("DecodeAuth() password = %v, want %v", password, tt.wantPassword)
				}
			}
		})
	}
}

func TestExtractRegistry(t *testing.T) {
	tests := []struct {
		name         string
		imageName    string
		wantRegistry string
		wantErr      bool
	}{
		{
			name:         "Docker Hub - short form",
			imageName:    "nginx:latest",
			wantRegistry: "docker.io",
			wantErr:      false,
		},
		{
			name:         "Docker Hub - with library prefix",
			imageName:    "library/nginx:latest",
			wantRegistry: "docker.io",
			wantErr:      false,
		},
		{
			name:         "Docker Hub - user image",
			imageName:    "user/myapp:v1.0",
			wantRegistry: "docker.io",
			wantErr:      false,
		},
		{
			name:         "GitHub Container Registry",
			imageName:    "ghcr.io/owner/repo:tag",
			wantRegistry: "ghcr.io",
			wantErr:      false,
		},
		{
			name:         "AWS ECR",
			imageName:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest",
			wantRegistry: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			wantErr:      false,
		},
		{
			name:         "Google Container Registry",
			imageName:    "gcr.io/project-id/image:tag",
			wantRegistry: "gcr.io",
			wantErr:      false,
		},
		{
			name:         "Google Artifact Registry",
			imageName:    "us-docker.pkg.dev/project/repo/image:tag",
			wantRegistry: "us-docker.pkg.dev",
			wantErr:      false,
		},
		{
			name:         "Azure Container Registry",
			imageName:    "myregistry.azurecr.io/myapp:v1",
			wantRegistry: "myregistry.azurecr.io",
			wantErr:      false,
		},
		{
			name:         "Quay.io",
			imageName:    "quay.io/organization/image:tag",
			wantRegistry: "quay.io",
			wantErr:      false,
		},
		{
			name:         "Private registry with port",
			imageName:    "myregistry.example.com:5000/app:latest",
			wantRegistry: "myregistry.example.com:5000",
			wantErr:      false,
		},
		{
			name:         "Localhost with port",
			imageName:    "localhost:5000/test:latest",
			wantRegistry: "localhost:5000",
			wantErr:      false,
		},
		{
			name:         "GitLab Container Registry",
			imageName:    "registry.gitlab.com/group/project:tag",
			wantRegistry: "registry.gitlab.com",
			wantErr:      false,
		},
		{
			name:         "JFrog Artifactory",
			imageName:    "mycompany.jfrog.io/docker/image:tag",
			wantRegistry: "mycompany.jfrog.io",
			wantErr:      false,
		},
		{
			name:         "Image with digest",
			imageName:    "nginx@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			wantRegistry: "docker.io",
			wantErr:      false,
		},
		{
			name:         "GHCR with digest",
			imageName:    "ghcr.io/user/app@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			wantRegistry: "ghcr.io",
			wantErr:      false,
		},
		{
			name:      "invalid image name",
			imageName: ":::invalid::::",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, err := ExtractRegistry(tt.imageName)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractRegistry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && registry != tt.wantRegistry {
				t.Errorf("ExtractRegistry() = %v, want %v", registry, tt.wantRegistry)
			}
		})
	}
}

func TestNormalizeRegistry(t *testing.T) {
	tests := []struct {
		name       string
		registry   string
		wantNormal string
	}{
		{
			name:       "docker.io to index.docker.io",
			registry:   "docker.io",
			wantNormal: "index.docker.io",
		},
		{
			name:       "registry-1.docker.io to index.docker.io",
			registry:   "registry-1.docker.io",
			wantNormal: "index.docker.io",
		},
		{
			name:       "index.docker.io stays the same",
			registry:   "index.docker.io",
			wantNormal: "index.docker.io",
		},
		{
			name:       "ghcr.io unchanged",
			registry:   "ghcr.io",
			wantNormal: "ghcr.io",
		},
		{
			name:       "strip https:// prefix",
			registry:   "https://ghcr.io",
			wantNormal: "ghcr.io",
		},
		{
			name:       "strip http:// prefix",
			registry:   "http://localhost:5000",
			wantNormal: "localhost:5000",
		},
		{
			name:       "strip trailing slash",
			registry:   "ghcr.io/",
			wantNormal: "ghcr.io",
		},
		{
			name:       "strip https and trailing slash",
			registry:   "https://myregistry.example.com/",
			wantNormal: "myregistry.example.com",
		},
		{
			name:       "registry with port",
			registry:   "localhost:5000",
			wantNormal: "localhost:5000",
		},
		{
			name:       "whitespace trimmed",
			registry:   "  ghcr.io  ",
			wantNormal: "ghcr.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := NormalizeRegistry(tt.registry)
			if normalized != tt.wantNormal {
				t.Errorf("NormalizeRegistry() = %v, want %v", normalized, tt.wantNormal)
			}
		})
	}
}

func TestIsDockerHub(t *testing.T) {
	tests := []struct {
		name      string
		registry  string
		isDockerH bool
	}{
		{
			name:      "docker.io is Docker Hub",
			registry:  "docker.io",
			isDockerH: true,
		},
		{
			name:      "index.docker.io is Docker Hub",
			registry:  "index.docker.io",
			isDockerH: true,
		},
		{
			name:      "registry-1.docker.io is Docker Hub",
			registry:  "registry-1.docker.io",
			isDockerH: true,
		},
		{
			name:      "ghcr.io is not Docker Hub",
			registry:  "ghcr.io",
			isDockerH: false,
		},
		{
			name:      "gcr.io is not Docker Hub",
			registry:  "gcr.io",
			isDockerH: false,
		},
		{
			name:      "localhost is not Docker Hub",
			registry:  "localhost:5000",
			isDockerH: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isHub := IsDockerHub(tt.registry)
			if isHub != tt.isDockerH {
				t.Errorf("IsDockerHub() = %v, want %v", isHub, tt.isDockerH)
			}
		})
	}
}
