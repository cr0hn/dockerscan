package auth

import (
	"path/filepath"
	"testing"
)

func TestLoadDockerConfigFrom(t *testing.T) {
	tests := []struct {
		name          string
		configPath    string
		wantNil       bool
		wantErr       bool
		checkCredStore bool
		wantCredStore string
		checkAuths    bool
		wantAuthCount int
	}{
		{
			name:          "valid config file",
			configPath:    "testdata/config_valid.json",
			wantNil:       false,
			wantErr:       false,
			checkAuths:    true,
			wantAuthCount: 3, // Docker Hub, ghcr.io, myregistry.example.com
		},
		{
			name:          "config with credStore",
			configPath:    "testdata/config_credstore.json",
			wantNil:       false,
			wantErr:       false,
			checkCredStore: true,
			wantCredStore: "desktop",
			checkAuths:    true,
			wantAuthCount: 1, // ghcr.io
		},
		{
			name:       "invalid JSON",
			configPath: "testdata/config_invalid.json",
			wantNil:    true, // Returns nil on error
			wantErr:    true,
		},
		{
			name:       "nonexistent file returns nil",
			configPath: "testdata/nonexistent.json",
			wantNil:    true,
			wantErr:    false,
		},
		{
			name:       "empty file returns error",
			configPath: "testdata/config_empty.json",
			wantNil:    true, // Returns nil on error
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to absolute path
			absPath, err := filepath.Abs(tt.configPath)
			if err != nil {
				t.Fatalf("Failed to get absolute path: %v", err)
			}

			config, err := LoadDockerConfigFrom(absPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadDockerConfigFrom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (config == nil) != tt.wantNil {
				t.Errorf("LoadDockerConfigFrom() config == nil is %v, want %v", config == nil, tt.wantNil)
				return
			}

			// Additional checks for valid configs
			if !tt.wantNil && !tt.wantErr {
				if tt.checkCredStore && config.CredStore != tt.wantCredStore {
					t.Errorf("LoadDockerConfigFrom() CredStore = %v, want %v", config.CredStore, tt.wantCredStore)
				}

				if tt.checkAuths {
					if len(config.Auths) != tt.wantAuthCount {
						t.Errorf("LoadDockerConfigFrom() auth count = %v, want %v", len(config.Auths), tt.wantAuthCount)
					}
				}
			}
		})
	}
}

func TestLoadDockerConfigFrom_TildeExpansion(t *testing.T) {
	// Test that tilde expansion works (we can't test the actual file without creating one in ~)
	// Just verify it doesn't error on path processing
	config, err := LoadDockerConfigFrom("~/nonexistent-test-file.json")

	// Should return nil (file doesn't exist), not error
	if err != nil {
		t.Errorf("LoadDockerConfigFrom() with tilde should not error on nonexistent file, got: %v", err)
	}

	if config != nil {
		t.Errorf("LoadDockerConfigFrom() should return nil for nonexistent file, got: %v", config)
	}
}

func TestDockerConfigStructure(t *testing.T) {
	// Test that we can properly parse a valid config
	absPath, err := filepath.Abs("testdata/config_valid.json")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	config, err := LoadDockerConfigFrom(absPath)
	if err != nil {
		t.Fatalf("LoadDockerConfigFrom() failed: %v", err)
	}

	if config == nil {
		t.Fatal("LoadDockerConfigFrom() returned nil config")
	}

	// Check Docker Hub auth (base64 encoded)
	dockerHubAuth, ok := config.Auths["https://index.docker.io/v1/"]
	if !ok {
		t.Error("Docker Hub auth not found")
	} else {
		if dockerHubAuth.Auth != "dXNlcjE6cGFzczE=" {
			t.Errorf("Docker Hub auth = %v, want dXNlcjE6cGFzczE=", dockerHubAuth.Auth)
		}
	}

	// Check ghcr.io auth (base64 encoded)
	ghcrAuth, ok := config.Auths["ghcr.io"]
	if !ok {
		t.Error("GHCR auth not found")
	} else {
		if ghcrAuth.Auth != "dXNlcjI6cGFzczI=" {
			t.Errorf("GHCR auth = %v, want dXNlcjI6cGFzczI=", ghcrAuth.Auth)
		}
	}

	// Check custom registry auth (plain username/password)
	customAuth, ok := config.Auths["myregistry.example.com"]
	if !ok {
		t.Error("Custom registry auth not found")
	} else {
		if customAuth.Username != "user3" {
			t.Errorf("Custom registry username = %v, want user3", customAuth.Username)
		}
		if customAuth.Password != "pass3" {
			t.Errorf("Custom registry password = %v, want pass3", customAuth.Password)
		}
		if customAuth.Email != "user3@example.com" {
			t.Errorf("Custom registry email = %v, want user3@example.com", customAuth.Email)
		}
	}
}
