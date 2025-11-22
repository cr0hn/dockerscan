package docker

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

// Client wraps Docker operations
type Client struct {
	// Would use actual Docker client library
	// For now, we define the interface
}

// NewClient creates a new Docker client
func NewClient() (*Client, error) {
	return &Client{}, nil
}

// InspectImage retrieves detailed image information
func (c *Client) InspectImage(ctx context.Context, imageName string) (*models.ImageInfo, error) {
	// Would use actual Docker API
	// docker/client.ImageInspect()

	info := &models.ImageInfo{
		Name:         imageName,
		Tag:          "latest",
		Created:      time.Now(),
		Architecture: "amd64",
		OS:           "linux",
		Environment:  make(map[string]string),
		Labels:       make(map[string]string),
	}

	return info, nil
}

// ExtractImageLayers extracts all layers from an image
func (c *Client) ExtractImageLayers(ctx context.Context, imageName string) ([]Layer, error) {
	// Would export image as tar and extract layers
	var layers []Layer

	return layers, nil
}

// GetImageHistory retrieves image build history
func (c *Client) GetImageHistory(ctx context.Context, imageName string) ([]HistoryEntry, error) {
	// Would use docker/client.ImageHistory()
	var history []HistoryEntry

	return history, nil
}

// ScanImageFiles scans all files in image layers
func (c *Client) ScanImageFiles(ctx context.Context, imageName string, callback func(string, io.Reader) error) error {
	// Export image as tar
	// Iterate through all layers
	// Call callback for each file

	return nil
}

// GetImageConfig retrieves image configuration
func (c *Client) GetImageConfig(ctx context.Context, imageName string) (*ImageConfig, error) {
	// Would parse image config JSON
	config := &ImageConfig{}

	return config, nil
}

// Layer represents a Docker image layer
type Layer struct {
	ID      string
	Size    int64
	Created time.Time
	Command string
}

// HistoryEntry represents a step in image build history
type HistoryEntry struct {
	Created    time.Time
	CreatedBy  string
	Size       int64
	Comment    string
	EmptyLayer bool
}

// ImageConfig represents Docker image configuration
type ImageConfig struct {
	Architecture    string            `json:"architecture"`
	OS              string            `json:"os"`
	Config          ContainerConfig   `json:"config"`
	RootFS          RootFS            `json:"rootfs"`
	History         []HistoryEntry    `json:"history"`
}

// ContainerConfig contains container configuration
type ContainerConfig struct {
	User         string              `json:"User"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	Env          []string            `json:"Env"`
	Cmd          []string            `json:"Cmd"`
	Volumes      map[string]struct{} `json:"Volumes"`
	WorkingDir   string              `json:"WorkingDir"`
	Entrypoint   []string            `json:"Entrypoint"`
	Labels       map[string]string   `json:"Labels"`
}

// RootFS contains filesystem information
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// ParseEnvVars converts env array to map
func ParseEnvVars(envArray []string) map[string]string {
	envMap := make(map[string]string)

	for _, env := range envArray {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	return envMap
}

// ExtractFileFromTar extracts a specific file from tar archive
func ExtractFileFromTar(tarReader *tar.Reader, filename string) ([]byte, error) {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == filename {
			data, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("file %s not found in tar", filename)
}

// ReadManifest reads manifest.json from image export
func ReadManifest(data []byte) (*Manifest, error) {
	var manifest []ManifestEntry
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	if len(manifest) == 0 {
		return nil, fmt.Errorf("empty manifest")
	}

	return &Manifest{
		Config:   manifest[0].Config,
		RepoTags: manifest[0].RepoTags,
		Layers:   manifest[0].Layers,
	}, nil
}

// Manifest represents Docker image manifest
type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// ManifestEntry is a single entry in manifest array
type ManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}
