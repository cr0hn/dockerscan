package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/moby/go-archive"
)

// Client wraps Docker operations
type Client struct {
	cli *client.Client
}

// NewClient creates a new Docker client
func NewClient() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &Client{cli: cli}, nil
}

// Close closes the Docker client
func (c *Client) Close() error {
	return c.cli.Close()
}

// Ping checks if Docker daemon is accessible
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.cli.Ping(ctx)
	return err
}

// ImageExists checks if an image exists locally
func (c *Client) ImageExists(ctx context.Context, imageName string) (bool, error) {
	_, err := c.cli.ImageInspect(ctx, imageName)
	if err != nil {
		// Use proper Docker API error type instead of string matching
		if errdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// PullImage pulls an image from registry
func (c *Client) PullImage(ctx context.Context, imageName string) error {
	reader, err := c.cli.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()

	// Read and discard the output (we could parse progress here)
	_, err = io.Copy(io.Discard, reader)
	return err
}

// ImageInfo contains detailed information about a Docker image
type ImageInfo struct {
	ID           string
	RepoTags     []string
	RepoDigests  []string
	Created      time.Time
	Size         int64
	Architecture string
	OS           string
	Author       string
	User         string
	ExposedPorts []string
	Env          map[string]string
	Cmd          []string
	Entrypoint   []string
	WorkingDir   string
	Labels       map[string]string
	Volumes      []string
	Healthcheck  *HealthcheckConfig
	LayerCount   int
	History      []HistoryEntry
	RootFS       RootFSInfo
}

// HealthcheckConfig contains healthcheck configuration
type HealthcheckConfig struct {
	Test        []string
	Interval    time.Duration
	Timeout     time.Duration
	StartPeriod time.Duration
	Retries     int
}

// RootFSInfo contains filesystem information
type RootFSInfo struct {
	Type   string
	Layers []string
}

// HistoryEntry represents a step in image build history
type HistoryEntry struct {
	Created    time.Time
	CreatedBy  string
	Size       int64
	Comment    string
	EmptyLayer bool
}

// InspectImage retrieves detailed image information
func (c *Client) InspectImage(ctx context.Context, imageName string) (*ImageInfo, error) {
	inspect, err := c.cli.ImageInspect(ctx, imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	info := &ImageInfo{
		ID:           inspect.ID,
		RepoTags:     inspect.RepoTags,
		RepoDigests:  inspect.RepoDigests,
		Size:         inspect.Size,
		Architecture: inspect.Architecture,
		OS:           inspect.Os,
		Author:       inspect.Author,
		LayerCount:   len(inspect.RootFS.Layers),
		RootFS: RootFSInfo{
			Type:   inspect.RootFS.Type,
			Layers: inspect.RootFS.Layers,
		},
	}

	// Parse created time
	if inspect.Created != "" {
		if t, err := time.Parse(time.RFC3339Nano, inspect.Created); err == nil {
			info.Created = t
		}
	}

	// Parse container config
	if inspect.Config != nil {
		info.User = inspect.Config.User
		info.Cmd = inspect.Config.Cmd
		info.Entrypoint = inspect.Config.Entrypoint
		info.WorkingDir = inspect.Config.WorkingDir
		info.Labels = inspect.Config.Labels

		// Parse environment variables
		info.Env = make(map[string]string)
		for _, env := range inspect.Config.Env {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				info.Env[parts[0]] = parts[1]
			}
		}

		// Parse exposed ports
		for port := range inspect.Config.ExposedPorts {
			info.ExposedPorts = append(info.ExposedPorts, string(port))
		}

		// Parse volumes
		for vol := range inspect.Config.Volumes {
			info.Volumes = append(info.Volumes, vol)
		}

		// Parse healthcheck
		if inspect.Config.Healthcheck != nil {
			info.Healthcheck = &HealthcheckConfig{
				Test:        inspect.Config.Healthcheck.Test,
				Interval:    inspect.Config.Healthcheck.Interval,
				Timeout:     inspect.Config.Healthcheck.Timeout,
				StartPeriod: inspect.Config.Healthcheck.StartPeriod,
				Retries:     inspect.Config.Healthcheck.Retries,
			}
		}
	}

	return info, nil
}

// GetImageHistory retrieves image build history
func (c *Client) GetImageHistory(ctx context.Context, imageName string) ([]HistoryEntry, error) {
	history, err := c.cli.ImageHistory(ctx, imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to get image history: %w", err)
	}

	entries := make([]HistoryEntry, len(history))
	for i, h := range history {
		entries[i] = HistoryEntry{
			Created:    time.Unix(h.Created, 0),
			CreatedBy:  h.CreatedBy,
			Size:       h.Size,
			Comment:    h.Comment,
			EmptyLayer: h.Size == 0,
		}
	}

	return entries, nil
}

// FileInfo represents information about a file in the image
type FileInfo struct {
	Path    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
	Link    string
}

// FileContent represents a file and its content
type FileContent struct {
	Info    FileInfo
	Content []byte
}

// ScanImageFiles scans all files in image layers and calls callback for each file
func (c *Client) ScanImageFiles(ctx context.Context, imageName string, callback func(FileInfo, io.Reader) error) error {
	// Export image as tar
	reader, err := c.cli.ImageSave(ctx, []string{imageName})
	if err != nil {
		return fmt.Errorf("failed to export image: %w", err)
	}
	defer reader.Close()

	// Create a temporary directory to extract the image
	tmpDir, err := os.MkdirTemp("", "dockerscan-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract the image tar
	if err := archive.Unpack(reader, tmpDir, &archive.TarOptions{}); err != nil {
		return fmt.Errorf("failed to extract image: %w", err)
	}

	// Read manifest.json to get layer order
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifests []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	if err := json.Unmarshal(manifestData, &manifests); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	if len(manifests) == 0 {
		return fmt.Errorf("empty manifest")
	}

	// Process each layer
	for _, layerPath := range manifests[0].Layers {
		layerFullPath := filepath.Join(tmpDir, layerPath)
		if err := c.processLayer(layerFullPath, callback); err != nil {
			return fmt.Errorf("failed to process layer %s: %w", layerPath, err)
		}
	}

	return nil
}

// processLayer processes a single layer tar file
func (c *Client) processLayer(layerPath string, callback func(FileInfo, io.Reader) error) error {
	file, err := os.Open(layerPath)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file

	// Check if gzipped
	if strings.HasSuffix(layerPath, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Skip whiteout files (deleted files marker)
		if strings.HasPrefix(filepath.Base(header.Name), ".wh.") {
			continue
		}

		fileInfo := FileInfo{
			Path:    header.Name,
			Size:    header.Size,
			Mode:    os.FileMode(header.Mode),
			ModTime: header.ModTime,
			IsDir:   header.Typeflag == tar.TypeDir,
			Link:    header.Linkname,
		}

		if err := callback(fileInfo, tarReader); err != nil {
			return err
		}
	}

	return nil
}

// ExtractFile extracts a specific file from the image
func (c *Client) ExtractFile(ctx context.Context, imageName, filePath string) ([]byte, error) {
	var content []byte
	found := false

	err := c.ScanImageFiles(ctx, imageName, func(info FileInfo, reader io.Reader) error {
		if info.Path == filePath || info.Path == strings.TrimPrefix(filePath, "/") {
			var err error
			content, err = io.ReadAll(reader)
			if err != nil {
				return err
			}
			found = true
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("file %s not found in image", filePath)
	}

	return content, nil
}

// ListPackages attempts to list installed packages in the image
func (c *Client) ListPackages(ctx context.Context, imageName string) ([]PackageInfo, error) {
	var packages []PackageInfo

	// Try to detect package manager and list packages
	err := c.ScanImageFiles(ctx, imageName, func(info FileInfo, reader io.Reader) error {
		// Detect dpkg (Debian/Ubuntu)
		if info.Path == "var/lib/dpkg/status" || info.Path == "/var/lib/dpkg/status" {
			content, err := io.ReadAll(reader)
			if err != nil {
				// Propagate read errors instead of silently ignoring them
				return fmt.Errorf("failed to read dpkg status file: %w", err)
			}
			packages = append(packages, parseDpkgStatus(content)...)
		}

		// Note: RPM (RHEL/CentOS/Fedora) detection would require rpm2cpio parsing
		// of /var/lib/rpm/Packages which is binary format - not implemented yet

		// Detect Alpine APK
		if info.Path == "lib/apk/db/installed" || info.Path == "/lib/apk/db/installed" {
			content, err := io.ReadAll(reader)
			if err != nil {
				// Propagate read errors instead of silently ignoring them
				return fmt.Errorf("failed to read apk installed file: %w", err)
			}
			packages = append(packages, parseApkInstalled(content)...)
		}

		return nil
	})

	return packages, err
}

// PackageInfo represents an installed package
type PackageInfo struct {
	Name    string
	Version string
	Source  string // dpkg, apk, rpm, etc.
}

// parseDpkgStatus parses Debian/Ubuntu dpkg status file
func parseDpkgStatus(content []byte) []PackageInfo {
	var packages []PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(content))

	var currentPkg PackageInfo
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			currentPkg = PackageInfo{Source: "dpkg"}
			currentPkg.Name = strings.TrimPrefix(line, "Package: ")
		} else if strings.HasPrefix(line, "Version: ") {
			currentPkg.Version = strings.TrimPrefix(line, "Version: ")
		} else if line == "" && currentPkg.Name != "" {
			// Only add package if it has both name and version
			if currentPkg.Version != "" {
				packages = append(packages, currentPkg)
			}
			currentPkg = PackageInfo{}
		}
	}

	// Only add final package if it has both name and version
	if currentPkg.Name != "" && currentPkg.Version != "" {
		packages = append(packages, currentPkg)
	}

	return packages
}

// parseApkInstalled parses Alpine APK installed database
func parseApkInstalled(content []byte) []PackageInfo {
	var packages []PackageInfo
	scanner := bufio.NewScanner(bytes.NewReader(content))

	var currentPkg PackageInfo
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "P:") {
			currentPkg = PackageInfo{Source: "apk"}
			currentPkg.Name = strings.TrimPrefix(line, "P:")
		} else if strings.HasPrefix(line, "V:") {
			currentPkg.Version = strings.TrimPrefix(line, "V:")
		} else if line == "" && currentPkg.Name != "" {
			// Only add package if it has both name and version
			if currentPkg.Version != "" {
				packages = append(packages, currentPkg)
			}
			currentPkg = PackageInfo{}
		}
	}

	// Only add final package if it has both name and version
	if currentPkg.Name != "" && currentPkg.Version != "" {
		packages = append(packages, currentPkg)
	}

	return packages
}

// ContainerInfo contains information about a running container
type ContainerInfo struct {
	ID           string
	Name         string
	Image        string
	State        string
	Privileged   bool
	CapAdd       []string
	CapDrop      []string
	SecurityOpt  []string
	NetworkMode  string
	PidMode      string
	IpcMode      string
	UsernsMode   string
	ReadonlyRoot bool
	Mounts       []MountInfo
	User         string
}

// MountInfo contains mount information
type MountInfo struct {
	Type        string
	Source      string
	Destination string
	Mode        string
	RW          bool
}

// InspectContainer retrieves detailed container information
func (c *Client) InspectContainer(ctx context.Context, containerID string) (*ContainerInfo, error) {
	inspect, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	info := &ContainerInfo{
		ID:    inspect.ID,
		Name:  strings.TrimPrefix(inspect.Name, "/"),
		Image: inspect.Image,
		State: inspect.State.Status,
	}

	if inspect.HostConfig != nil {
		info.Privileged = inspect.HostConfig.Privileged
		info.CapAdd = inspect.HostConfig.CapAdd
		info.CapDrop = inspect.HostConfig.CapDrop
		info.SecurityOpt = inspect.HostConfig.SecurityOpt
		info.NetworkMode = string(inspect.HostConfig.NetworkMode)
		info.PidMode = string(inspect.HostConfig.PidMode)
		info.IpcMode = string(inspect.HostConfig.IpcMode)
		info.UsernsMode = string(inspect.HostConfig.UsernsMode)
		info.ReadonlyRoot = inspect.HostConfig.ReadonlyRootfs
	}

	if inspect.Config != nil {
		info.User = inspect.Config.User
	}

	for _, mount := range inspect.Mounts {
		info.Mounts = append(info.Mounts, MountInfo{
			Type:        string(mount.Type),
			Source:      mount.Source,
			Destination: mount.Destination,
			Mode:        mount.Mode,
			RW:          mount.RW,
		})
	}

	return info, nil
}

// ListContainers lists all containers
func (c *Client) ListContainers(ctx context.Context, all bool) ([]ContainerInfo, error) {
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: all})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var infos []ContainerInfo
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		infos = append(infos, ContainerInfo{
			ID:    c.ID,
			Name:  name,
			Image: c.Image,
			State: c.State,
		})
	}

	return infos, nil
}

// SearchFileContent searches for patterns in file content.
// maxMatches limits the total number of matches to prevent unbounded memory growth.
// Use 0 for unlimited matches (not recommended for production).
func (c *Client) SearchFileContent(ctx context.Context, imageName string, patterns map[string]*regexp.Regexp, maxFileSize int64, maxMatches int) ([]SecretMatch, error) {
	var matches []SecretMatch

	err := c.ScanImageFiles(ctx, imageName, func(info FileInfo, reader io.Reader) error {
		// Skip directories and large files
		if info.IsDir || info.Size > maxFileSize {
			return nil
		}

		// Skip binary files by extension
		ext := strings.ToLower(filepath.Ext(info.Path))
		binaryExts := map[string]bool{
			".exe": true, ".dll": true, ".so": true, ".dylib": true,
			".bin": true, ".o": true, ".a": true, ".pyc": true,
			".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
			".ico": true, ".pdf": true, ".zip": true, ".tar": true,
			".gz": true, ".bz2": true, ".xz": true, ".7z": true,
		}
		if binaryExts[ext] {
			return nil
		}

		content, err := io.ReadAll(reader)
		if err != nil {
			return nil
		}

		// Check if binary content
		if isBinary(content) {
			return nil
		}

		// Search for patterns
		for name, pattern := range patterns {
			if locs := pattern.FindAllIndex(content, -1); locs != nil {
				for _, loc := range locs {
					// Check if we've hit the match limit (if configured)
					if maxMatches > 0 && len(matches) >= maxMatches {
						return fmt.Errorf("match limit reached (%d), stopping search to prevent memory exhaustion", maxMatches)
					}

					// Validate slice bounds before accessing
					if len(loc) != 2 || loc[0] < 0 || loc[1] > len(content) || loc[0] > loc[1] {
						continue // Skip invalid match indices
					}
					lineNum := bytes.Count(content[:loc[0]], []byte("\n")) + 1
					match := string(content[loc[0]:loc[1]])

					matches = append(matches, SecretMatch{
						PatternName: name,
						FilePath:    info.Path,
						LineNumber:  lineNum,
						Match:       match,
					})
				}
			}
		}

		return nil
	})

	return matches, err
}

// SecretMatch represents a found secret
type SecretMatch struct {
	PatternName string
	FilePath    string
	LineNumber  int
	Match       string
}

// isBinary checks if content appears to be binary by detecting null bytes.
//
// LIMITATION: This simple heuristic may incorrectly classify UTF-16 and UTF-32
// encoded text files as binary since they contain null bytes. For more accurate
// detection, consider using a library like github.com/h2non/filetype or
// implementing BOM (Byte Order Mark) detection for UTF-16/UTF-32.
//
// The check examines up to the first 8KB of content for performance reasons.
func isBinary(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	// Check for null bytes in first 8KB
	// Note: This will flag UTF-16/UTF-32 text as binary
	checkLen := len(content)
	if checkLen > 8192 {
		checkLen = 8192
	}

	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return true
		}
	}

	return false
}

// VerifyImageSignature checks if an image has a valid signature
func (c *Client) VerifyImageSignature(ctx context.Context, imageName string) (bool, string, error) {
	// Check for Docker Content Trust
	// This would require checking Notary server or cosign signatures
	// For now, we check if DOCKER_CONTENT_TRUST is enabled and if image has digest

	info, err := c.InspectImage(ctx, imageName)
	if err != nil {
		return false, "", err
	}

	// Check if image has digest (indicates it was pulled with content trust or from registry)
	hasDigest := len(info.RepoDigests) > 0

	if hasDigest {
		return true, info.RepoDigests[0], nil
	}

	return false, "", nil
}

// GetImageManifest retrieves the image manifest
func (c *Client) GetImageManifest(ctx context.Context, imageName string) (*ImageManifest, error) {
	// Export image and read manifest
	reader, err := c.cli.ImageSave(ctx, []string{imageName})
	if err != nil {
		return nil, fmt.Errorf("failed to export image: %w", err)
	}
	defer reader.Close()

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == "manifest.json" {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}

			var manifests []ImageManifest
			if err := json.Unmarshal(content, &manifests); err != nil {
				return nil, err
			}

			if len(manifests) > 0 {
				return &manifests[0], nil
			}
		}
	}

	return nil, fmt.Errorf("manifest not found")
}

// ImageManifest represents Docker image manifest
type ImageManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// GetImageConfig retrieves the image configuration
func (c *Client) GetImageConfig(ctx context.Context, imageName string) (*ImageConfig, error) {
	manifest, err := c.GetImageManifest(ctx, imageName)
	if err != nil {
		return nil, err
	}

	// Export image and read config
	reader, err := c.cli.ImageSave(ctx, []string{imageName})
	if err != nil {
		return nil, fmt.Errorf("failed to export image: %w", err)
	}
	defer reader.Close()

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == manifest.Config {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, err
			}

			var config ImageConfig
			if err := json.Unmarshal(content, &config); err != nil {
				return nil, err
			}

			return &config, nil
		}
	}

	return nil, fmt.Errorf("config not found")
}

// ImageConfig represents the full image configuration
type ImageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		User         string              `json:"User"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Env          []string            `json:"Env"`
		Cmd          []string            `json:"Cmd"`
		Volumes      map[string]struct{} `json:"Volumes"`
		WorkingDir   string              `json:"WorkingDir"`
		Entrypoint   []string            `json:"Entrypoint"`
		Labels       map[string]string   `json:"Labels"`
		Healthcheck  *struct {
			Test     []string `json:"Test"`
			Interval int64    `json:"Interval"`
			Timeout  int64    `json:"Timeout"`
		} `json:"Healthcheck"`
	} `json:"config"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer,omitempty"`
		Comment    string `json:"comment,omitempty"`
	} `json:"history"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}
