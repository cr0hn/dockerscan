package cvedb

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultDBURL is the default URL for downloading the CVE database
	DefaultDBURL = "https://raw.githubusercontent.com/cr0hn/dockerscan/master/data/latest.db.gz"

	// DefaultChecksumURL is the default URL for the database checksum
	DefaultChecksumURL = "https://raw.githubusercontent.com/cr0hn/dockerscan/master/data/latest.db.gz.sha256"

	// DefaultDBPath is the default local path for the CVE database
	DefaultDBPath = "~/.dockerscan/cve-db.sqlite"
)

// Downloader manages CVE database downloads
type Downloader struct {
	dbURL       string
	checksumURL string
	destPath    string
	httpClient  *http.Client
}

// NewDownloader creates a new database downloader
func NewDownloader(dbURL, checksumURL, destPath string) *Downloader {
	if dbURL == "" {
		dbURL = DefaultDBURL
	}
	if checksumURL == "" {
		checksumURL = DefaultChecksumURL
	}
	if destPath == "" {
		destPath = DefaultDBPath
	}

	return &Downloader{
		dbURL:       dbURL,
		checksumURL: checksumURL,
		destPath:    destPath,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// Download downloads and verifies the CVE database
func (d *Downloader) Download(ctx context.Context) error {
	// Expand ~ in destination path
	destPath := d.destPath
	if strings.HasPrefix(destPath, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		destPath = filepath.Join(homeDir, destPath[1:])
	}

	// Ensure parent directory exists
	parentDir := filepath.Dir(destPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Step 1: Fetch remote checksum
	remoteChecksum, err := d.fetchChecksum(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch remote checksum: %w", err)
	}

	// Step 2: Download compressed database to temporary file
	gzPath := destPath + ".gz.tmp"
	if err := d.downloadFile(ctx, d.dbURL, gzPath); err != nil {
		os.Remove(gzPath) // Cleanup on error
		return fmt.Errorf("failed to download database: %w", err)
	}
	defer os.Remove(gzPath) // Cleanup temp file

	// Step 3: Verify downloaded file checksum
	downloadedChecksum, err := d.calculateFileChecksum(gzPath)
	if err != nil {
		return fmt.Errorf("failed to calculate downloaded file checksum: %w", err)
	}

	if downloadedChecksum != remoteChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", remoteChecksum, downloadedChecksum)
	}

	// Step 4: Decompress to final destination
	if err := d.decompressFile(gzPath, destPath); err != nil {
		return fmt.Errorf("failed to decompress database: %w", err)
	}

	return nil
}

// NeedsUpdate checks if the database needs to be updated
// Returns true if remote checksum differs from local checksum
func (d *Downloader) NeedsUpdate() (needsUpdate bool, remoteChecksum string, err error) {
	// Get remote checksum
	remoteChecksum, err = d.fetchChecksum(context.Background())
	if err != nil {
		return false, "", fmt.Errorf("failed to fetch remote checksum: %w", err)
	}

	// Get local checksum
	localChecksum, err := d.GetLocalChecksum()
	if err != nil {
		// If local file doesn't exist, we need to download
		if os.IsNotExist(err) {
			return true, remoteChecksum, nil
		}
		return false, "", fmt.Errorf("failed to get local checksum: %w", err)
	}

	needsUpdate = (localChecksum != remoteChecksum)
	return needsUpdate, remoteChecksum, nil
}

// GetLocalChecksum calculates the checksum of the local database file
func (d *Downloader) GetLocalChecksum() (string, error) {
	destPath := d.destPath
	if strings.HasPrefix(destPath, "~") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		destPath = filepath.Join(homeDir, destPath[1:])
	}

	return d.calculateFileChecksum(destPath)
}

// fetchChecksum fetches the remote checksum file
func (d *Downloader) fetchChecksum(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", d.checksumURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch checksum: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read checksum response: %w", err)
	}

	// Checksum file format: "checksum  filename" or just "checksum"
	checksum := strings.TrimSpace(string(body))
	if idx := strings.Index(checksum, " "); idx > 0 {
		checksum = checksum[:idx]
	}

	return checksum, nil
}

// downloadFile downloads a file from a URL
func (d *Downloader) downloadFile(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create destination file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	// Copy with progress tracking
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// calculateFileChecksum calculates SHA256 checksum of a file
func (d *Downloader) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// decompressFile decompresses a gzip file
func (d *Downloader) decompressFile(gzPath, destPath string) error {
	// Open gzip file
	gzFile, err := os.Open(gzPath)
	if err != nil {
		return fmt.Errorf("failed to open gzip file: %w", err)
	}
	defer gzFile.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// Decompress
	if _, err := io.Copy(destFile, gzReader); err != nil {
		return fmt.Errorf("failed to decompress: %w", err)
	}

	return nil
}
