package scanner

import (
	"context"
	"fmt"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

// Scanner is the interface that all security scanners must implement
// This makes the system highly extensible - new scanners can be added easily
type Scanner interface {
	// Name returns the scanner identifier
	Name() string

	// Description returns what the scanner does
	Description() string

	// Scan performs the security scan
	Scan(ctx context.Context, target models.ScanTarget) ([]models.Finding, error)

	// Enabled returns whether this scanner should run
	Enabled() bool
}

// Registry manages all available scanners
type Registry struct {
	scanners map[string]Scanner
}

// NewRegistry creates a new scanner registry
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry
func (r *Registry) Register(scanner Scanner) {
	r.scanners[scanner.Name()] = scanner
}

// Get retrieves a scanner by name
func (r *Registry) Get(name string) (Scanner, error) {
	scanner, exists := r.scanners[name]
	if !exists {
		return nil, fmt.Errorf("scanner '%s' not found", name)
	}
	return scanner, nil
}

// List returns all registered scanners
func (r *Registry) List() []Scanner {
	scanners := make([]Scanner, 0, len(r.scanners))
	for _, scanner := range r.scanners {
		scanners = append(scanners, scanner)
	}
	return scanners
}

// ScanAll runs all enabled scanners
func (r *Registry) ScanAll(ctx context.Context, target models.ScanTarget) ([]models.Finding, map[string]int, error) {
	var allFindings []models.Finding
	stats := make(map[string]int)

	for _, scanner := range r.scanners {
		if !scanner.Enabled() {
			continue
		}

		findings, err := scanner.Scan(ctx, target)
		if err != nil {
			// Log error but continue with other scanners
			stats[scanner.Name()+"_errors"] = 1
			continue
		}

		allFindings = append(allFindings, findings...)
		stats[scanner.Name()] = len(findings)
	}

	return allFindings, stats, nil
}

// BaseScanner provides common functionality for scanners
type BaseScanner struct {
	name        string
	description string
	enabled     bool
}

// NewBaseScanner creates a base scanner
func NewBaseScanner(name, description string, enabled bool) BaseScanner {
	return BaseScanner{
		name:        name,
		description: description,
		enabled:     enabled,
	}
}

func (b BaseScanner) Name() string        { return b.name }
func (b BaseScanner) Description() string { return b.description }
func (b BaseScanner) Enabled() bool       { return b.enabled }
