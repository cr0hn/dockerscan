package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

// SARIF (Static Analysis Results Interchange Format)
// Compatible with GitHub Security, Azure DevOps, VS Code, etc.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SARIFReport represents the root of a SARIF document
type SARIFReport struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []SARIFRun  `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool      `json:"tool"`
	Results []SARIFResult  `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	InformationURI  string       `json:"informationUri,omitempty"`
	Rules           []SARIFRule  `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription SARIFMessage       `json:"shortDescription"`
	FullDescription  SARIFMessage       `json:"fullDescription,omitempty"`
	Help             SARIFMessage       `json:"help,omitempty"`
	DefaultLevel     string             `json:"defaultConfiguration,omitempty"`
	Properties       map[string]string  `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// SARIFReporter generates SARIF format reports
type SARIFReporter struct {
	Version string
}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter() *SARIFReporter {
	return &SARIFReporter{
		Version: "2.0.0",
	}
}

// Generate creates a SARIF report from scan results
func (r *SARIFReporter) Generate(result *models.ScanResult) ([]byte, error) {
	sarif := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []SARIFRun{r.buildRun(result)},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// WriteToFile writes the SARIF report to a file
func (r *SARIFReporter) WriteToFile(result *models.ScanResult, filename string) error {
	data, err := r.Generate(result)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func (r *SARIFReporter) buildRun(result *models.ScanResult) SARIFRun {
	run := SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:           "DockerScan",
				Version:        r.Version,
				InformationURI: "https://github.com/cr0hn/dockerscan",
				Rules:          r.buildRules(result),
			},
		},
		Results: r.buildResults(result),
	}

	return run
}

func (r *SARIFReporter) buildRules(result *models.ScanResult) []SARIFRule {
	rulesMap := make(map[string]models.Finding)

	// Collect unique rules
	for _, finding := range result.Findings {
		if _, exists := rulesMap[finding.ID]; !exists {
			rulesMap[finding.ID] = finding
		}
	}

	rules := make([]SARIFRule, 0, len(rulesMap))
	for _, finding := range rulesMap {
		rule := SARIFRule{
			ID:   finding.ID,
			Name: finding.Title,
			ShortDescription: SARIFMessage{
				Text: finding.Title,
			},
			FullDescription: SARIFMessage{
				Text: finding.Description,
			},
			Help: SARIFMessage{
				Text: finding.Remediation,
			},
			Properties: map[string]string{
				"category": finding.Category,
				"severity": string(finding.Severity),
			},
		}
		rules = append(rules, rule)
	}

	return rules
}

func (r *SARIFReporter) buildResults(result *models.ScanResult) []SARIFResult {
	results := make([]SARIFResult, 0, len(result.Findings))

	for _, finding := range result.Findings {
		sarifResult := SARIFResult{
			RuleID: finding.ID,
			Level:  r.severityToSARIFLevel(finding.Severity),
			Message: SARIFMessage{
				Text: finding.Description,
			},
		}

		if finding.Location != nil {
			uri := finding.Location.File
			if uri == "" {
				uri = fmt.Sprintf("layer:%s", finding.Location.Layer)
			}

			sarifResult.Locations = []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: uri,
						},
						Region: &SARIFRegion{
							StartLine: finding.Location.Line,
						},
					},
				},
			}
		}

		results = append(results, sarifResult)
	}

	return results
}

func (r *SARIFReporter) severityToSARIFLevel(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow, models.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}
