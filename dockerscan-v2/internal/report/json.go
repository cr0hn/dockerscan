package report

import (
	"encoding/json"
	"os"

	"github.com/cr0hn/dockerscan/v2/internal/models"
)

// JSONReporter generates JSON format reports
type JSONReporter struct {
	Pretty bool
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(pretty bool) *JSONReporter {
	return &JSONReporter{Pretty: pretty}
}

// Generate creates a JSON report
func (r *JSONReporter) Generate(result *models.ScanResult) ([]byte, error) {
	var data []byte
	var err error

	if r.Pretty {
		data, err = json.MarshalIndent(result, "", "  ")
	} else {
		data, err = json.Marshal(result)
	}

	if err != nil {
		return nil, err
	}

	return data, nil
}

// WriteToFile writes the JSON report to a file
func (r *JSONReporter) WriteToFile(result *models.ScanResult, filename string) error {
	data, err := r.Generate(result)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
