package output

import (
	"encoding/json"
	"io"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// NDJSONRenderer emits one JSON object per line.
type NDJSONRenderer struct{}

func (r *NDJSONRenderer) Render(report *schema.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	for _, f := range report.Findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}
