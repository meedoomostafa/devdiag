package output

import (
	"encoding/json"
	"io"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// JSONRenderer emits valid JSON to stdout with no banners.
type JSONRenderer struct{}

func (r *JSONRenderer) Render(report *schema.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
