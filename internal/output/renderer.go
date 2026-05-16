package output

import (
	"io"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Renderer produces formatted output from a Report.
type Renderer interface {
	Render(*schema.Report, io.Writer) error
}
