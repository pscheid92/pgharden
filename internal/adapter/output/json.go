package output

import (
	"encoding/json"

	"github.com/pscheid92/pgharden/internal/app/report"
	"io"
)

func WriteJSON(w io.Writer, r *report.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
