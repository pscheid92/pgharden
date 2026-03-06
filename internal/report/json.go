package report

import (
	"encoding/json"
	"io"
)

// WriteJSON writes the report as formatted JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
