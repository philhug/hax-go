package hax

import (
	"bytes"
	"encoding/json"
)

// compactJSON serializes v to compact JSON without HTML escaping.
// This matches Python's json.dumps(v, separators=(",", ":")) byte-for-byte
// for the parts that matter: no spaces, no HTML escaping.
func compactJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// json.Encoder.Encode appends a trailing newline; trim it.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// compactJSONString is a convenience wrapper returning a string.
func compactJSONString(v any) (string, error) {
	b, err := compactJSON(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
