//go:build linux

package sandbox

import (
	"encoding/json"
	"io"
)

func newJSONEncoder(w io.Writer) *json.Encoder {
	return json.NewEncoder(w)
}

func newJSONDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(r)
}
