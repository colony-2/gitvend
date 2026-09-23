// Package jsonutil rejects ambiguous and unknown JSON fields at trust boundaries.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := value(d, 0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func value(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON nesting too deep")
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return fmt.Errorf("duplicate or invalid JSON key")
			}
			seen[s] = true
			if e = value(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = value(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter")
	}
	_, e = d.Token()
	return e
}
