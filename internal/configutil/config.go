// Package configutil decodes strict, single-document YAML configuration.
// JSON wire protocols use jsonutil separately.
package configutil

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

func Decode(data []byte, dst any) error {
	if len(data) > 1<<20 {
		return fmt.Errorf("configuration too large")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid YAML configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("configuration must contain exactly one YAML document")
	}
	return nil
}
