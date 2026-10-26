package configutil

import (
	"strings"
	"testing"
)

type sample struct {
	Name        string   `yaml:"name"`
	Enabled     *bool    `yaml:"enabled"`
	Permissions []string `yaml:"permissions"`
}

func TestYAMLConfiguration(t *testing.T) {
	for _, data := range []string{
		"# setup\nname: issuer\nenabled: false\npermissions:\n  - 'github.com/*:r'\n  - '!github.com/org/*#main:w'\n",
		`{"name":"issuer","enabled":false,"permissions":["github.com/*:r","!github.com/org/*#main:w"]}`,
	} {
		var c sample
		if err := Decode([]byte(data), &c); err != nil {
			t.Fatal(err)
		}
		if c.Name != "issuer" || c.Enabled == nil || *c.Enabled || len(c.Permissions) != 2 || c.Permissions[1] != "!github.com/org/*#main:w" {
			t.Fatalf("wrong YAML values: %#v", c)
		}
	}
}

func TestYAMLRejectsAmbiguousConfiguration(t *testing.T) {
	for _, data := range []string{
		"name: first\nname: second\n", "unknown: true\n", "name: issuer\n---\nname: other\n",
		"name: issuer\n---\n", "permissions: {}\n", "enabled: definitely\n", "name: [list]\n", "",
		`{"name":"first","name":"second"}`, "name: [unterminated", strings.Repeat(" ", (1<<20)+1),
	} {
		var c sample
		if err := Decode([]byte(data), &c); err == nil {
			t.Errorf("invalid configuration accepted: %.80s", data)
		}
	}
}
