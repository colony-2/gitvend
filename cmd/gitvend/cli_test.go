package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/colony-2/gitvend/internal/config"
	"github.com/colony-2/gitvend/internal/configutil"
	"gopkg.in/yaml.v3"
)

func TestCobraSetupHelp(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}, {"help"}} {
		var out, errout bytes.Buffer
		if err := run(args, nil, &out, &errout); err != nil || errout.Len() != 0 {
			t.Fatalf("help: %v %s", err, errout.String())
		}
		for _, required := range []string{"GITHUB_TOKEN", "keygen --private", "gitvend.yaml", "public_key_file", "creation_defaults", "has_pull_requests", "gitvend validate", "gitvend sign", "credential --host", "protocol.version 2", "jobdb-gitvend-secret-provider", "completion"} {
			if !strings.Contains(out.String(), required) {
				t.Errorf("missing setup information: %s", required)
			}
		}
	}
	for _, command := range []string{"serve", "validate", "keygen", "sign", "explain", "credential"} {
		var out bytes.Buffer
		if err := run([]string{command, "--help"}, nil, &out, &out); err != nil || !strings.Contains(out.String(), "Flags:") {
			t.Fatalf("%s help: %v", command, err)
		}
	}
}

func TestGatewayHelpYAMLValidatesWithoutStartingServer(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "signing.key"), filepath.Join(dir, "signing.pub")
	var out bytes.Buffer
	if err := run([]string{"keygen", "--private", private, "--public", public}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(gatewaySetupHelp, "       listen:")
	end := strings.Index(gatewaySetupHelp[start:], "\n\n") + start
	c := config.Defaults()
	if err := configutil.Decode([]byte(gatewaySetupHelp[start:end]), &c); err != nil {
		t.Fatal(err)
	}
	c.Keys[0].PublicKeyFile = public
	t.Setenv("GITHUB_TOKEN", "test-upstream-token")
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gitvend.yaml")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"validate", "--config", path}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Gateway configuration, public keys and credentials are valid.\n" {
		t.Fatal(out.String())
	}
}

func TestLegacyFlagsPreserveValuesAndTerminators(t *testing.T) {
	root := newRootCmd()
	for _, tt := range []struct{ in, want []string }{
		{[]string{"sign", "-subject", "-literal", "-permission=github.com/*:r"}, []string{"sign", "--subject", "-literal", "--permission=github.com/*:r"}},
		{[]string{"sign", "--subject", "-literal", "--", "-output"}, []string{"sign", "--subject", "-literal", "--", "-output"}},
		{[]string{"validate", "-c", "-filename"}, []string{"validate", "-c", "-filename"}},
	} {
		if got := legacyFlags(root, tt.in); strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Fatalf("got %v want %v", got, tt.want)
		}
	}
	for _, args := range [][]string{{"serve", "extra"}, {"keygen", "extra"}, {"sign", "--unknown"}, {"credential", "get", "extra"}, {"validate", "--config", "missing.yaml"}} {
		var out, errout bytes.Buffer
		if err := run(args, nil, &out, &errout); err == nil || out.Len() != 0 || errout.Len() != 0 {
			t.Fatalf("invalid command emitted output: %v", args)
		}
	}
}
