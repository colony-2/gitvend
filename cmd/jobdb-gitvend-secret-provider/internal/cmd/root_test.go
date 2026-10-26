package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func executeTest(args ...string) (string, string, error) {
	root := newRootCmd("test-version")
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{}, args...))
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func TestHelpExplainsSetupWithoutLoadingConfiguration(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}, {"help"}, {"--config", "/missing/issuer.yaml", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, stderr, err := executeTest(args...)
			if err != nil || stderr != "" {
				t.Fatalf("help failed: %v; stderr=%q", err, stderr)
			}
			for _, required := range []string{
				commandName, "gitvend keygen", "signing_key_file", "base_permissions",
				"target_permissions", "validate --config", "providers.json", "--secret-providers-file",
				"gitvend_base_token", "gitvend_cell_token", "AppMetadata.repo", "completion",
				"creation_defaults", "allow_creation", "Migration:",
			} {
				if !strings.Contains(out, required) {
					t.Errorf("help is missing setup detail %q", required)
				}
			}
		})
	}
}

func helpConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signing.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	// Validate the exact sample from --help, rather than a second test-only config.
	sample := []byte(issuerSetupYAML)
	path := filepath.Join(dir, "issuer.yaml")
	if err := os.WriteFile(path, sample, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateHelpExampleAndRelativeKey(t *testing.T) {
	path := helpConfig(t)
	for _, flag := range []string{"--config", "-c"} {
		out, stderr, err := executeTest("validate", flag, path)
		if err != nil || stderr != "" || out != "Configuration and signing key are valid.\n" {
			t.Fatalf("validate failed: %v; stdout=%q; stderr=%q", err, out, stderr)
		}
	}
}

func TestCLIRejectsInvalidArgumentsBeforeStartingPlugin(t *testing.T) {
	for _, args := range [][]string{
		{"validate"}, {"validate", "--config", ""}, {"--config", ""},
		{"validate", "--unknown"}, {"--unknown"}, {"unknown-command"},
		{"validate", "--config", "unused.yaml", "extra"}, {"--config", "unused.yaml", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, err := executeTest(args...)
			if err == nil || stdout != "" || stderr != "" {
				t.Fatalf("expected one returned error with no output: err=%v stdout=%q stderr=%q", err, stdout, stderr)
			}
		})
	}
}

func TestConfigurationErrorsDoNotExposeInputOrWriteProtocolOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.yaml")
	for _, contents := range []string{
		`{"private-secret-canary":`,
		`{"issuer":"jobdb","key_id":"key","signing_key_file":"private-secret-canary"}`,
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"--config", path}, {"validate", "--config", path}} {
			stdout, stderr, err := executeTest(args...)
			if err == nil || strings.Contains(err.Error(), "private-secret-canary") || stdout != "" || stderr != "" {
				t.Fatalf("unsafe configuration error: err=%v stdout=%q stderr=%q", err, stdout, stderr)
			}
		}
	}
}

func TestVersionAndValidateHelp(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		out, stderr, err := executeTest(args...)
		if err != nil || stderr != "" || out != commandName+" version test-version\n" {
			t.Fatalf("version failed: %v; stdout=%q; stderr=%q", err, out, stderr)
		}
	}
	out, stderr, err := executeTest("validate", "--help")
	if err != nil || stderr != "" || !strings.Contains(out, "--config") || !strings.Contains(out, "Ed25519") {
		t.Fatalf("validate help failed: %v; stdout=%q; stderr=%q", err, out, stderr)
	}
}
