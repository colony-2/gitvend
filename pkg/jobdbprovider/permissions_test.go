package jobdbprovider

import (
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/colony-2/gitvend/internal/policy"
	"github.com/colony-2/jobdb/pkg/jobdb"
)

func TestTargetPermissionsPreserveActionsSelectorsAndDenies(t *testing.T) {
	p, v, request := testProvider(t)
	c := testConfig()
	tenant := tenantConfig{
		BasePermissions: []string{"github.com/*:r", "!github.com/acme/*#protected:w"},
		TargetPermissions: []string{
			"github.com/acme/*:c",
			"github.com/acme/alpha-*#(main|work/*|protected):rwd",
			"!github.com/acme/*#main:wd",
			"github.com/acme/beta-*:rwc",
		},
	}
	c.Tenants["alpha"] = tenant
	p, err := newProvider(c, p.key, p.now)
	if err != nil {
		t.Fatal(err)
	}
	// The compiled target policy must also own its input.
	tenant.TargetPermissions[0] = "github.com/*:rwc"
	out := resolve(t, p, request)
	base := verify(t, v, out.Secrets[BaseSecretName])
	cell := verify(t, v, out.Secrets[CellSecretName])
	want := append(append([]string(nil), tenant.BasePermissions...),
		"github.com/acme/alpha-one:c",
		"github.com/acme/alpha-one#(main|work/*|protected):rwd",
		"!github.com/acme/alpha-one#main:wd")
	if !reflect.DeepEqual(cell.Claims.Grant.Permissions, want) {
		t.Fatalf("permissions = %v, want %v", cell.Claims.Grant.Permissions, want)
	}
	for _, path := range []string{"acme/alpha-one", "acme/alpha-two", "acme/beta-one", "other/repo"} {
		repo := policy.Repository{Host: "github.com", Path: path, FoldCase: true}
		isTarget := path == "acme/alpha-one"
		if !base.Policy.Read(repo) || !cell.Policy.Read(repo) || base.Policy.Allows(repo, "", "repo.create") || base.Policy.Write(repo, "refs/heads/work/a", "ref.update") {
			t.Fatalf("incorrect base access: %s", path)
		}
		if cell.Policy.Allows(repo, "", "repo.create") != isTarget || cell.Policy.Write(repo, "refs/heads/work/a", "ref.update") != isTarget || cell.Policy.Write(repo, "refs/heads/work/a", "ref.delete") != isTarget {
			t.Fatalf("target permissions leaked or missing: %s", path)
		}
		for _, ref := range []string{"refs/heads/main", "refs/heads/protected", "refs/heads/other", "refs/tags/work/a"} {
			if cell.Policy.Write(repo, ref, "ref.update") {
				t.Fatalf("unauthorized write: %s %s", path, ref)
			}
		}
	}
}

func TestBasePermissionsAreStandardRulesAndTargetMayBeOmitted(t *testing.T) {
	p, v, r := testProvider(t)
	c := testConfig()
	c.Tenants["alpha"] = tenantConfig{BasePermissions: []string{"github.com/acme/shared:rwdc"}}
	p, err := newProvider(c, p.key, p.now)
	if err != nil {
		t.Fatal(err)
	}
	r.AppMetadata = nil
	out := resolve(t, p, r)
	if len(out.Secrets) != 1 {
		t.Fatal("expected only base token")
	}
	id := verify(t, v, out.Secrets[BaseSecretName])
	repo := policy.Repository{Host: "github.com", Path: "acme/shared"}
	if !id.Policy.Write(repo, "refs/heads/main", "ref.delete") || !id.Policy.Allows(repo, "", "repo.create") {
		t.Fatal("base actions were changed")
	}
	r.Names = []string{"gitvend_read_token"}
	if len(resolve(t, p, r).Secrets) != 0 {
		t.Fatal("legacy read token must not silently acquire write permissions")
	}
}

func TestTargetOnlyPolicyAndDenyPrecedence(t *testing.T) {
	for _, rules := range [][]string{
		{"github.com/acme/*:rwc", "!github.com/acme/alpha-*:c"},
		{"!github.com/acme/*:rwc"},
		{"github.com/elsewhere/*:rwc", "!github.com/acme/*:rwc"},
	} {
		p, v, r := testProvider(t)
		c := testConfig()
		c.Tenants["alpha"] = tenantConfig{TargetPermissions: rules}
		p, err := newProvider(c, p.key, p.now)
		if err != nil {
			t.Fatal(err)
		}
		out := resolve(t, p, r)
		if _, exists := out.Secrets[BaseSecretName]; exists {
			t.Fatal("empty base policy issued token")
		}
		if len(rules) == 2 && strings.Contains(rules[0], "acme") {
			id := verify(t, v, out.Secrets[CellSecretName])
			repo := policy.Repository{Host: "github.com", Path: "acme/alpha-one"}
			if id.Policy.Allows(repo, "", "repo.create") || !id.Policy.Write(repo, "refs/heads/main", "ref.update") {
				t.Fatal("target deny lost")
			}
		} else if len(out.Secrets) != 0 {
			t.Fatal("cell without matching target allow issued")
		}
	}
}

func TestPermissionRuleBoundsAndLegacyConfig(t *testing.T) {
	p, _, _ := testProvider(t)
	c := testConfig()
	c.Tenants["alpha"] = tenantConfig{}
	if _, err := newProvider(c, p.key, p.now); err == nil {
		t.Fatal("empty tenant policy accepted")
	}
	rules := make([]string, policy.MaxRules)
	for i := range rules {
		rules[i] = "github.com/*:r"
	}
	c.Tenants["alpha"] = tenantConfig{BasePermissions: rules, TargetPermissions: []string{"github.com/acme/*:rw"}}
	if _, err := newProvider(c, p.key, p.now); err == nil {
		t.Fatal("combined rule limit not enforced")
	}
	path := writeConfig(t, p)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"read_permissions", "cell_write_repositories"} {
		var value map[string]any
		if err := yaml.Unmarshal(b, &value); err != nil {
			t.Fatal(err)
		}
		value["tenants"].(map[string]any)["alpha"].(map[string]any)[field] = []string{"github.com/*:r"}
		data, _ := yaml.Marshal(value)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("legacy field %s silently accepted", field)
		}
	}
}

func TestNarrowedRuleLengthFailsWithoutPartialCredentials(t *testing.T) {
	p, _, request := testProvider(t)
	c := testConfig()
	prefix, suffix := "github.com/*#", ":rw"
	rule := prefix + strings.Repeat("a", policy.MaxPattern-len(prefix)-len(suffix)) + suffix
	c.Tenants["alpha"] = tenantConfig{BasePermissions: []string{"github.com/*:r"}, TargetPermissions: []string{rule}}
	p, err := newProvider(c, p.key, p.now)
	if err != nil {
		t.Fatal(err)
	}
	// This valid template exceeds the gateway rule-length limit once narrowed.
	// The base token was requested first but must not escape a failed resolution.
	out, err := p.ResolveSecrets(t.Context(), request)
	if err != jobdb.ErrSecretResolutionFailed || len(out.Secrets) != 0 {
		t.Fatalf("partial or invalid credentials returned: %v", err)
	}
}
