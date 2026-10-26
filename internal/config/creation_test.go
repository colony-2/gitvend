package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCreationDefaultsValidation(t *testing.T) {
	for _, tt := range []struct {
		name, settings string
		valid          bool
	}{
		{"omitted settings", `{}`, true},
		{"private features off", `{"visibility":"private","has_issues":false,"has_projects":false,"has_wiki":false,"has_pull_requests":false}`, true},
		{"public features on", `{"visibility":"public","has_issues":true,"has_projects":true,"has_wiki":true,"has_pull_requests":true,"pull_request_creation_policy":"collaborators_only"}`, true},
		{"invalid visibility", `{"visibility":"internal"}`, false},
		{"invalid PR policy", `{"pull_request_creation_policy":"nobody"}`, false},
		{"no merge methods", `{"allow_squash_merge":false,"allow_merge_commit":false,"allow_rebase_merge":false}`, false},
		{"unknown option", `{"has_prs":false}`, false},
		{"initial commit forbidden", `{"auto_init":true}`, false},
		{"duplicate option", `{"has_issues":false,"has_issues":true}`, false},
		{"wrong type", `{"has_issues":"false"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig(t)
			b, _ := json.Marshal(c)
			var value map[string]json.RawMessage
			json.Unmarshal(b, &value)
			var providers []map[string]json.RawMessage
			json.Unmarshal(value["providers"], &providers)
			providers[0]["creation_defaults"] = json.RawMessage(tt.settings)
			value["providers"], _ = json.Marshal(providers)
			b, _ = json.Marshal(value)
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := Load(path)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, err=%v", tt.valid, err)
			}
			if err == nil && tt.name == "private features off" {
				d := got.Providers[0].CreationDefaults
				if !d.Private() || d.HasIssues == nil || *d.HasIssues || d.HasPullRequests == nil || *d.HasPullRequests {
					t.Fatal("explicit false lost")
				}
			}
			if err == nil && tt.name == "omitted settings" {
				d := got.Providers[0].CreationDefaults
				if !d.Private() || d.HasIssues != nil || d.HasPullRequests != nil {
					t.Fatal("defaults changed")
				}
			}
		})
	}
}

func TestIndependentProviderCreationDefaults(t *testing.T) {
	c := validConfig(t)
	second := c.Providers[0]
	second.Alias, second.AllowedOwners = "second", []string{"other"}
	second.CreationDefaults.Visibility = "public"
	c.Providers = append(c.Providers, second)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Providers[0].CreationDefaults.Private() || c.Providers[1].CreationDefaults.Private() {
		t.Fatal("provider settings mixed")
	}
}
