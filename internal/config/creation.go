package config

import "fmt"

// CreationDefaults controls newly provisioned repositories on one provider.
// Pointer fields distinguish an omitted setting from an explicit false.
type CreationDefaults struct {
	Visibility                string  `json:"visibility,omitempty" yaml:"visibility,omitempty"`
	Description               *string `json:"description,omitempty" yaml:"description,omitempty"`
	Homepage                  *string `json:"homepage,omitempty" yaml:"homepage,omitempty"`
	HasIssues                 *bool   `json:"has_issues,omitempty" yaml:"has_issues,omitempty"`
	HasProjects               *bool   `json:"has_projects,omitempty" yaml:"has_projects,omitempty"`
	HasWiki                   *bool   `json:"has_wiki,omitempty" yaml:"has_wiki,omitempty"`
	HasPullRequests           *bool   `json:"has_pull_requests,omitempty" yaml:"has_pull_requests,omitempty"`
	PullRequestCreationPolicy string  `json:"pull_request_creation_policy,omitempty" yaml:"pull_request_creation_policy,omitempty"`
	AllowSquashMerge          *bool   `json:"allow_squash_merge,omitempty" yaml:"allow_squash_merge,omitempty"`
	AllowMergeCommit          *bool   `json:"allow_merge_commit,omitempty" yaml:"allow_merge_commit,omitempty"`
	AllowRebaseMerge          *bool   `json:"allow_rebase_merge,omitempty" yaml:"allow_rebase_merge,omitempty"`
	AllowAutoMerge            *bool   `json:"allow_auto_merge,omitempty" yaml:"allow_auto_merge,omitempty"`
	DeleteBranchOnMerge       *bool   `json:"delete_branch_on_merge,omitempty" yaml:"delete_branch_on_merge,omitempty"`
}

// Private retains the existing private-only default unless public is explicit.
func (c CreationDefaults) Private() bool { return c.Visibility != "public" }

func (c CreationDefaults) Validate() error {
	if c.Visibility != "" && c.Visibility != "private" && c.Visibility != "public" {
		return fmt.Errorf("creation_defaults.visibility must be private or public")
	}
	if c.PullRequestCreationPolicy != "" && c.PullRequestCreationPolicy != "all" && c.PullRequestCreationPolicy != "collaborators_only" {
		return fmt.Errorf("creation_defaults.pull_request_creation_policy must be all or collaborators_only")
	}
	if c.AllowSquashMerge != nil && !*c.AllowSquashMerge && c.AllowMergeCommit != nil && !*c.AllowMergeCommit && c.AllowRebaseMerge != nil && !*c.AllowRebaseMerge {
		return fmt.Errorf("creation_defaults must allow at least one merge method")
	}
	return nil
}
