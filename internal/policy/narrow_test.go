package policy

import "testing"

func TestRuleForRepositoryPreservesPolicy(t *testing.T) {
	repo := Repository{Host: "github.com", Path: "org/cell", FoldCase: true}
	for _, text := range []string{
		"github.com/org/*:rwc",
		"!github.com/org/*#(main|work/*):wd",
		`github.com/org/*#work/\(literal\):rw`,
		"github.com/org/*#refs/tags/v*:rwd",
	} {
		original, err := Compile([]string{text})
		if err != nil {
			t.Fatal(err)
		}
		line, ok := original.Rules[0].ForRepository(repo)
		if !ok {
			t.Fatal("matching rule omitted")
		}
		narrowed, err := Compile([]string{line})
		if err != nil {
			t.Fatal(err)
		}
		other := Repository{Host: "github.com", Path: "org/cell-other"}
		if narrowed.Rules[0].MatchesRepository(other) {
			t.Fatal("repository scope widened")
		}
		for _, ref := range []string{"refs/heads/main", "refs/heads/work/a", "refs/heads/work/(literal)", "refs/tags/v1"} {
			for _, action := range []string{"repo.read", "repo.create", "ref.discover", "ref.create", "ref.update", "ref.delete"} {
				before, after := original.Explain(repo, ref, action), narrowed.Explain(repo, ref, action)
				if before.Allowed != after.Allowed || len(before.Denies) != len(after.Denies) {
					t.Fatalf("narrowing changed semantics: %s %s %s", text, ref, action)
				}
			}
		}
		if _, ok := original.Rules[0].ForRepository(Repository{Host: "other.example", Path: "org/cell"}); ok {
			t.Fatal("host mismatch accepted")
		}
	}
}
