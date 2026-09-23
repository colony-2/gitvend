package policy

import "testing"

func must(t *testing.T, lines ...string) *Policy {
	t.Helper()
	p, e := Compile(lines)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPermissions(t *testing.T) {
	p := must(t, "github.com/fooorg/*:r", "github.com/fooorg/blue*:wd", "!github.com/fooorg/*#(main|master):wd")
	for _, tt := range []struct {
		repo, ref, act string
		want           bool
	}{{"fooorg/blue", "refs/heads/agent/task/fix", "ref.update", true}, {"fooorg/bluer", "refs/heads/master", "ref.delete", false}, {"fooorg/red", "refs/heads/task", "ref.update", false}, {"fooorg/blue", "refs/tags/v1", "ref.create", true}, {"other/blue", "refs/heads/task", "ref.create", false}} {
		if got := p.Write(Repository{"github.com", tt.repo, true}, tt.ref, tt.act); got != tt.want {
			t.Errorf("%+v got %v", tt, got)
		}
	}
}
func TestReadBoundary(t *testing.T) {
	r := Repository{"github.com", "org/repo", true}
	p := must(t, "github.com/org/repo#main:rw", "!github.com/org/repo#secret/*:r")
	if !p.Read(r) || !p.Discover(r, "refs/heads/main") || p.Discover(r, "refs/heads/secret/x") || p.Discover(r, "refs/tags/main") {
		t.Fatal("read boundary")
	}
	p = must(t, "github.com/*:rw", "!github.com/org/repo:r")
	if p.Read(r) || p.Write(r, "refs/heads/main", "ref.update") {
		t.Fatal("repo deny")
	}
}
func TestGlobs(t *testing.T) {
	for _, tt := range []struct {
		pattern, path, ref string
		want               bool
	}{{"gitlab.com/*:r", "org/team/repo", "refs/heads/main", true}, {"gitlab.com/org/*:r", "org/team/repo", "refs/heads/main", false}, {"gitlab.com/org/**/repo:r", "org/repo", "refs/heads/main", true}, {"gitlab.com/org/**/repo:r", "org/team/sub/repo", "refs/heads/main", true}, {"gitlab.com/org/**:r", "org/team/repo", "refs/heads/main", true}, {"github.com/org/(blue|green)*#(main|release/*):r", "org/bluebird", "refs/heads/release/1/fix", true}, {`github.com/org/repo#topic\(test\):r`, "org/repo", "refs/heads/topic(test)", true}, {"github.com/org/repo#main:r", "org/repo", "refs/heads/main-old", false}} {
		p := must(t, tt.pattern)
		host := p.Rules[0].Host
		if got := p.Discover(Repository{host, tt.path, false}, tt.ref); got != tt.want {
			t.Errorf("%+v got %v", tt, got)
		}
	}
}
func TestInvalid(t *testing.T) {
	for _, s := range []string{"github.com/org/*:rr", "github.com/org/*:x", "github.com/org/r#main:c", "github.com/org/r#(a|):r", "github.com/org/r#((a|b)|c):r", "*.com/org/r:r", "github.com/org/r#refs/*:r", "github.com/org/r#foo**:r", "github.com/org/r#foo?:r", "github.com/org/r:r\\", "github.com/org/r#:r"} {
		if _, e := Compile([]string{s}); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestIntersection(t *testing.T) {
	r := Repository{"github.com", "org/repo", false}
	for _, tt := range []struct {
		rules []string
		want  bool
	}{{[]string{"github.com/org/repo#agents/*:rw"}, true}, {[]string{"github.com/org/repo#(a|b):r", "github.com/org/repo#b:w"}, true}, {[]string{"github.com/org/repo#main:r", "github.com/org/repo#agent/*:w"}, false}, {[]string{"github.com/org/repo#agents/*:rw", "!github.com/org/repo#agents/*:w"}, false}, {[]string{"github.com/org/repo#(a|b):rw", "!github.com/org/repo#a:r", "!github.com/org/repo#b:w"}, false}, {[]string{"github.com/org/repo#x.lock:rw"}, false}, {[]string{"github.com/org/repo#x..y:rw"}, false}, {[]string{"github.com/org/repo#refs/tags/*:rw"}, false}, {[]string{"github.com/org/repo#*:rw", "!github.com/org/repo#(main|master):w"}, true}} {
		p := must(t, tt.rules...)
		got, err := p.CanWrite(r, true)
		if err != nil || got != tt.want {
			t.Errorf("%v got %v %v", tt.rules, got, err)
		}
	}
}
func FuzzCompile(f *testing.F) {
	for _, s := range []string{"github.com/org/r#(main|a/*):rw", "github.com/*:r", "github.com/org/**/r:r"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, e := Compile([]string{s})
		if e == nil {
			p.Discover(Repository{"github.com", "org/r", true}, "refs/heads/main")
		}
	})
}
