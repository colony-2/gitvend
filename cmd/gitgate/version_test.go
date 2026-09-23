package main

import (
	"bytes"
	"runtime/debug"
	"testing"
)

func TestVersion(t *testing.T) {
	for _, tt := range []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{"unavailable", nil, "development"},
		{"empty", &debug.BuildInfo{}, "development"},
		{"installed", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, "v1.2.3"},
		{"clean", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef"}}}, "development-0123456789ab"},
		{"dirty", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef"}, {Key: "vcs.modified", Value: "true"}}}, "development-abcdef-dirty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionFromBuild(tt.info); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
	old := version
	version = "1.2.3"
	t.Cleanup(func() { version = old })
	var out bytes.Buffer
	if err := run([]string{"version"}, nil, &out, &out); err != nil || out.String() != "gitgate version 1.2.3\n" {
		t.Fatalf("%s: %v", out.String(), err)
	}
	if err := run([]string{"version", "unexpected"}, nil, &out, &out); err == nil {
		t.Fatal("accepted extra version argument")
	}
}
