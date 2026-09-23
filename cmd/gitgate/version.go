package main

import "runtime/debug"

// Set by release builds. Development builds fall back to Go's build metadata.
var version, commit, date string

func buildVersion() string {
	info, _ := debug.ReadBuildInfo()
	return versionFromBuild(info)
}

func versionFromBuild(info *debug.BuildInfo) string {
	if version != "" {
		return version
	}
	if info == nil {
		return "development"
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	revision, modified := "", false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return "development"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	result := "development-" + revision
	if modified {
		result += "-dirty"
	}
	return result
}
