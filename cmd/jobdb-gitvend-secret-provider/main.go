// jobdb-gitvend-secret-provider issues Gitvend credentials over JobDB's plugin protocol.
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/colony-2/gitvend/cmd/jobdb-gitvend-secret-provider/internal/cmd"
)

// Set with -ldflags for release builds. go install builds use module metadata.
var version string

func main() {
	if version == "" {
		version = "development"
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
	code, err := cmd.Execute(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(code)
}
