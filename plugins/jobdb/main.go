// jobdb-gitvend-secret-provider issues Gitvend credentials over JobDB's plugin protocol.
package main

import (
	"flag"
	"fmt"
	"os"

	secretplugin "github.com/colony-2/jobdb/pkg/jobdb/secrets/plugin"
)

func main() {
	path := flag.String("config", "", "provider JSON configuration file")
	flag.Parse()
	p, err := load(*path)
	if err != nil || flag.NArg() != 0 {
		// Configuration can contain credentials; never print its contents or raw errors.
		fmt.Fprintln(os.Stderr, "gitvend secret provider configuration failed")
		os.Exit(1)
	}
	secretplugin.Serve(p)
}
