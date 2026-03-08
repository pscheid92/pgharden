package main

import (
	"os"

	"github.com/pscheid92/pgharden/internal/cli"
)

func main() {
	code, err := cli.Execute()
	if err != nil {
		os.Exit(cli.ExitError)
	}
	os.Exit(code)
}
