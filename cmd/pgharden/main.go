package main

import (
	"os"

	"github.com/pgharden/pgharden/internal/cli"
)

func main() {
	code, err := cli.Execute()
	if err != nil {
		os.Exit(cli.ExitError)
	}
	os.Exit(code)
}
