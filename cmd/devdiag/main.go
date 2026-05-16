package main

import (
	"os"

	"github.com/meedoomostafa/devdiag/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
