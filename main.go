package main

import (
	"os"

	"github.com/Adversis/tailsnitch/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
