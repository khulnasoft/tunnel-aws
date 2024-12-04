package main

import (
	"github.com/khulnasoft/tunnel-aws/pkg/commands"
	"github.com/khulnasoft/tunnel/pkg/log"
)

func main() {
	if err := run(); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}
}

func run() error {
	cmd := commands.NewCmd()
	return cmd.Execute()
}
