package main

import (
	"fmt"
	"os"

	"github.com/go-errors/errors"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage %v verb\n", os.Args[0])
	}

	verb := os.Args[1]
	var err error

	if verb == "sniffer" {
		err = runSniffer()
	} else if verb == "reassmble" {
		err = runReassmble()
	} else if verb == "ns-reassmble" {
		err = runNsReassmble()
	}

	switch err := err.(type) {
	case *errors.Error:
		fmt.Printf("Error: %v\n", err.ErrorStack())
	default:
		fmt.Printf("Error: %v\n", err)
	}

	os.Exit(1)
}
