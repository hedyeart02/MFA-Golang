package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("SAMLGuard CLI - Debugging and Administration Utility")
	if len(os.Args) < 2 {
		fmt.Println("Usage: samlguard-cli [command]")
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "parse":
		fmt.Println("Parsing SAML payload... (not implemented)")
	default:
		fmt.Printf("Unknown command: %s\n", command)
	}
}
