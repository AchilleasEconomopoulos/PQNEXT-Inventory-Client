package main

import (
	"fmt"
	"os"
)

var version = "0.3.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if err := runScan(os.Args[2:], cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "list":
		if _, err := loadConfig(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		runList()
	case "config":
		if len(os.Args) < 3 {
			usageConfig()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "edit":
			if err := runConfigEdit(); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
		case "help", "-h", "--help":
			usageConfig()
		default:
			fmt.Fprintln(os.Stderr, "unknown config command:", os.Args[2])
			usageConfig()
			os.Exit(2)
		}
	case "identity":
		if len(os.Args) < 3 {
			usageIdentity()
			os.Exit(2)
		}
		command := os.Args[2]
		if command == "help" || command == "-h" || command == "--help" {
			usageIdentity()
			return
		}
		if command != "enroll" && command != "renew" && command != "status" {
			fmt.Fprintln(os.Stderr, "unknown identity command:", command)
			usageIdentity()
			os.Exit(2)
		}
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		switch command {
		case "enroll":
			err = runIdentityEnroll(os.Args[3:], cfg)
		case "renew":
			err = runIdentityRenew(os.Args[3:], cfg)
		case "status":
			err = runIdentityStatus(os.Args[3:], cfg)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Println("pqnext", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `pqnext — run CBOM generators, merge their output, post to a CBOMkit backend

Usage:
  pqnext <command> [flags]

Commands:
  scan      Run generators against a target, merge CBOMs, optionally post to the backend
  list      List the configured generators
  config    Manage pqnext's config file (edit)
  identity  Enroll, renew, and inspect the CBOMkit mTLS identity
  version   Print the version
  help      Show this help

Run "pqnext scan -h" for scan flags.
Run "pqnext config -h" for config commands.
Run "pqnext identity -h" for identity commands.
`)
}

func usageConfig() {
	fmt.Fprint(os.Stderr, `Usage: pqnext config <command>

Commands:
  edit   Open the config file in your editor (created from defaults on first use)
`)
}

func usageIdentity() {
	fmt.Fprint(os.Stderr, `Usage: pqnext identity <command> [flags]

Commands:
  enroll   Obtain a new client certificate using a one-time token
  renew    Renew the current client certificate using mTLS
  status   Validate the current identity and show its expiration

Run "pqnext identity <command> -h" for command flags.
`)
}
