package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func runScan(args []string, cfg config) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var (
		mode       = fs.String("mode", "dir", "scan mode: dir | image")
		server     = fs.String("server", "", "CBOMkit backend base URL, e.g. https://<server-ip>:8443 (default: 'server.cbomkit' in the config file, see 'pqnext edit'; empty = do not post)")
		output     = fs.String("output", "merged-cbom.json", "path to write the merged CBOM")
		gens       = fs.String("generators", "", "comma-separated generators to run (default: all that support the mode)")
		workdir    = fs.String("workdir", ".", "host directory mounted at /workspace for dir scans")
		resourceID = fs.String("resource-id", "", "override the backend resource id (default: derived from target)")
		noPost     = fs.Bool("no-post", false, "do not post even if --server is set")
		keep       = fs.Bool("keep", false, "keep each generator's raw CBOM as <output>.<generator>.json")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pqnext scan [flags] <target>

Runs each configured generator against <target>, merges the CBOMs into one,
writes it to --output, and (if --server is set) posts it to the backend.

Arguments:
  <target>   --mode dir:   a path relative to --workdir (e.g. "." or "src")
             --mode image: a container image reference (e.g. "alpine:3.19")

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, `
Examples:
  # Scan the current directory with all generators, write merged-cbom.json
  pqnext scan .

  # Scan ./src and post the result to a remote backend
  pqnext scan --server 'https://<server-ip>:8443' --workdir . src

  # Scan a container image with only theia
  pqnext scan --mode image --generators theia alpine:3.19
`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("exactly one <target> argument is required")
	}
	target := fs.Arg(0)

	if *mode != "dir" && *mode != "image" {
		return fmt.Errorf("--mode must be 'dir' or 'image', got %q", *mode)
	}

	serverURL := *server
	if serverURL == "" {
		serverURL = cfg.Servers["cbomkit"]
	}
	var cbomClient *http.Client
	if serverURL != "" && !*noPost {
		var err error
		cbomClient, serverURL, err = newCBOMHTTPClient(serverURL, cfg.CBOMKitTLS)
		if err != nil {
			return fmt.Errorf("configuring CBOMkit mTLS: %w", err)
		}
	}

	absWorkdir, err := filepath.Abs(*workdir)
	if err != nil {
		return fmt.Errorf("resolving --workdir: %w", err)
	}

	selected, err := selectGenerators(*gens, *mode)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		return fmt.Errorf("no generators support mode %q", *mode)
	}

	in := invocation{
		mode:    *mode,
		target:  target,
		workdir: absWorkdir,
		uid:     os.Getuid(),
		gid:     os.Getgid(),
	}

	var cboms [][]byte
	for _, g := range selected {
		fmt.Fprintf(os.Stderr, "[%s] running %s ...\n", g.Name, g.Image)
		data, err := g.run(in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] FAILED: %v\n", g.Name, err)
			continue
		}
		if !json.Valid(data) {
			fmt.Fprintf(os.Stderr, "[%s] FAILED: output is not valid JSON\n", g.Name)
			continue
		}
		fmt.Fprintf(os.Stderr, "[%s] ok\n", g.Name)
		cboms = append(cboms, data)
		if *keep {
			p := *output + "." + g.Name + ".json"
			if err := os.WriteFile(p, data, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] warning: could not write %s: %v\n", g.Name, p, err)
			}
		}
	}
	if len(cboms) == 0 {
		return fmt.Errorf("all generators failed; nothing to merge")
	}

	merged, err := mergeCBOMs(cboms)
	if err != nil {
		return fmt.Errorf("merging CBOMs: %w", err)
	}
	if err := os.WriteFile(*output, merged, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", *output, err)
	}
	fmt.Fprintf(os.Stderr, "merged %d CBOM(s) -> %s\n", len(cboms), *output)

	if serverURL == "" || *noPost {
		return nil
	}
	rid := *resourceID
	if rid == "" {
		rid = deriveResourceID(*mode, absWorkdir, target)
	}
	if err := postCBOM(cbomClient, serverURL, rid, merged); err != nil {
		return fmt.Errorf("posting to backend: %w", err)
	}
	fmt.Fprintf(os.Stderr, "posted to %s (resource id: %s)\n", serverURL, rid)
	return nil
}

// selectGenerators returns the generators to run. An empty list means "all that
// support the mode". Named generators that don't support the mode are skipped
// with a warning; unknown names are an error.
func selectGenerators(list, mode string) ([]Generator, error) {
	var chosen []Generator
	if strings.TrimSpace(list) == "" {
		for _, g := range registry {
			if supportsMode(g, mode) {
				chosen = append(chosen, g)
			}
		}
		return chosen, nil
	}
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		g, ok := findGenerator(name)
		if !ok {
			return nil, fmt.Errorf("unknown generator %q (see 'pqnext list')", name)
		}
		if !supportsMode(g, mode) {
			fmt.Fprintf(os.Stderr, "skipping %s: does not support mode %q\n", name, mode)
			continue
		}
		chosen = append(chosen, g)
	}
	return chosen, nil
}

// deriveResourceID builds the backend resource id from the target. For dir mode
// it is the absolute, cleaned path (URL-encoding happens at POST time); for
// image mode it is the image reference itself.
func deriveResourceID(mode, absWorkdir, target string) string {
	if mode == "image" {
		return target
	}
	return filepath.Clean(filepath.Join(absWorkdir, target))
}
