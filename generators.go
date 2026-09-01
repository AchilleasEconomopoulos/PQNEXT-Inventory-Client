package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Generator describes one CBOM-producing tool that runs as a Docker container.
//
// Add a new tool by appending an entry to registry below. Keep Image pinned to
// a published, versioned tag so every scan host produces reproducible output.
type Generator struct {
	Name  string   // identifier used with --generators and `list`
	Image string   // pinned Docker image, e.g. "pqca/cbomkit-theia:1.0.0"
	Modes []string // scan modes this tool supports: "dir" and/or "image"

	// Output is where the tool writes its CBOM: "stdout" or "file".
	Output string

	// AcceptExitCodes are non-zero exit codes that still mean "valid CBOM".
	AcceptExitCodes []int

	// buildArgs returns the arguments passed to `docker` (everything after the
	// word "docker") for one invocation.
	buildArgs func(g Generator, in invocation) []string
}

// invocation carries the per-run parameters a generator needs.
type invocation struct {
	mode    string // "dir" or "image"
	target  string // directory subpath (dir mode) or image reference (image mode)
	workdir string // absolute host directory mounted at /workspace (dir mode)
	uid     int
	gid     int

	// outFile is the container-visible path a "file" generator writes to.
	// hostOutFile is the same file as seen on the host. Both are set by run().
	outFile     string
	hostOutFile string
}

// registry holds the built-in generators. Image is a default; it can be
// overridden per generator name via pqnext.conf (see config.go) without
// touching this file.
var registry = []Generator{
	{
		Name:   "theia",
		Image:  "achilleaseconomopoulos/pqnext-theia:latest",
		Modes:  []string{"dir", "image"},
		Output: "stdout",
		buildArgs: func(g Generator, in invocation) []string {
			// Mirrors run-cbomkit-theia.sh: mount the workdir read-only and
			// pass "<mode> <target>". The tool prints the CBOM to stdout.
			return []string{
				"run", "--rm",
				"--volume", in.workdir + ":/workspace:ro",
				"--workdir", "/workspace",
				g.Image,
				in.mode, in.target,
			}
		},
	},
}

func findGenerator(name string) (Generator, bool) {
	for _, g := range registry {
		if g.Name == name {
			return g, true
		}
	}
	return Generator{}, false
}

func supportsMode(g Generator, mode string) bool {
	for _, m := range g.Modes {
		if m == mode {
			return true
		}
	}
	return false
}

func accepts(g Generator, code int) bool {
	if code == 0 {
		return true
	}
	for _, c := range g.AcceptExitCodes {
		if c == code {
			return true
		}
	}
	return false
}

// run executes one generator and returns the raw CBOM bytes it produced.
func (g Generator) run(in invocation) ([]byte, error) {
	// For file-output tools, allocate a temp file inside the mounted workdir so
	// the container can write to it and we can read it back on the host.
	if g.Output == "file" {
		f, err := os.CreateTemp(in.workdir, "."+g.Name+"-cbom-*.json")
		if err != nil {
			return nil, fmt.Errorf("create temp output: %w", err)
		}
		f.Close()
		in.hostOutFile = f.Name()
		defer os.Remove(in.hostOutFile)
		in.outFile = "/workspace/" + filepath.Base(in.hostOutFile)
	}

	args := g.buildArgs(g, in)
	cmd := exec.Command("docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("running docker: %w", err)
		}
	}
	if !accepts(g, code) {
		return nil, fmt.Errorf("%s exited with code %d: %s", g.Name, code, strings.TrimSpace(stderr.String()))
	}

	switch g.Output {
	case "stdout":
		return stdout.Bytes(), nil
	case "file":
		data, err := os.ReadFile(in.hostOutFile)
		if err != nil {
			return nil, fmt.Errorf("reading %s output: %w", g.Name, err)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("generator %s: unknown output mode %q", g.Name, g.Output)
	}
}

func runList() {
	fmt.Println("Configured generators:")
	for _, g := range registry {
		fmt.Printf("  %-12s image=%s  modes=%s  output=%s\n",
			g.Name, g.Image, strings.Join(g.Modes, ","), g.Output)
	}
}
