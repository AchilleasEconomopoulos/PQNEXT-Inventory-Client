package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeriveResourceID(t *testing.T) {
	workdir := t.TempDir()
	absoluteTarget := filepath.Join(workdir, "src")
	for _, tt := range []struct {
		name   string
		mode   string
		target string
		want   string
	}{
		{"relative directory", "dir", "src", absoluteTarget},
		{"absolute directory", "dir", absoluteTarget, absoluteTarget},
		{"cleaned directory", "dir", "src" + string(filepath.Separator) + ".." + string(filepath.Separator) + "app", filepath.Join(workdir, "app")},
		{"image reference", "image", "registry.example.com:5000/app:latest", "registry.example.com:5000/app:latest"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, hostname := range []string{"scanner-01", "scanner-02"} {
				want := hostname + ":" + tt.want
				if got := deriveResourceID(hostname, tt.mode, workdir, tt.target); got != want {
					t.Fatalf("resource id = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestResolveDirScanTarget(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "src")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeTarget, err := filepath.Rel(cwd, target)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		input           string
		workdir         string
		explicitWorkdir bool
		wantMount       string
		wantTarget      string
		wantError       string
	}{
		{"absolute target", target, parent, false, target, ".", ""},
		{"relative target", relativeTarget, parent, false, target, ".", ""},
		{"explicit parent", "src", parent, true, parent, "src", ""},
		{"explicit parent with absolute target", target, parent, true, parent, "src", ""},
		{"outside explicit parent", parent, target, true, "", "", "outside --workdir"},
		{"missing target", filepath.Join(parent, "missing"), parent, false, "", "", "checking scan target"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mount, containerTarget, absoluteTarget, err := resolveDirScanTarget(tt.input, tt.workdir, tt.explicitWorkdir)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mount != tt.wantMount || containerTarget != tt.wantTarget || absoluteTarget != target {
				t.Fatalf("got (%q, %q, %q), want (%q, %q, %q)", mount, containerTarget, absoluteTarget, tt.wantMount, tt.wantTarget, target)
			}
		})
	}
}
