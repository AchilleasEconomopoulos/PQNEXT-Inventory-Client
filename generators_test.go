package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCBOMKitLibGenerator(t *testing.T) {
	g, ok := findGenerator("cbomkit-lib")
	if !ok {
		t.Fatal("cbomkit-lib is not registered")
	}
	if !reflect.DeepEqual(g.Modes, []string{"dir"}) || g.Output != "file" {
		t.Fatalf("cbomkit-lib modes=%v output=%q", g.Modes, g.Output)
	}
	for _, tt := range []struct {
		mode string
		want []string
	}{
		{"dir", []string{"theia", "cbomkit-lib"}},
		{"image", []string{"theia"}},
	} {
		selected, err := selectGenerators("", tt.mode)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, generator := range selected {
			names = append(names, generator.Name)
		}
		if !reflect.DeepEqual(names, tt.want) {
			t.Fatalf("default %s generators=%v, want %v", tt.mode, names, tt.want)
		}
	}

	workdir := t.TempDir()
	in := invocation{
		mode: "dir", target: "src", workdir: workdir, uid: 123, gid: 456,
		hostOutFile: filepath.Join(workdir, "output", "cbom.json"), outFile: "/output/cbom.json",
	}
	want := []string{
		"run", "--rm",
		"--volume", workdir + ":/workspace:ro",
		"--volume", filepath.Dir(in.hostOutFile) + ":/output:rw",
		"--workdir", "/workspace", "--user", "123:456",
		g.Image, "--input", "/workspace/src", "--output", "/output/cbom.json",
	}
	if got := g.buildArgs(g, in); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker args=%v, want %v", got, want)
	}
}

func TestFileOutputGeneratorCleansTemporaryMount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mock Docker executable uses a shell script")
	}
	binDir := t.TempDir()
	docker := filepath.Join(binDir, "docker")
	script := `#!/bin/sh
for arg do
  case "$arg" in
    *:/output:rw) output_dir=${arg%:/output:rw} ;;
  esac
done
if [ -z "$output_dir" ]; then exit 9; fi
if [ "$MOCK_DOCKER_FAIL" = 1 ]; then exit 7; fi
printf '{"bomFormat":"CycloneDX","specVersion":"1.6"}' > "$output_dir/cbom.json"
`
	if err := os.WriteFile(docker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	outputRoot := t.TempDir()
	workdir := t.TempDir()
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TMPDIR", outputRoot)
	t.Setenv("MOCK_DOCKER_FAIL", "")
	g, _ := findGenerator("cbomkit-lib")
	in := invocation{mode: "dir", target: ".", workdir: workdir, uid: os.Getuid(), gid: os.Getgid()}

	for _, fail := range []bool{false, true} {
		if fail {
			t.Setenv("MOCK_DOCKER_FAIL", "1")
		}
		data, err := g.run(in)
		if fail {
			if err == nil || !strings.Contains(err.Error(), "code 7") {
				t.Fatalf("failed Docker run error=%v", err)
			}
		} else if err != nil || string(data) != `{"bomFormat":"CycloneDX","specVersion":"1.6"}` {
			t.Fatalf("successful Docker run data=%q error=%v", data, err)
		}
		for _, dir := range []string{outputRoot, workdir} {
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("directory %s after run: entries=%v error=%v", dir, entries, err)
			}
		}
	}
}
