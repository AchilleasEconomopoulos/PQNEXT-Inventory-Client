package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// defaultConfig is the config template shipped inside the binary. It's
// written to the user's config directory the first time pqnext needs a
// config file and none exists there yet.
//
//go:embed pqnext.conf
var defaultConfig []byte

// knownServers are the backend names configurable via server.<name> entries.
var knownServers = map[string]bool{
	"cbomkit": true,
	"step-ca": true,
}

// configDir returns the OS-appropriate directory pqnext keeps its config file
// in, based on os.UserConfigDir():
//
//	Linux:   $XDG_CONFIG_HOME/pqnext (usually ~/.config/pqnext)
//	macOS:   ~/Library/Application Support/pqnext
//	Windows: %AppData%\pqnext
func configDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating user config directory: %w", err)
	}
	return filepath.Join(dir, "pqnext"), nil
}

func configFilePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "pqnext.conf"), nil
}

// ensureFile returns path, creating it (and its parent directory) from
// template on first use.
func ensureFile(path string, template []byte) (string, error) {
	switch _, err := os.Stat(path); {
	case err == nil:
		return path, nil
	case !os.IsNotExist(err):
		return "", fmt.Errorf("checking %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, template, 0o644); err != nil {
		return "", fmt.Errorf("writing default to %s: %w", path, err)
	}
	return path, nil
}

func ensureConfigFile() (string, error) {
	path, err := configFilePath()
	if err != nil {
		return "", err
	}
	return ensureFile(path, defaultConfig)
}

// config holds settings loaded from the config file that aren't generator
// images (those are applied directly to registry).
type config struct {
	// Servers maps a backend name ("cbomkit" or "step-ca") to its base URL,
	// as set by server.<name> entries in the config file.
	Servers map[string]string
	// CBOMKitTLS identifies the private CA and client identity used for CBOM
	// uploads. Relative paths are resolved from the config file's directory.
	CBOMKitTLS tlsCredentials
}

type tlsCredentials struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// loadConfig reads pqnext's config file — creating it from the built-in
// default template on first use, see ensureConfigFile — a flat KEY=value
// file (# starts a comment, blank lines ignored):
//
//	generator.theia=youruser/cbomkit-theia:1.0.0
//	server.cbomkit=https://<server-ip>:8443
//	server.step-ca=https://<ca-ip>:9000
//	tls.cbomkit.ca=ca.crt
//	tls.cbomkit.cert=client.crt
//	tls.cbomkit.key=client.key
//
// generator.<name> entries override registry[i].Image; server.<name> sets a
// backend's default URL (name must be one of knownServers). tls.cbomkit.*
// entries configure the identity used to post CBOMs over mTLS.
func loadConfig() (config, error) {
	cfg := config{Servers: map[string]string{}}

	path, err := ensureConfigFile()
	if err != nil {
		return cfg, err
	}
	cfg.CBOMKitTLS = tlsCredentials{
		CAFile:   filepath.Join(filepath.Dir(path), "ca.crt"),
		CertFile: filepath.Join(filepath.Dir(path), "client.crt"),
		KeyFile:  filepath.Join(filepath.Dir(path), "client.key"),
	}

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return cfg, fmt.Errorf("%s:%d: expected KEY=value, got %q", path, lineNum, text)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch {
		case strings.HasPrefix(key, "server."):
			name := strings.TrimPrefix(key, "server.")
			if !knownServers[name] {
				return cfg, fmt.Errorf("%s:%d: unknown server %q", path, lineNum, name)
			}
			cfg.Servers[name] = value
		case strings.HasPrefix(key, "tls.cbomkit."):
			credentialPath := value
			if credentialPath != "" {
				if !filepath.IsAbs(credentialPath) {
					credentialPath = filepath.Join(filepath.Dir(path), credentialPath)
				}
				credentialPath = filepath.Clean(credentialPath)
			}

			switch strings.TrimPrefix(key, "tls.cbomkit.") {
			case "ca":
				cfg.CBOMKitTLS.CAFile = credentialPath
			case "cert":
				cfg.CBOMKitTLS.CertFile = credentialPath
			case "key":
				cfg.CBOMKitTLS.KeyFile = credentialPath
			default:
				return cfg, fmt.Errorf("%s:%d: unknown CBOMkit TLS setting %q", path, lineNum, key)
			}
		case strings.HasPrefix(key, "generator."):
			name := strings.TrimPrefix(key, "generator.")
			if value == "" {
				return cfg, fmt.Errorf("%s:%d: empty image for generator %q", path, lineNum, name)
			}
			idx := -1
			for i, g := range registry {
				if g.Name == name {
					idx = i
					break
				}
			}
			if idx == -1 {
				return cfg, fmt.Errorf("%s:%d: unknown generator %q (see 'pqnext list')", path, lineNum, name)
			}
			registry[idx].Image = value
		default:
			return cfg, fmt.Errorf("%s:%d: unknown key %q", path, lineNum, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, fmt.Errorf("reading %s: %w", path, err)
	}
	return cfg, nil
}

// runConfigEdit opens the config file — creating it from the default
// template if it doesn't exist yet — in the user's editor.
func runConfigEdit() error {
	path, err := ensureConfigFile()
	if err != nil {
		return err
	}
	return openInEditor(path)
}

// openInEditor opens path in $VISUAL, then $EDITOR, then an OS default
// (notepad on Windows, vi elsewhere).
func openInEditor(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		if runtime.GOOS == "windows" {
			editor = "notepad"
		} else {
			editor = "vi"
		}
	}

	// Split so "code --wait" style EDITOR values work, not just bare names.
	fields := strings.Fields(editor)
	cmd := exec.Command(fields[0], append(fields[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running editor %q: %w", editor, err)
	}
	return nil
}
