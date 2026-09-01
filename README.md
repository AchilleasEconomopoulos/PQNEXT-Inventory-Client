# pqnext

Runs one or more containerized CBOM generators against a target, merges their
output into a single CycloneDX CBOM, and optionally posts it to a CBOMkit
backend. Built-in generators: `theia`.

## Prerequisites

- Docker for `scan` (the generators run as containers). Identity enrollment
  and renewal are native Go operations and do not require Docker or `step`.
- Go 1.27.0+ to build the binary.

## Build

```sh
go build -o pqnext .
```

This produces a single static binary. Cross-compile for other hosts with, e.g.:

```sh
GOOS=linux   GOARCH=amd64 go build -o pqnext-linux-amd64 .
GOOS=darwin  GOARCH=arm64 go build -o pqnext-darwin-arm64 .
```

## Continuous integration and releases

GitHub Actions checks formatting with `gofmt`, runs `go vet` and the race-enabled
test suite, and builds a static Linux AMD64 binary on pushes to `main` and pull
requests. Push a version tag such as `v0.3.0` to run the same checks and, if they
pass, publish a GitHub release containing `pqnext-linux-amd64` and its SHA-256
checksum.

## Commands

### `scan` — run generators, merge, and post

```
pqnext scan [flags] <target>
```

Runs each selected generator against `<target>`, merges the resulting CBOMs
into one, writes it to `--output`, and (if `--server` is set) posts it to the
backend. If some generators fail, the rest are still merged; the command only
errors if *all* of them fail.

**Argument**

| Argument   | Meaning |
|------------|---------|
| `<target>` | With `--mode dir`: a path relative to `--workdir` (e.g. `.` or `src`). With `--mode image`: a container image reference (e.g. `alpine:3.19`). |

**Flags**

| Flag            | Default            | Description |
|-----------------|--------------------|-------------|
| `--mode`        | `dir`              | `dir` scans a directory; `image` scans a container image. |
| `--workdir`     | `.`                | Host directory mounted at `/workspace` for `dir` scans. `<target>` is relative to this. |
| `--generators`  | *(all)*            | Comma-separated subset to run, e.g. `theia`. Default runs all that support the mode. |
| `--server`      | `server.cbomkit` in the config file | CBOMkit mTLS base URL, e.g. `https://<server-ip>:8443`. It must use HTTPS and an IP literal. Empty (flag and config) means do not post. |
| `--output`      | `merged-cbom.json` | Where to write the merged CBOM. |
| `--resource-id` | *(derived)*        | Override the backend resource id. Default: absolute target path (`dir`) or the image reference (`image`). |
| `--no-post`     | `false`            | Produce the merged CBOM but skip posting even if `--server` is set. |
| `--keep`        | `false`            | Also write each generator's raw CBOM as `<output>.<generator>.json` for debugging. |

**Examples**

```sh
# Scan the current directory with all generators -> merged-cbom.json
pqnext scan .

# Scan ./src and post the result to a remote backend over mTLS
pqnext scan --server 'https://<server-ip>:8443' --workdir . src

# Scan a container image with only theia
pqnext scan --mode image --generators theia alpine:3.19

# Produce a CBOM without posting, keeping each tool's raw output
pqnext scan --no-post --keep .
```

### `list` — show configured generators

```
pqnext list
```

Prints each generator's name, pinned image, supported modes, and output mode.

### `config edit` — open the config file

```
pqnext config edit
```

Opens the config file in `$VISUAL`, then `$EDITOR`, then an OS default
(`notepad` on Windows, `vi` elsewhere). If the file doesn't exist yet, it's
created first from the built-in default template.

### `identity enroll` — obtain a client identity

```sh
pqnext identity enroll \
  --ca-url https://<ca-ip>:9000 \
  --root /path/to/ca.crt \
  --token-file /path/to/client.token \
  --name scanner-001
```

Generates a private key locally and exchanges the one-time token for a
`clientAuth` certificate using step-ca's native Go client. The token file must
be a regular file readable only by its owner (normally mode `0600`). `--name`
is optional; when present, enrollment rejects a certificate with a different
common name.

The root CA is copied to `tls.cbomkit.ca`, and the new certificate and key are
written to `tls.cbomkit.cert` and `tls.cbomkit.key`. Existing certificate or key
files are never overwritten. The configured root is reused only if its contents
exactly match `--root`.

`--ca-url` may be omitted when `server.step-ca` is configured. The CA URL must
be an absolute HTTPS URL without credentials, a path, query, or fragment.
Connections require TLS 1.3, trust only the supplied root, and do not follow
redirects.

### `identity renew` — renew the client certificate

```sh
pqnext identity renew
```

Renews the configured certificate through step-ca using the current mTLS
identity. The returned chain and subject are validated before the certificate
is atomically replaced; the existing private key is retained. Use `--ca-url`
to override `server.step-ca`.

For 24-hour certificates, schedule this command with the host's service
manager, such as a systemd timer. Concurrent enrollment and renewal operations
are serialized with a filesystem lock.

### `identity status` — inspect the client identity

```sh
pqnext identity status
```

Validates the key permissions, key/certificate match, trust chain,
`clientAuth` usage, and validity period, then prints the subject and expiration.

### `version` — print the version

```
pqnext version
```

## Configuration

Generators are defined in `generators.go` in the `registry` slice: name,
supported modes, output mode, and how to invoke them. To add a tool, append
an entry there.

Four things are configured in a per-user file, so they can be changed without
touching code or rebuilding: each generator's Docker **image**, the CBOMkit
default **server** URL, the step-ca **server** URL, and the CBOMkit mTLS
**credentials**. Edit it with:

```sh
pqnext config edit
```

The file lives in the OS-standard per-user config location (via Go's
`os.UserConfigDir()`):

| OS      | Directory |
|---------|-----------|
| Linux   | `$XDG_CONFIG_HOME/pqnext` (usually `~/.config/pqnext`) |
| macOS   | `~/Library/Application Support/pqnext` |
| Windows | `%AppData%\pqnext` |

It does not depend on the current directory — it applies no matter where you
run `pqnext` from. The first time `pqnext` needs it and it doesn't exist yet,
it's created from the default template embedded in the binary (source:
[`pqnext.conf`](pqnext.conf) in this repo).

`pqnext.conf` is a flat `KEY=value` format — `#` starts a comment, blank
lines are ignored:

```sh
# Docker image for each generator (see `pqnext list` for names). Overrides
# the default baked into generators.go.
generator.theia=achilleaseconomopoulos/pqnext-theia:latest

# Default CBOMkit backend base URL used by `pqnext scan` when --server isn't
# passed. It must use an IP literal and HTTPS, for example:
# server.cbomkit=https://<server-ip>:8443
# Leave empty to require --server explicitly.
server.cbomkit=

# Private CA and client identity used for CBOMkit mTLS. Relative paths are
# resolved from this configuration file's directory.
tls.cbomkit.ca=ca.crt
tls.cbomkit.cert=client.crt
tls.cbomkit.key=client.key

# step-ca endpoint used by identity enrollment and renewal.
server.step-ca=https://<ca-ip>:9000
```

Every rule is optional:

- Omit a `generator.<name>` line (or set it to the empty template default) to
  keep the built-in image — but every name present must match a generator
  already in `registry`.
- Omit or leave `server.cbomkit` empty to require `--server` explicitly for
  `scan`; `--server` always overrides it when passed.
- Omit or leave `server.step-ca` empty to require `--ca-url` explicitly for
  `identity enroll` and `identity renew`; `--ca-url` always overrides it.
- Omit the `tls.cbomkit.*` entries to use `ca.crt`, `client.crt`, and
  `client.key` beside `pqnext.conf`. Absolute paths are accepted; relative
  paths are resolved from the config directory.

### CBOMkit mTLS

Every CBOM upload requires mTLS. Before running scanners, pqnext rejects a
non-HTTPS server, a DNS hostname, missing or invalid credentials, an expired
certificate, and a certificate without `clientAuth` usage. The configured CA
bundle is the only trust store used for the CBOMkit connection, and redirects
are not followed.

The server URL must contain the server's IP address, and that IP must be in the
server certificate's Subject Alternative Name. `ca.crt` must contain the
private CA trust chain. `client.crt` must contain the client leaf followed by
any intermediate certificates needed to reach that CA.

`client.key` must be an unencrypted PEM private key. On Linux and macOS it
must not be accessible by group or other users; mode `0600` is the normal
setting:

```sh
chmod 600 client.key
```

TLS connections require TLS 1.3 and explicitly enable hybrid
X25519+ML-KEM-768 key exchange with X25519 as the interoperability fallback.
Use `pqnext identity enroll` with the one-time token produced by the step-ca
project, and schedule `pqnext identity renew` before the current 24-hour client
certificate expires.

> Pin real, versioned tags (e.g. `youruser/cbomkit-theia:1.0.0`) instead of
> `:latest` — that's what makes scans reproducible across hosts and over time.

## Merge limitations

The merge is **structural**: the first successful CBOM is kept as the base
(its `specVersion` and `metadata` are preserved), and components and
dependencies from all generators are combined into it, de-duplicated by
`bom-ref` (falling back to name+version+purl for components). It does **not**:

- reconcile `metadata.tools` across differing spec versions;
- understand dependency entries beyond the `ref` / `dependsOn` shape.

For full-fidelity CycloneDX merging, swap the structural merge in `merge.go`
for the `cyclonedx-go` library.
