package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/smallstep/certificates/api"
	stepca "github.com/smallstep/certificates/ca"
)

const identityRequestTimeout = 30 * time.Second

func runIdentityEnroll(args []string, cfg config) error {
	fs := flag.NewFlagSet("identity enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		tokenFile = fs.String("token-file", "", "path to the one-time step-ca enrollment token (required)")
		rootFile  = fs.String("root", "", "path to the trusted step-ca root CA bundle (required)")
		caURL     = fs.String("ca-url", "", "step-ca base URL (default: server.step-ca in the config file)")
		name      = fs.String("name", "", "expected certificate common name (optional safety check)")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pqnext identity enroll [flags]

Obtains a new CBOMkit client identity using a one-time step-ca token. The
private key is generated locally. Existing certificate or key files are never
overwritten.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("identity enroll does not accept positional arguments")
	}
	if *tokenFile == "" {
		return fmt.Errorf("--token-file is required")
	}
	if *rootFile == "" {
		return fmt.Errorf("--root is required")
	}
	endpoint, err := configuredCAURL(*caURL, cfg)
	if err != nil {
		return err
	}
	return withIdentityLock(func() error {
		return enrollIdentity(endpoint, *tokenFile, *rootFile, strings.TrimSpace(*name), cfg.CBOMKitTLS)
	})
}

func runIdentityRenew(args []string, cfg config) error {
	fs := flag.NewFlagSet("identity renew", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	caURL := fs.String("ca-url", "", "step-ca base URL (default: server.step-ca in the config file)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: pqnext identity renew [flags]

Renews the configured CBOMkit client certificate using its existing mTLS
identity. The private key is retained.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("identity renew does not accept positional arguments")
	}
	endpoint, err := configuredCAURL(*caURL, cfg)
	if err != nil {
		return err
	}
	return withIdentityLock(func() error {
		leaf, err := renewIdentity(endpoint, cfg.CBOMKitTLS)
		if err != nil {
			return err
		}
		fmt.Printf("Renewed identity %q; certificate expires at %s.\n", leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339))
		return nil
	})
}

func runIdentityStatus(args []string, cfg config) error {
	fs := flag.NewFlagSet("identity status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("identity status does not accept arguments")
	}
	leaf, err := loadAndValidateIdentity(cfg.CBOMKitTLS, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("Status:      valid\n")
	fmt.Printf("Subject:     %s\n", leaf.Subject.String())
	fmt.Printf("Serial:      %s\n", leaf.SerialNumber)
	fmt.Printf("Not before:  %s\n", leaf.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not after:   %s\n", leaf.NotAfter.Format(time.RFC3339))
	fmt.Printf("Remaining:   %s\n", time.Until(leaf.NotAfter).Round(time.Second))
	fmt.Printf("Certificate: %s\n", cfg.CBOMKitTLS.CertFile)
	fmt.Printf("Private key: %s\n", cfg.CBOMKitTLS.KeyFile)
	fmt.Printf("CA bundle:   %s\n", cfg.CBOMKitTLS.CAFile)
	return nil
}

func configuredCAURL(flagValue string, cfg config) (string, error) {
	value := strings.TrimSpace(flagValue)
	if value == "" {
		value = strings.TrimSpace(cfg.Servers["step-ca"])
	}
	if value == "" {
		return "", fmt.Errorf("step-ca URL is required: use --ca-url or configure server.step-ca")
	}
	return validateCAURL(value)
}

func validateCAURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parsing step-ca URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("step-ca URL must be an absolute HTTPS URL")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("step-ca URL must not contain user information")
	}
	if (parsed.Path != "" && parsed.Path != "/") || (parsed.RawPath != "" && parsed.RawPath != "/") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("step-ca URL must not contain a path, query, or fragment")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed.String(), nil
}

func enrollIdentity(caURL, tokenPath, rootPath, expectedName string, credentials tlsCredentials) error {
	if err := validateSecretFile(tokenPath, "enrollment token"); err != nil {
		return err
	}
	tokenBytes, err := readLimitedFile(tokenPath, 1<<20)
	if err != nil {
		return fmt.Errorf("reading enrollment token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("enrollment token file is empty")
	}
	rootPEM, roots, err := loadRootBundle(rootPath)
	if err != nil {
		return err
	}
	if err := checkEnrollmentDestinations(credentials, rootPEM); err != nil {
		return err
	}

	transport := newCATransport(roots, nil)
	client, err := stepca.NewClient(caURL,
		stepca.WithTransport(rejectRedirects(transport)),
		stepca.WithCertificate(tls.Certificate{}),
		stepca.WithTimeout(identityRequestTimeout),
	)
	if err != nil {
		return fmt.Errorf("creating step-ca client: %w", err)
	}
	defer client.CloseIdleConnections()
	req, privateKey, err := stepca.CreateSignRequest(token)
	if err != nil {
		return fmt.Errorf("creating certificate request: %w", err)
	}
	if expectedName != "" && req.CsrPEM.Subject.CommonName != expectedName {
		return fmt.Errorf("enrollment token subject %q does not match --name %q", req.CsrPEM.Subject.CommonName, expectedName)
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityRequestTimeout)
	defer cancel()
	response, err := client.SignWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("enrolling with step-ca: %w", err)
	}
	chain, err := certificateChain(response)
	if err != nil {
		return err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("generated private key does not implement crypto.Signer")
	}
	leaf, err := validateIssuedIdentity(chain, signer, roots, time.Now())
	if err != nil {
		return fmt.Errorf("validating issued identity: %w", err)
	}
	if expectedName != "" && leaf.Subject.CommonName != expectedName {
		return fmt.Errorf("issued certificate common name %q does not match --name %q", leaf.Subject.CommonName, expectedName)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := installNewIdentity(credentials, rootPEM, encodeCertificateChain(chain), keyPEM); err != nil {
		return err
	}
	fmt.Printf("Enrolled identity %q; certificate expires at %s.\n", leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339))
	fmt.Printf("Private key: %s\n", credentials.KeyFile)
	return nil
}

func renewIdentity(caURL string, credentials tlsCredentials) (*x509.Certificate, error) {
	currentLeaf, err := loadAndValidateIdentity(credentials, time.Now())
	if err != nil {
		return nil, err
	}
	identity, err := tls.LoadX509KeyPair(credentials.CertFile, credentials.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading current identity: %w", err)
	}
	_, roots, err := loadRootBundle(credentials.CAFile)
	if err != nil {
		return nil, err
	}
	transport := rejectRedirects(newCATransport(roots, &identity))
	client, err := stepca.NewClient(caURL,
		stepca.WithTransport(transport),
		stepca.WithCertificate(tls.Certificate{}),
		stepca.WithTimeout(identityRequestTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("creating step-ca client: %w", err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), identityRequestTimeout)
	defer cancel()
	response, err := client.RenewWithContext(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("renewing with step-ca: %w", err)
	}
	chain, err := certificateChain(response)
	if err != nil {
		return nil, err
	}
	signer, ok := identity.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("current private key does not implement crypto.Signer")
	}
	leaf, err := validateIssuedIdentity(chain, signer, roots, time.Now())
	if err != nil {
		return nil, fmt.Errorf("validating renewed identity: %w", err)
	}
	if leaf.Subject.String() != currentLeaf.Subject.String() {
		return nil, fmt.Errorf("renewed certificate subject %q differs from current subject %q", leaf.Subject, currentLeaf.Subject)
	}
	if err := atomicReplaceFile(credentials.CertFile, encodeCertificateChain(chain), 0o644); err != nil {
		return nil, fmt.Errorf("installing renewed certificate: %w", err)
	}
	return leaf, nil
}

func loadAndValidateIdentity(credentials tlsCredentials, now time.Time) (*x509.Certificate, error) {
	if err := validatePrivateKeyPermissions(credentials.KeyFile); err != nil {
		return nil, err
	}
	identity, err := tls.LoadX509KeyPair(credentials.CertFile, credentials.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading CBOMkit client certificate and key: %w", err)
	}
	_, roots, err := loadRootBundle(credentials.CAFile)
	if err != nil {
		return nil, err
	}
	chain := make([]*x509.Certificate, 0, len(identity.Certificate))
	for _, der := range identity.Certificate {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing client certificate chain: %w", err)
		}
		chain = append(chain, certificate)
	}
	signer, ok := identity.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("client private key does not implement crypto.Signer")
	}
	return validateIssuedIdentity(chain, signer, roots, now)
}

func certificateChain(response *api.SignResponse) ([]*x509.Certificate, error) {
	if response == nil {
		return nil, fmt.Errorf("step-ca returned an empty certificate response")
	}
	certificates := response.CertChainPEM
	if len(certificates) == 0 {
		certificates = []api.Certificate{response.ServerPEM, response.CaPEM}
	}
	chain := make([]*x509.Certificate, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate.Certificate != nil {
			chain = append(chain, certificate.Certificate)
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("step-ca returned no certificates")
	}
	return chain, nil
}

func validateIssuedIdentity(chain []*x509.Certificate, privateKey crypto.Signer, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 || chain[0] == nil {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	leaf := chain[0]
	certPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encoding certificate public key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("encoding private-key public key: %w", err)
	}
	if !bytes.Equal(certPublic, keyPublic) {
		return nil, fmt.Errorf("certificate public key does not match the private key")
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("client certificate is not valid before %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("client certificate expired at %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if !hasClientAuthUsage(leaf) {
		return nil, fmt.Errorf("client certificate does not permit client authentication")
	}
	for _, usage := range leaf.ExtKeyUsage {
		if usage != x509.ExtKeyUsageClientAuth {
			return nil, fmt.Errorf("client certificate contains a non-client extended key usage: %v", usage)
		}
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
	}); err != nil {
		return nil, fmt.Errorf("verifying client certificate chain: %w", err)
	}
	return leaf, nil
}

func loadRootBundle(path string) ([]byte, *x509.CertPool, error) {
	data, err := readLimitedFile(path, 4<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("reading step-ca root bundle %s: %w", path, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, nil, fmt.Errorf("step-ca root bundle %s does not contain a valid PEM certificate", path)
	}
	return data, roots, nil
}

func newCATransport(roots *x509.CertPool, identity *tls.Certificate) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{
		RootCAs:          roots,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
	if identity != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{*identity}
	}
	return transport
}

type redirectRejectingTransport struct {
	next http.RoundTripper
}

func rejectRedirects(next http.RoundTripper) http.RoundTripper {
	return redirectRejectingTransport{next: next}
}

func (transport redirectRejectingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response.Body.Close()
		return nil, fmt.Errorf("step-ca returned a redirect to %q; redirects are not followed", response.Header.Get("Location"))
	}
	return response, nil
}

func (transport redirectRejectingTransport) CloseIdleConnections() {
	if closer, ok := transport.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func validateSecretFile(path, description string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("checking %s %s: %w", description, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s is not a regular file", description, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s %s is accessible by group or other users; use chmod 600", description, path)
	}
	return nil
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func encodeCertificateChain(chain []*x509.Certificate) []byte {
	var output []byte
	for _, certificate := range chain {
		output = append(output, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return output
}

func checkEnrollmentDestinations(credentials tlsCredentials, rootPEM []byte) error {
	for _, path := range []string{credentials.CertFile, credentials.KeyFile} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing identity file %s", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("checking identity file %s: %w", path, err)
		}
	}
	if existing, err := os.ReadFile(credentials.CAFile); err == nil {
		if !bytes.Equal(existing, rootPEM) {
			return fmt.Errorf("refusing to overwrite existing CA bundle %s with different contents", credentials.CAFile)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking CA bundle %s: %w", credentials.CAFile, err)
	}
	return nil
}

func installNewIdentity(credentials tlsCredentials, rootPEM, certPEM, keyPEM []byte) error {
	if err := checkEnrollmentDestinations(credentials, rootPEM); err != nil {
		return err
	}
	installed := make([]string, 0, 3)
	rollback := func() {
		for i := len(installed) - 1; i >= 0; i-- {
			_ = os.Remove(installed[i])
		}
	}
	if _, err := os.Stat(credentials.CAFile); os.IsNotExist(err) {
		if err := installFileNoReplace(credentials.CAFile, rootPEM, 0o644); err != nil {
			return fmt.Errorf("installing CA bundle: %w", err)
		}
		installed = append(installed, credentials.CAFile)
	}
	if err := installFileNoReplace(credentials.CertFile, certPEM, 0o644); err != nil {
		rollback()
		return fmt.Errorf("installing client certificate: %w", err)
	}
	installed = append(installed, credentials.CertFile)
	if err := installFileNoReplace(credentials.KeyFile, keyPEM, 0o600); err != nil {
		rollback()
		return fmt.Errorf("installing private key: %w", err)
	}
	return nil
}

func installFileNoReplace(path string, data []byte, mode os.FileMode) error {
	temporary, err := writeTemporaryFile(path, data, mode)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func atomicReplaceFile(path string, data []byte, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	temporary, err := writeTemporaryFile(path, data, mode)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeTemporaryFile(target string, data []byte, mode os.FileMode) (string, error) {
	directory := filepath.Dir(target)
	if info, err := os.Stat(directory); err != nil {
		return "", fmt.Errorf("checking directory %s: %w", directory, err)
	} else if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", directory)
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(target)+"-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	cleanup := func() {
		file.Close()
		os.Remove(name)
	}
	if err := file.Chmod(mode); err != nil {
		cleanup()
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func withIdentityLock(operation func() error) error {
	directory, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	identityLock := flock.New(filepath.Join(directory, "identity.lock"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	locked, err := identityLock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return fmt.Errorf("locking identity files: %w", err)
	}
	if !locked {
		return fmt.Errorf("another identity operation is in progress")
	}
	defer identityLock.Unlock()
	return operation()
}
