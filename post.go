package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

func newCBOMHTTPClient(server string, credentials tlsCredentials) (*http.Client, string, error) {
	base, err := validateCBOMServerURL(server)
	if err != nil {
		return nil, "", err
	}

	if credentials.CAFile == "" || credentials.CertFile == "" || credentials.KeyFile == "" {
		return nil, "", fmt.Errorf("tls.cbomkit.ca, tls.cbomkit.cert, and tls.cbomkit.key are all required")
	}
	if err := validatePrivateKeyPermissions(credentials.KeyFile); err != nil {
		return nil, "", err
	}

	caPEM, err := os.ReadFile(credentials.CAFile)
	if err != nil {
		return nil, "", fmt.Errorf("reading CBOMkit CA bundle %s: %w", credentials.CAFile, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, "", fmt.Errorf("CBOMkit CA bundle %s does not contain a valid PEM certificate", credentials.CAFile)
	}

	identity, err := tls.LoadX509KeyPair(credentials.CertFile, credentials.KeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("loading CBOMkit client certificate and key: %w", err)
	}
	if len(identity.Certificate) == 0 {
		return nil, "", fmt.Errorf("CBOMkit client certificate %s is empty", credentials.CertFile)
	}
	if identity.Leaf == nil {
		identity.Leaf, err = x509.ParseCertificate(identity.Certificate[0])
		if err != nil {
			return nil, "", fmt.Errorf("parsing CBOMkit client certificate %s: %w", credentials.CertFile, err)
		}
	}

	now := time.Now()
	if now.Before(identity.Leaf.NotBefore) {
		return nil, "", fmt.Errorf("CBOMkit client certificate is not valid before %s", identity.Leaf.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(identity.Leaf.NotAfter) {
		return nil, "", fmt.Errorf("CBOMkit client certificate expired at %s", identity.Leaf.NotAfter.Format(time.RFC3339))
	}
	if !hasClientAuthUsage(identity.Leaf) {
		return nil, "", fmt.Errorf("CBOMkit client certificate does not permit client authentication")
	}

	intermediates := x509.NewCertPool()
	for _, der := range identity.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, "", fmt.Errorf("parsing CBOMkit client certificate chain: %w", err)
		}
		intermediates.AddCert(certificate)
	}
	if _, err := identity.Leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
	}); err != nil {
		return nil, "", fmt.Errorf("verifying CBOMkit client certificate chain: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = &tls.Config{
		Certificates:     []tls.Certificate{identity},
		RootCAs:          roots,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, base, nil
}

func validateCBOMServerURL(server string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(server), "/")
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parsing CBOMkit server URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("CBOMkit server URL must use https")
	}
	if parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("CBOMkit server URL must be an absolute HTTPS URL")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("CBOMkit server URL must not contain user information")
	}
	if net.ParseIP(parsed.Hostname()) == nil {
		return "", fmt.Errorf("CBOMkit server URL host must be an IP address")
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("CBOMkit server URL must not contain a path, query, or fragment")
	}
	return base, nil
}

func validatePrivateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("checking CBOMkit client key %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("CBOMkit client key %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("CBOMkit client key %s is accessible by group or other users; use chmod 600", path)
	}
	return nil
}

func hasClientAuthUsage(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

// postCBOM sends the merged CBOM to the CBOMkit backend at
//
//	{server}/api/v1/cbom/{resourceID}
//
// The resource id is URL-encoded so a filesystem path survives as a single
// path segment (e.g. "/" -> "%2F")
func postCBOM(client *http.Client, server, resourceID string, body []byte) error {
	base := strings.TrimRight(server, "/")
	endpoint := base + "/api/v1/cbom/" + url.QueryEscape(resourceID)

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("backend returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
