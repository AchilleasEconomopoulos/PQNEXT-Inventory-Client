package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/smallstep/certificates/api"
)

func TestEnrollAndRenewIdentity(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	root, rootKey, roots := newTestCA(t, now)
	serverCertificate := newTestServerCertificate(t, root, rootKey, now)
	var serial atomic.Int64
	serial.Store(10)

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var subject pkix.Name
		var publicKey crypto.PublicKey
		switch request.URL.Path {
		case "/sign":
			var signRequest api.SignRequest
			if err := json.NewDecoder(request.Body).Decode(&signRequest); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			if signRequest.CsrPEM.CertificateRequest == nil {
				http.Error(writer, "missing CSR", http.StatusBadRequest)
				return
			}
			subject = signRequest.CsrPEM.Subject
			publicKey = signRequest.CsrPEM.PublicKey
		case "/renew":
			if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
				http.Error(writer, "missing mTLS identity", http.StatusUnauthorized)
				return
			}
			subject = request.TLS.PeerCertificates[0].Subject
			publicKey = request.TLS.PeerCertificates[0].PublicKey
		default:
			http.NotFound(writer, request)
			return
		}

		leaf := issueTestClientCertificate(t, root, rootKey, subject, publicKey, serial.Add(1), now)
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(api.SignResponse{
			ServerPEM:    api.NewCertificate(leaf),
			CaPEM:        api.NewCertificate(root),
			CertChainPEM: []api.Certificate{api.NewCertificate(leaf), api.NewCertificate(root)},
		}); err != nil {
			t.Errorf("encoding CA response: %v", err)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	directory := t.TempDir()
	rootPath := filepath.Join(directory, "bootstrap-root.crt")
	tokenPath := filepath.Join(directory, "scanner.token")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(testToken("scanner-native")), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials := tlsCredentials{
		CAFile:   filepath.Join(directory, "ca.crt"),
		CertFile: filepath.Join(directory, "client.crt"),
		KeyFile:  filepath.Join(directory, "client.key"),
	}
	if err := enrollIdentity(server.URL, tokenPath, rootPath, "scanner-native", credentials); err != nil {
		t.Fatalf("enrollIdentity() error = %v", err)
	}
	first, err := loadAndValidateIdentity(credentials, time.Now())
	if err != nil {
		t.Fatalf("validating enrolled identity: %v", err)
	}
	renewed, err := renewIdentity(server.URL, credentials)
	if err != nil {
		t.Fatalf("renewIdentity() error = %v", err)
	}
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("renewal did not replace the certificate")
	}
	if renewed.Subject.CommonName != "scanner-native" {
		t.Fatalf("renewed common name = %q", renewed.Subject.CommonName)
	}
}

func TestValidateCAURL(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "valid", value: "https://ca.example.test:9000", want: "https://ca.example.test:9000"},
		{name: "trailing slash", value: "https://127.0.0.1:9000/", want: "https://127.0.0.1:9000"},
		{name: "http", value: "http://ca.example.test", wantErr: true},
		{name: "credentials", value: "https://user@ca.example.test", wantErr: true},
		{name: "path", value: "https://ca.example.test/api", wantErr: true},
		{name: "query", value: "https://ca.example.test?token=secret", wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := validateCAURL(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateCAURL() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("validateCAURL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestValidateIssuedIdentity(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	root, rootKey, roots := newTestCA(t, now)
	leaf, leafKey := newTestClientCertificate(t, root, rootKey, now)

	got, err := validateIssuedIdentity([]*x509.Certificate{leaf}, leafKey, roots, now)
	if err != nil {
		t.Fatalf("validateIssuedIdentity() error = %v", err)
	}
	if got != leaf {
		t.Fatal("validateIssuedIdentity() returned a different leaf certificate")
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateIssuedIdentity([]*x509.Certificate{leaf}, wrongKey, roots, now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key error = %v", err)
	}
	leaf.ExtKeyUsage = append(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	if _, err := validateIssuedIdentity([]*x509.Certificate{leaf}, leafKey, roots, now); err == nil || !strings.Contains(err.Error(), "non-client") {
		t.Fatalf("additional EKU error = %v", err)
	}
}

func TestInstallNewIdentity(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	credentials := tlsCredentials{
		CAFile:   filepath.Join(directory, "ca.crt"),
		CertFile: filepath.Join(directory, "client.crt"),
		KeyFile:  filepath.Join(directory, "client.key"),
	}
	root, cert, key := []byte("root"), []byte("cert"), []byte("key")
	if err := installNewIdentity(credentials, root, cert, key); err != nil {
		t.Fatalf("installNewIdentity() error = %v", err)
	}
	assertFileContents(t, credentials.CAFile, root)
	assertFileContents(t, credentials.CertFile, cert)
	assertFileContents(t, credentials.KeyFile, key)
	if info, err := os.Stat(credentials.KeyFile); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("private key mode = %#o, want 0600", got)
	}
	if err := installNewIdentity(credentials, root, cert, key); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second install error = %v", err)
	}
}

func TestRedirectRejectingTransport(t *testing.T) {
	t.Parallel()
	transport := rejectRedirects(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"https://other.example.test"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
		}, nil
	}))
	request, err := http.NewRequest(http.MethodPost, "https://ca.example.test/sign", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Fatalf("RoundTrip() error = %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func newTestCA(t *testing.T, now time.Time) (*x509.Certificate, crypto.Signer, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certificate, key, roots
}

func newTestClientCertificate(t *testing.T, root *x509.Certificate, rootKey crypto.Signer, now time.Time) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "scanner-001"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func newTestServerCertificate(t *testing.T, root *x509.Certificate, rootKey crypto.Signer, now time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test step-ca"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: key}
}

func issueTestClientCertificate(t *testing.T, root *x509.Certificate, rootKey crypto.Signer, subject pkix.Name, publicKey crypto.PublicKey, serial int64, now time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func testToken(subject string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{"sub": subject, "sans": []string{subject}})
	signature := make([]byte, 64)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s contents = %q, want %q", path, got, want)
	}
}
