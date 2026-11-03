/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package externalgrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"k8s.io/autoscaler/cluster-autoscaler/cloudprovider/externalgrpc/protos"
)

const testServerName = "provider.test"

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

type testLeaf struct {
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
}

var testSerial int64

func nextSerial() *big.Int {
	testSerial++
	return big.NewInt(testSerial)
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, name string, usage x509.ExtKeyUsage) *testLeaf {
	t.Helper()
	return ca.issueValid(t, name, usage, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func (ca *testCA) newIntermediate(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issueValid(t *testing.T, name string, usage x509.ExtKeyUsage, notBefore, notAfter time.Time) *testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return &testLeaf{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

type testFiles struct {
	cert, key, ca string
}

func newTestFiles(t *testing.T) testFiles {
	t.Helper()
	dir := t.TempDir()
	return testFiles{
		cert: filepath.Join(dir, "tls.crt"),
		key:  filepath.Join(dir, "tls.key"),
		ca:   filepath.Join(dir, "ca.crt"),
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func (f testFiles) writeClient(t *testing.T, leaf *testLeaf) {
	t.Helper()
	writeFile(t, f.cert, leaf.certPEM)
	writeFile(t, f.key, leaf.keyPEM)
}

type testServer struct {
	addr string
	peer chan *x509.Certificate
}

func serverTLSConfig(t *testing.T, serverCertPEM []byte, serverKeyPEM []byte, clientCAs *x509.CertPool) *tls.Config {
	t.Helper()
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
}

func startTestServer(t *testing.T, serverLeaf *testLeaf, clientCAs *x509.CertPool, extraChainPEM ...[]byte) *testServer {
	t.Helper()
	certPEM := serverLeaf.certPEM
	for _, extra := range extraChainPEM {
		certPEM = append(append([]byte{}, certPEM...), extra...)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig(t, certPEM, serverLeaf.keyPEM, clientCAs))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	srv := &testServer{addr: listener.Addr().String(), peer: make(chan *x509.Certificate, 16)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := conn.(*tls.Conn)
				_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := tlsConn.Handshake(); err != nil {
					srv.peer <- nil
					return
				}
				srv.peer <- tlsConn.ConnectionState().PeerCertificates[0]
				_, _ = conn.Write([]byte{1})
			}()
		}
	}()
	return srv
}

func (s *testServer) handshake(t *testing.T, cfg *tls.Config) (*x509.Certificate, error) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var clientErr error
	conn, err := tls.DialWithDialer(dialer, "tcp", s.addr, cfg)
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, clientErr = conn.Read(make([]byte, 1))
		_ = conn.Close()
	} else {
		clientErr = err
	}
	var peer *x509.Certificate
	select {
	case peer = <-s.peer:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish the handshake")
	}
	if clientErr != nil {
		return nil, clientErr
	}
	if peer == nil {
		return nil, errors.New("server rejected the handshake")
	}
	return peer, nil
}

func poolOf(pems ...[]byte) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, p := range pems {
		pool.AppendCertsFromPEM(p)
	}
	return pool
}

func TestReloadingTLSConfigUsesRenewedClientCertificate(t *testing.T) {
	ca := newTestCA(t, "ca")
	server := startTestServer(t, ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth), poolOf(ca.pem))
	files := newTestFiles(t)
	writeFile(t, files.ca, ca.pem)

	first := ca.issue(t, "client", x509.ExtKeyUsageClientAuth)
	files.writeClient(t, first)
	cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
	require.NoError(t, err)

	peer, err := server.handshake(t, cfg)
	require.NoError(t, err)
	assert.Equal(t, first.cert.SerialNumber, peer.SerialNumber)

	second := ca.issue(t, "client", x509.ExtKeyUsageClientAuth)
	files.writeClient(t, second)
	peer, err = server.handshake(t, cfg)
	require.NoError(t, err)
	assert.Equal(t, second.cert.SerialNumber, peer.SerialNumber)
	assert.NotEqual(t, first.cert.SerialNumber, peer.SerialNumber)
}

func TestReloadingTLSConfigUsesRenewedKeyWithCertificate(t *testing.T) {
	ca := newTestCA(t, "ca")
	server := startTestServer(t, ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth), poolOf(ca.pem))
	files := newTestFiles(t)
	writeFile(t, files.ca, ca.pem)
	files.writeClient(t, ca.issue(t, "client", x509.ExtKeyUsageClientAuth))
	cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
	require.NoError(t, err)

	renewed := ca.issue(t, "client", x509.ExtKeyUsageClientAuth)
	writeFile(t, files.key, renewed.keyPEM)
	_, err = server.handshake(t, cfg)
	require.Error(t, err, "new key with old certificate must not be used")

	writeFile(t, files.cert, renewed.certPEM)
	peer, err := server.handshake(t, cfg)
	require.NoError(t, err)
	assert.Equal(t, renewed.cert.SerialNumber, peer.SerialNumber)
}

func TestReloadingTLSConfigCABundleWithTwoCAs(t *testing.T) {
	caA := newTestCA(t, "ca-a")
	caB := newTestCA(t, "ca-b")
	clientCA := newTestCA(t, "client-ca")
	files := newTestFiles(t)
	writeFile(t, files.ca, append(append([]byte{}, caA.pem...), caB.pem...))
	files.writeClient(t, clientCA.issue(t, "client", x509.ExtKeyUsageClientAuth))
	cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
	require.NoError(t, err)

	for name, ca := range map[string]*testCA{"first CA": caA, "second CA": caB} {
		t.Run(name, func(t *testing.T) {
			server := startTestServer(t, ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth), poolOf(clientCA.pem))
			_, err := server.handshake(t, cfg)
			assert.NoError(t, err)
		})
	}

	t.Run("CA outside the bundle", func(t *testing.T) {
		other := newTestCA(t, "other")
		server := startTestServer(t, other.issue(t, testServerName, x509.ExtKeyUsageServerAuth), poolOf(clientCA.pem))
		_, err := server.handshake(t, cfg)
		assert.Error(t, err)
	})
}

func TestReloadingTLSConfigRereadsCABundle(t *testing.T) {
	oldCA := newTestCA(t, "old")
	newCA := newTestCA(t, "new")
	clientCA := newTestCA(t, "client-ca")
	files := newTestFiles(t)
	writeFile(t, files.ca, oldCA.pem)
	files.writeClient(t, clientCA.issue(t, "client", x509.ExtKeyUsageClientAuth))
	cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
	require.NoError(t, err)
	server := startTestServer(t, newCA.issue(t, testServerName, x509.ExtKeyUsageServerAuth), poolOf(clientCA.pem))

	_, err = server.handshake(t, cfg)
	require.Error(t, err)

	writeFile(t, files.ca, newCA.pem)
	_, err = server.handshake(t, cfg)
	assert.NoError(t, err)
}

func TestReloadingTLSConfigFailsClosedOnBadFiles(t *testing.T) {
	ca := newTestCA(t, "ca")
	good := ca.issue(t, "client", x509.ExtKeyUsageClientAuth)
	other := ca.issue(t, "client", x509.ExtKeyUsageClientAuth)

	tests := []struct {
		name   string
		mutate func(t *testing.T, f testFiles)
	}{
		{"empty CA file", func(t *testing.T, f testFiles) { writeFile(t, f.ca, nil) }},
		{"garbage CA file", func(t *testing.T, f testFiles) { writeFile(t, f.ca, []byte("not pem")) }},
		{"missing CA file", func(t *testing.T, f testFiles) { require.NoError(t, os.Remove(f.ca)) }},
		{"mismatched cert and key", func(t *testing.T, f testFiles) { writeFile(t, f.key, other.keyPEM) }},
		{"empty cert file", func(t *testing.T, f testFiles) { writeFile(t, f.cert, nil) }},
		{"missing key file", func(t *testing.T, f testFiles) { require.NoError(t, os.Remove(f.key)) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := startTestServer(t, ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth), poolOf(ca.pem))
			files := newTestFiles(t)
			writeFile(t, files.ca, ca.pem)
			files.writeClient(t, good)
			cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
			require.NoError(t, err)
			_, err = server.handshake(t, cfg)
			require.NoError(t, err)

			tc.mutate(t, files)
			_, err = server.handshake(t, cfg)
			assert.Error(t, err)

			_, err = newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
			assert.Error(t, err)
		})
	}
}

func TestReloadingTLSConfigRejectsWrongServerName(t *testing.T) {
	ca := newTestCA(t, "ca")
	server := startTestServer(t, ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth), poolOf(ca.pem))
	files := newTestFiles(t)
	writeFile(t, files.ca, ca.pem)
	files.writeClient(t, ca.issue(t, "client", x509.ExtKeyUsageClientAuth))

	cfg, err := newReloadingTLSConfig("other.test", files.cert, files.key, files.ca)
	require.NoError(t, err)
	_, err = server.handshake(t, cfg)
	require.Error(t, err)
	assert.Contains(t, fmt.Sprint(err), "other.test")
}

func TestReloadingTLSConfigRejectsServerCertWithoutServerAuthUsage(t *testing.T) {
	ca := newTestCA(t, "ca")
	server := startTestServer(t, ca.issue(t, testServerName, x509.ExtKeyUsageClientAuth), poolOf(ca.pem))
	files := newTestFiles(t)
	writeFile(t, files.ca, ca.pem)
	files.writeClient(t, ca.issue(t, "client", x509.ExtKeyUsageClientAuth))

	cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
	require.NoError(t, err)
	_, err = server.handshake(t, cfg)
	assert.Error(t, err)
}

func TestReloadingTLSConfigRejectsEmptyServerName(t *testing.T) {
	ca := newTestCA(t, "ca")
	files := newTestFiles(t)
	writeFile(t, files.ca, ca.pem)
	files.writeClient(t, ca.issue(t, "client", x509.ExtKeyUsageClientAuth))

	cfg, err := newReloadingTLSConfig("", files.cert, files.key, files.ca)
	assert.Error(t, err)
	assert.Nil(t, cfg)

	_, _, err = newExternalGrpcCloudProviderClient([]byte(fmt.Sprintf("address: \":8086\"\ncert: %s\nkey: %s\ncacert: %s\n", files.cert, files.key, files.ca)))
	assert.Error(t, err)
}

func TestReloadingTLSConfigRejectsServerCertOutsideValidity(t *testing.T) {
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{"expired", time.Now().Add(-2 * time.Hour), time.Now().Add(-time.Hour)},
		{"not yet valid", time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t, "ca")
			server := startTestServer(t, ca.issueValid(t, testServerName, x509.ExtKeyUsageServerAuth, tc.notBefore, tc.notAfter), poolOf(ca.pem))
			files := newTestFiles(t)
			writeFile(t, files.ca, ca.pem)
			files.writeClient(t, ca.issue(t, "client", x509.ExtKeyUsageClientAuth))
			cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
			require.NoError(t, err)

			_, err = server.handshake(t, cfg)
			assert.Error(t, err)
		})
	}
}

func TestReloadingTLSConfigVerifiesChainThroughIntermediate(t *testing.T) {
	root := newTestCA(t, "root")
	intermediate := root.newIntermediate(t, "intermediate")
	serverLeaf := intermediate.issue(t, testServerName, x509.ExtKeyUsageServerAuth)
	files := newTestFiles(t)
	writeFile(t, files.ca, root.pem)
	files.writeClient(t, root.issue(t, "client", x509.ExtKeyUsageClientAuth))
	cfg, err := newReloadingTLSConfig(testServerName, files.cert, files.key, files.ca)
	require.NoError(t, err)

	t.Run("intermediate sent by the server", func(t *testing.T) {
		server := startTestServer(t, serverLeaf, poolOf(root.pem), intermediate.pem)
		_, err := server.handshake(t, cfg)
		assert.NoError(t, err)
	})

	t.Run("intermediate not sent", func(t *testing.T) {
		server := startTestServer(t, serverLeaf, poolOf(root.pem))
		_, err := server.handshake(t, cfg)
		assert.Error(t, err)
	})
}

func TestNewExternalGrpcCloudProviderClientHandshakesOverGRPC(t *testing.T) {
	ca := newTestCA(t, "ca")
	serverLeaf := ca.issue(t, "localhost", x509.ExtKeyUsageServerAuth)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLSConfig(t, serverLeaf.certPEM, serverLeaf.keyPEM, poolOf(ca.pem)))))
	protos.RegisterCloudProviderServer(srv, &gpuLabelServer{label: "kmd/gpu"})
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	files := newTestFiles(t)
	writeFile(t, files.ca, ca.pem)
	files.writeClient(t, ca.issue(t, "client", x509.ExtKeyUsageClientAuth))
	configFor := func(address string) []byte {
		return []byte(fmt.Sprintf("address: %s\ncert: %s\nkey: %s\ncacert: %s\n", address, files.cert, files.key, files.ca))
	}
	callGPULabel := func(config []byte) (*protos.GPULabelResponse, error) {
		client, _, err := newExternalGrpcCloudProviderClient(config)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return client.GPULabel(ctx, &protos.GPULabelRequest{})
	}

	resp, err := callGPULabel(configFor("localhost:" + port))
	require.NoError(t, err)
	assert.Equal(t, "kmd/gpu", resp.GetLabel())

	_, err = callGPULabel(configFor("127.0.0.1:" + port))
	assert.Error(t, err)

	writeFile(t, files.ca, newTestCA(t, "other").pem)
	_, err = callGPULabel(configFor("localhost:" + port))
	assert.Error(t, err)
}

type gpuLabelServer struct {
	protos.UnimplementedCloudProviderServer
	label string
}

func (s *gpuLabelServer) GPULabel(context.Context, *protos.GPULabelRequest) (*protos.GPULabelResponse, error) {
	return &protos.GPULabelResponse{Label: s.label}, nil
}

func TestNewExternalGrpcCloudProviderClientTLSConfig(t *testing.T) {
	ca := newTestCA(t, "ca")
	files := newTestFiles(t)
	writeFile(t, files.ca, ca.pem)
	files.writeClient(t, ca.issue(t, "client", x509.ExtKeyUsageClientAuth))

	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{"insecure when cert is empty", "address: localhost:8086\n", false},
		{"valid TLS files", fmt.Sprintf("address: localhost:8086\ncert: %s\nkey: %s\ncacert: %s\n", files.cert, files.key, files.ca), false},
		{"missing CA file", fmt.Sprintf("address: localhost:8086\ncert: %s\nkey: %s\ncacert: %s\n", files.cert, files.key, files.ca+".missing"), true},
		{"missing key file", fmt.Sprintf("address: localhost:8086\ncert: %s\nkey: %s\ncacert: %s\n", files.cert, files.key+".missing", files.ca), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := newExternalGrpcCloudProviderClient([]byte(tc.config))
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
