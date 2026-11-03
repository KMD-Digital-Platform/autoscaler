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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func loadClientKeyPair(certPath, keyPath string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("could not open Cert configuration file %q: %v", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not open Key configuration file %q: %v", keyPath, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert key pair: %v", err)
	}
	return &cert, nil
}

func loadCAPool(caPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("could not open Cacert configuration file %q: %v", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse ca: no certificates found in %q", caPath)
	}
	return pool, nil
}

// newReloadingTLSConfig returns a client TLS config that reads the client key pair and the CA bundle
// from disk on every handshake, so rotated files are picked up without a restart.
// The server certificate is verified against the freshly read CA bundle and serverName; there is no
// fallback to system roots.
func newReloadingTLSConfig(serverName, certPath, keyPath, caPath string) (*tls.Config, error) {
	if serverName == "" {
		return nil, errors.New("TLS requires a host in the configured address to verify the server name")
	}
	if _, err := loadClientKeyPair(certPath, keyPath); err != nil {
		return nil, err
	}
	if _, err := loadCAPool(caPath); err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName: serverName,
		// Chain and name verification happen in VerifyConnection against the CA bundle read per handshake.
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadClientKeyPair(certPath, keyPath)
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			roots, err := loadCAPool(caPath)
			if err != nil {
				return err
			}
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				DNSName:       serverName,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			return err
		},
		MinVersion: tls.VersionTLS12,
	}, nil
}
