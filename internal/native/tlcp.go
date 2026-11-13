package native

import (
	"errors"
	"os"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

func newTLCPConfig(s *Session) (*tlcp.Config, error) {
	// TLCP has distinct signing and encryption certificates. A fingerprint for
	// just one leaf is not sufficient to establish trust in both identities.
	if s.CAFile == "" || s.CertificateSHA256 != "" {
		return nil, errors.New("TLCP requires explicit CA trust for both server certificates")
	}
	data, err := os.ReadFile(s.CAFile)
	if err != nil {
		return nil, errors.New("read TLCP CA failed")
	}
	roots := smx509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("TLCP CA file contains no supported certificates")
	}
	name := s.ServerName
	if name == "" {
		name = s.gatewayURL.Hostname()
	}
	// The library verifies hostname, time and certificate chains for both
	// server leaves. Never retry a failed TLCP handshake using ordinary TLS.
	return &tlcp.Config{ServerName: name, RootCAs: roots, EnableRFC8998SM2Code: true, MinVersion: tlcp.VersionTLCP, MaxVersion: tlcp.VersionTLCP, CipherSuites: []uint16{tlcp.ECC_SM4_GCM_SM3, tlcp.ECC_SM4_CBC_SM3}}, nil
}
