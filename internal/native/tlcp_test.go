package native

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func tlcpFixture(t *testing.T, variant string) (*tlcp.Config, []byte) {
	t.Helper()
	rootKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &smx509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign}
	rootDER, err := smx509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = smx509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	config := &tlcp.Config{CipherSuites: []uint16{tlcp.ECC_SM4_GCM_SM3, tlcp.ECC_SM4_CBC_SM3}}
	for i := 0; i < 2; i++ {
		key, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &smx509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "gateway.example"}, DNSNames: []string{"gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth}}
		if i == 0 {
			leaf.KeyUsage = smx509.KeyUsageDigitalSignature
		} else {
			leaf.KeyUsage = smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment
		}
		if (variant == "expired-sign" && i == 0) || (variant == "expired-encryption" && i == 1) {
			leaf.NotBefore = time.Now().Add(-2 * time.Hour)
			leaf.NotAfter = time.Now().Add(-time.Hour)
		}
		if variant == "wrong-encryption-name" && i == 1 {
			leaf.DNSNames = []string{"other.example"}
		}
		der, err := smx509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		// Chain roots are supplied once after both leaves by the TLCP server.
		chain := [][]byte{der}
		if i == 1 {
			chain = append(chain, rootDER)
		}
		config.Certificates = append(config.Certificates, tlcp.Certificate{Certificate: chain, PrivateKey: key})
	}
	return config, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

func TestTLCPGatewayVerifiesBothServerCertificates(t *testing.T) {
	for _, variant := range []string{"valid", "wrong-ca", "wrong-name", "expired-sign", "expired-encryption", "wrong-encryption-name"} {
		t.Run(variant, func(t *testing.T) {
			config, ca := tlcpFixture(t, variant)
			listener, err := tlcp.Listen("tcp", "127.0.0.1:0", config)
			if err != nil {
				t.Fatal(err)
			}
			var handlers sync.WaitGroup
			var connectRequests atomic.Int32
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				if request.Method != "CONNECT" {
					t.Error("wrong gateway method")
					return
				}
				connectRequests.Add(1)
				fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\nTLCP-verified\n")
			}()
			t.Cleanup(func() { listener.Close(); handlers.Wait() })
			if variant == "wrong-ca" {
				_, ca = tlcpFixture(t, "valid")
			}
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caPath, ca, 0600); err != nil {
				t.Fatal(err)
			}
			s := exampleSession("https://" + listener.Addr().String())
			s.TLSMode = "tlcp"
			s.CAFile = caPath
			s.ServerName = "gateway.example"
			if variant == "wrong-name" {
				s.ServerName = "other.example"
			}
			if err := s.Validate(time.Now()); err != nil {
				t.Fatal(err)
			}
			d, err := NewDialer(s)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, "tcp", "inside.example:22")
			if variant != "valid" {
				if err == nil {
					conn.Close()
					t.Fatal("invalid TLCP identity accepted")
				}
				if connectRequests.Load() != 0 {
					t.Fatal("resource ticket sent before certificate validation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			data := make([]byte, len("TLCP-verified\n"))
			if _, err := io.ReadFull(conn, data); err != nil || string(data) != "TLCP-verified\n" {
				t.Fatal("TLCP CONNECT lost early data", err)
			}
		})
	}
}

func TestTLCPRejectsSingleLeafPin(t *testing.T) {
	s := exampleSession("https://gateway.example")
	s.TLSMode = "tlcp"
	s.CAFile = "ca.pem"
	s.CertificateSHA256 = strings.Repeat("0", 64)
	if err := s.Validate(time.Now()); err == nil {
		t.Fatal("one fingerprint authorized two TLCP leaves")
	}
}

func TestTLCPDoesNotFallBackToOrdinaryTLS(t *testing.T) {
	var accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("CONNECT reached an ordinary TLS handler") }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	_, ca := tlcpFixture(t, "valid")
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, ca, 0600)
	s := exampleSession(server.URL)
	s.TLSMode = "tlcp"
	s.CAFile = path
	s.ServerName = "gateway.example"
	if err := s.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	d, err := NewDialer(s)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := d.DialContext(ctx, "tcp", "inside.example:22"); err == nil {
		conn.Close()
		t.Fatal("TLCP was silently changed to TLS")
	}
	if accepted.Load() != 1 {
		t.Fatal("handshake failure triggered a transport retry", accepted.Load())
	}
}
