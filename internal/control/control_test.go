package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestLegacyInteroperabilityAndBounds(t *testing.T) {
	// Independent fixture: Python zlib level 9, OpenSSL AES-128-CBC and Base64.
	fixture := []byte("afcYC8MTtDQ8DRqgMX1soB+N6LsSzaeVMrvNcejD/ME=")
	plain := []byte(`{"PinCode":"4CU4PD"}`)
	decoded, err := DecodeLegacy(fixture)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatalf("independent fixture: %q, %v", decoded, err)
	}
	encoded, err := EncodeLegacy(plain)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = DecodeLegacy(encoded)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("round trip failed")
	}
	for _, invalid := range [][]byte{nil, []byte("invalid"), []byte("AAAAAAAAAAAAAAAAAAAAAA=="), bytes.Repeat([]byte{'a'}, (2<<20)+1)} {
		if _, err := DecodeLegacy(invalid); err == nil {
			t.Fatal("accepted invalid or oversized ciphertext")
		}
	}
	compressedBomb, err := EncodeLegacy(bytes.Repeat([]byte{'a'}, (1<<20)+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLegacy(compressedBomb); err == nil {
		t.Fatal("accepted oversized decompressed response")
	}
}

func TestRegistrationWireAndError(t *testing.T) {
	c, _ := NewClient("https://control.example")
	c.GUID, c.TenantID, c.Machine = DeviceGUID("our-random-seed"), "123", "MacBook-Pro"
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("guid") != c.GUID || !r.URL.Query().Has("mid") || r.URL.Query().Get("cmd") != "10006001" || r.Header.Get("Proto-Cmd") != "10006001" {
			t.Fatal("missing command or device URL parameters")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["Machine"] != "MacBook-Pro" || body["MachineGuid"] != c.GUID {
			t.Fatal("registration must use plaintext JSON inside HTTPS")
		}
		if _, exists := body["CompanyId"]; exists {
			t.Fatal("initial registration must not substitute TenantID for CompanyId")
		}
		return mockResponse(`{"RetCode":10,"Mid":""}`), nil
	})
	r, err := c.Register(context.Background())
	if err == nil || r == nil {
		t.Fatal("refused registration must preserve response and return an error")
	}
}

func TestOrganizationEncoding(t *testing.T) {
	c, _ := NewClient("https://control.example")
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(r.Body)
		plain, err := DecodeLegacy(data)
		if err != nil || string(plain) != `{"PinCode":"PUBLIC"}` {
			t.Fatal("organization API must use legacy encoding")
		}
		return mockResponse(`{"CommonRsp":{"RetCode":""},"Data":{"TenantID":"123","Company":"Example"}}`), nil
	})
	org, err := c.QueryOrganization(context.Background(), "PUBLIC")
	if err != nil || org.TenantID != "123" {
		t.Fatalf("organization: %+v, %v", org, err)
	}
}

func TestAuthkeeperSignsExactBody(t *testing.T) {
	c, _ := NewClient("https://control.example")
	c.MID, c.TenantID = "test-device", "123"
	c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(r.Body)
		if !bytes.Contains(data, []byte("?a=1&b=2")) {
			t.Fatal("JSON must match browser escaping")
		}
		ts, nonce := r.Header.Get("ts"), r.Header.Get("nonce")
		if r.Header.Get("sign") != authSignature(c.MID, "authkeeper"+ts+string(data)+nonce) || r.Header.Get("tnonce") != authSignature(c.MID, ts+c.TenantID+nonce) {
			t.Fatal("invalid authkeeper signatures")
		}
		if r.Header.Get("mid") != c.MID || r.Header.Get("platform") != "Linux" {
			t.Fatal("missing device identity")
		}
		return mockResponse(`{"code":"Success"}`), nil
	})
	_, err := c.Authkeeper(context.Background(), "login", map[string]any{"redirect_uri": "https://control.example/?a=1&b=2"})
	if err != nil {
		t.Fatal(err)
	}
}
