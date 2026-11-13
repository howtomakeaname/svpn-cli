package control

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/howtomakeaname/svpn-cli/internal/headers"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const ProtocolClientVersion = "211.9.12599.62001"

type Client struct {
	Origin   string
	TenantID string
	MID      string
	GUID     string
	Machine  string
	HTTP     *http.Client
	Profile  headers.Profile
}

func NewClient(origin string) (*Client, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("control origin must be HTTPS")
	}
	// Control and gateway connections must use the same network egress. In
	// particular, do not inherit a user's local proxy and route back into this client.
	return &Client{Origin: u.Scheme + "://" + u.Host, Machine: "localhost", HTTP: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxResponseHeaderBytes: 32768}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func UUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

// DeviceGUID derives a persistent 32-hex device identifier from this
// client's own random seed.
func DeviceGUID(seed string) string {
	sum := md5.Sum([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func (c *Client) Call(ctx context.Context, path, command string, body any) (map[string]json.RawMessage, error) {
	if path != "/cmd.cgi" && path != "/access-mgr/cluster-route/GetTenantIDWithPinCode" && path != "/api/v1/Auth/ExchangeTicketV1" && path != "/api/v1/Auth/GetStatusTicketV1" && path != "/api/public/clientlogin/apply_st" {
		return nil, errors.New("unsupported control API")
	}
	plain, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	payload := plain
	if path == "/access-mgr/cluster-route/GetTenantIDWithPinCode" || path == "/api/v1/Auth/ExchangeTicketV1" || path == "/api/v1/Auth/GetStatusTicketV1" {
		payload, err = EncodeLegacy(plain)
		if err != nil {
			return nil, err
		}
	}
	endpoint := c.Origin + path
	query := make(url.Values)
	query.Set("guid", c.GUID)
	query.Set("mid", c.MID)
	if path == "/cmd.cgi" {
		if command == "" {
			return nil, errors.New("cmd.cgi requires a command")
		}
		// Command routing requires both the request header and URL query.
		query.Set("cmd", command)
	}
	endpoint += "?" + query.Encode()
	// Organization and ticket APIs use legacy encoding; command requests
	// carry JSON over TLS. Content-Encrypt alone does not select a codec.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"Content-Type": "application/json", "Content-Encrypt": "xxx", "Content-Seq": strconv.FormatInt(time.Now().UnixMicro(), 10), "Proto-Ver": "1", "Client-Platform": "linux", "Client-Version": ProtocolClientVersion, "Client-Machine": c.Machine, "Language": "zh-cn", "Timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10)}
	if c.TenantID != "" {
		headers["Tenant-Id"] = c.TenantID
	}
	if c.MID != "" {
		headers["Client-Mid"] = c.MID
	}
	if c.GUID != "" {
		headers["Client-Guid"] = c.GUID
	}
	if command != "" {
		headers["Proto-Cmd"] = command
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if err := c.Profile.ApplyControl(req); err != nil {
		return nil, err
	}
	response, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control HTTPS request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("control API HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 2<<20 {
		return nil, errors.New("control response too large")
	}
	if !json.Valid(data) {
		data, err = DecodeLegacy(data)
		if err != nil {
			return nil, err
		}
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil || result == nil {
		return nil, errors.New("invalid control response object")
	}
	if raw, ok := result["CommonRsp"]; ok {
		var common struct {
			RetCode json.RawMessage
			ErrMsg  string
		}
		if err := json.Unmarshal(raw, &common); err != nil {
			return nil, errors.New("invalid CommonRsp")
		}
		if !successCode(common.RetCode) {
			return result, fmt.Errorf("control API refused request (RetCode %s)", common.RetCode)
		}
	}
	if raw, ok := result["RetCode"]; ok && !successCode(raw) {
		return result, fmt.Errorf("control API refused request (RetCode %s)", raw)
	}
	for _, key := range []string{"errorcode", "retcode", "ErrCode"} {
		if raw, ok := result[key]; ok && !successCode(raw) {
			return result, fmt.Errorf("control API refused request (%s %s)", key, raw)
		}
	}
	return result, nil
}

func successCode(raw json.RawMessage) bool {
	switch string(raw) {
	case "", "null", "0", `""`, `"0"`, `"Success"`, `"success"`:
		return true
	}
	return false
}

type Organization struct {
	TenantID    string
	TenantNonce string
	Company     string
}

func (c *Client) QueryOrganization(ctx context.Context, pin string) (Organization, error) {
	r, err := c.Call(ctx, "/access-mgr/cluster-route/GetTenantIDWithPinCode", "", map[string]string{"PinCode": pin})
	if err != nil {
		return Organization{}, err
	}
	var org Organization
	if err := json.Unmarshal(r["Data"], &org); err != nil || org.TenantID == "" {
		return org, errors.New("organization response has no TenantID")
	}
	return org, nil
}

func (c *Client) Register(ctx context.Context) (map[string]json.RawMessage, error) {
	if c.GUID == "" || c.TenantID == "" {
		return nil, errors.New("GUID and TenantID are required for device registration")
	}
	// Do not collect host usernames or local interface addresses. Status/OSType
	// match the Linux registration fields; no compliance attestation is sent.
	// CompanyId is a distinct server-issued value, absent before registration;
	// the public organization TenantID must not be substituted for it.
	body := map[string]any{"IpList": []string{"127.0.0.1"}, "LastMid": c.MID, "Machine": c.Machine, "MachineGuid": c.GUID, "MachineType": 1, "OSType": 0, "Status": 0, "UserName": "svpn-cli"}
	return c.Call(ctx, "/cmd.cgi", "10006001", body)
}
