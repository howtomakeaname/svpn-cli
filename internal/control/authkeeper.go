package control

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

func authSignature(key, message string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Authkeeper signs the exact request body with the device MID and nonce.
// Authentication is limited to returning the user's browser-issued SSO code.
func (c *Client) Authkeeper(ctx context.Context, operation string, body map[string]any) (map[string]json.RawMessage, error) {
	switch operation {
	case "domains", "auth-configs", "system-configs", "login":
	default:
		return nil, errors.New("unsupported authkeeper operation")
	}
	if c.MID == "" || c.TenantID == "" {
		return nil, errors.New("registered MID and TenantID required")
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(body); err != nil {
		return nil, err
	}
	data := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	var random [5]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(random[:])
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	id, err := UUID()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Origin+"/authkeeper/api/v1/"+operation, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"mid":          c.MID, "Tenant-Id": c.TenantID, "Timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
		"Version": "1", "Request-Id": id, "platform": "Linux", "ts": ts, "ts-offset": "0", "nonce": nonce,
		"sign":   authSignature(c.MID, "authkeeper"+ts+string(data)+nonce),
		"tnonce": authSignature(c.MID, ts+c.TenantID+nonce),
	}
	if domain, ok := body["domain"].(string); ok {
		headers["domain"] = domain
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if err := c.Profile.ApplyControl(req); err != nil {
		return nil, err
	}
	response, err := c.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("authkeeper HTTPS request failed") // may contain a sensitive callback URL
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authkeeper HTTP %d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return nil, errors.New("invalid or oversized authkeeper response")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(data, &result) != nil || result == nil {
		return nil, errors.New("invalid authkeeper response object")
	}
	var code string
	if json.Unmarshal(result["code"], &code) != nil || code != "Success" {
		return result, fmt.Errorf("authkeeper refused request (code %q)", code)
	}
	return result, nil
}
