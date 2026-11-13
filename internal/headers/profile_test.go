package headers

import (
	"net/http"
	"strings"
	"testing"
)

func TestProfileProtectsProtocolAndFraming(t *testing.T) {
	for _, p := range []Profile{
		{UserAgent: "agent\r\nInjected: yes"},
		{Gateway: map[string]string{"Proxy-Authorization": "replacement"}},
		{Control: map[string]string{"tNoNcE": "replacement"}},
		{Gateway: map[string]string{"Host": "elsewhere"}},
		{Control: map[string]string{"X-Tag": "value\nInjected: yes"}},
		{Gateway: map[string]string{"Bad Name": "value"}},
		{Gateway: map[string]string{"X-Tag": "one", "x-tag": "two"}},
		{UserAgent: strings.Repeat("x", 2049)},
	} {
		if p.Validate() == nil {
			t.Fatal("accepted unsafe header profile")
		}
	}
	if strings.Contains((Profile{}).Agent(), "svpn-cli") {
		t.Fatal("default adds an implementation product tag")
	}
	req, _ := http.NewRequest("POST", "https://control.example", nil)
	p := Profile{UserAgent: "custom-agent/1", Control: map[string]string{"Accept-Language": "zh-CN"}}
	if err := p.ApplyControl(req); err != nil {
		t.Fatal(err)
	}
	if req.UserAgent() != "custom-agent/1" || req.Header.Get("Accept-Language") != "zh-CN" {
		t.Fatal("custom control headers not applied")
	}
}
