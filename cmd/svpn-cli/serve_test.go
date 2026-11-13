package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestServeReadyReportsActualListenerAndShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	a := &application{json: true, out: writer, errOut: io.Discard}
	go func() {
		err := a.serve(ctx, (&net.Dialer{}).DialContext, "auto", "127.0.0.1:0", "127.0.0.1:0", 8)
		done <- err
		writer.CloseWithError(err)
	}()
	decoder := json.NewDecoder(reader)
	var ready struct {
		Event string `json:"event"`
		Data  struct {
			Listeners map[string]string `json:"listeners"`
			Tested    bool              `json:"target_connectivity_tested"`
		} `json:"data"`
	}
	if err := decoder.Decode(&ready); err != nil || ready.Event != "ready" || len(ready.Data.Listeners) != 2 || ready.Data.Tested {
		t.Fatal("missing or misleading readiness event", err)
	}
	for _, address := range ready.Data.Listeners {
		_, port, err := net.SplitHostPort(address)
		if err != nil || port == "0" {
			t.Fatal("readiness did not report an actual bound address")
		}
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "proxy works") }))
	defer target.Close()
	proxyURL, _ := url.Parse("http://" + ready.Data.Listeners["HTTP"])
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	res, err := client.Get(target.URL)
	if err != nil {
		t.Fatal("ready proxy was unusable", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "proxy works" {
		t.Fatal("proxy changed the response")
	}
	cancel()
	var stopped response
	if err := decoder.Decode(&stopped); err != nil || stopped.Event != "stopped" || !stopped.OK {
		t.Fatal("missing shutdown event", err)
	}
	if err := <-done; err != nil {
		t.Fatal("graceful shutdown failed", err)
	}
}

func TestServeCannotAnnouncePartiallyBoundListeners(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	var out bytes.Buffer
	a := &application{json: true, out: &out, errOut: io.Discard}
	err = a.serve(context.Background(), (&net.Dialer{}).DialContext, "vpn-only", "127.0.0.1:0", occupied.Addr().String(), 1)
	if err == nil || classifyError(err).Code != "LISTENER_FAILED" || out.Len() != 0 {
		t.Fatal("announced readiness despite a listener failure")
	}
}
