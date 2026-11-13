package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestFixedForwardPreservesHalfCloseAndResponse(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		body, _ := io.ReadAll(conn)
		conn.Write(append([]byte("response:"), body...))
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, (&net.Dialer{}).DialContext, target.Addr().String(), 2) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("payload\x00\xff"))
	conn.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "response:payload\x00\xff" {
		t.Fatalf("half-close lost bytes: %q %v", got, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFixedForwardDeniesWithoutFallbackAndClosesActiveOnCancel(t *testing.T) {
	for _, deny := range []bool{false, true} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		attempt := make(chan string, 2)
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			attempt <- address
			if deny {
				return nil, errors.New("denied")
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, listener, dial, "only-target.example:22", 1) }()
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if address := <-attempt; address != "only-target.example:22" {
			t.Fatal("forward dialed an unintended target")
		}
		if !deny {
			// An in-flight dial consumes the slot too. Reject the second client
			// without starting another ticket request or leaving it queued.
			second, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			second.SetReadDeadline(time.Now().Add(time.Second))
			_, err = second.Read(make([]byte, 1))
			second.Close()
			if err == nil {
				t.Fatal("over-limit stream was not closed")
			}
		}
		cancel()
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
		if err == nil {
			t.Fatal("cancelled/denied stream remained open")
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if len(attempt) != 0 {
			t.Fatal("unexpected retry or fallback dial")
		}
	}
}
