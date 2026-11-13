// Package tun converts IP packets into policy-controlled TCP and UDP flows.
package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/proxy"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Run owns device until it returns. Routing, interface addresses and resolver
// settings are configured externally; this function never changes host routes.
func Run(ctx context.Context, device io.ReadWriteCloser, mtu, limit int, dial proxy.DialFunc, ready func()) error {
	if device == nil || dial == nil || mtu < 1280 || mtu > 65535 || limit < 1 || limit > 4096 {
		return errors.New("invalid TUN parameters")
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	link := channel.New(256, uint32(mtu), "")
	defer link.Close()
	var closeOnce sync.Once
	closeStack := func() { closeOnce.Do(s.Close) }
	defer s.Wait()
	defer closeStack()
	if err := s.CreateNIC(1, link); err != nil {
		return errors.New("create TUN userspace interface failed")
	}
	if err := s.SetPromiscuousMode(1, true); err != nil {
		return errors.New("configure TUN promiscuous mode failed")
	}
	if err := s.SetSpoofing(1, true); err != nil {
		return errors.New("configure TUN source addressing failed")
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	sem := make(chan struct{}, limit)
	var flows sync.WaitGroup
	var flowGate sync.Mutex
	acquire := func() bool {
		flowGate.Lock()
		defer flowGate.Unlock()
		if ctx.Err() != nil {
			return false
		}
		select {
		case sem <- struct{}{}:
			flows.Add(1)
			return true
		default:
			return false
		}
	}
	target := func(id stack.TransportEndpointID) string {
		return net.JoinHostPort(net.IP(id.LocalAddress.AsSlice()).String(), strconv.Itoa(int(id.LocalPort)))
	}
	tcpForwarder := tcp.NewForwarder(s, 0, limit, func(r *tcp.ForwarderRequest) {
		if !acquire() {
			r.Complete(true)
			return
		}
		go func() {
			defer flows.Done()
			defer func() { <-sem }()
			upstream, err := dial(ctx, "tcp", target(r.ID()))
			if err != nil {
				r.Complete(true)
				return
			}
			defer upstream.Close()
			var queue waiter.Queue
			ep, createErr := r.CreateEndpoint(&queue)
			r.Complete(createErr != nil)
			if createErr != nil {
				return
			}
			client := gonet.NewTCPConn(&queue, ep)
			defer client.Close()
			stop := context.AfterFunc(ctx, func() { client.Close(); upstream.Close() })
			defer stop()
			proxy.Relay(client, client, upstream)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		if !acquire() {
			return false
		}
		address := target(r.ID())
		var queue waiter.Queue
		ep, err := r.CreateEndpoint(&queue)
		if err != nil {
			<-sem
			flows.Done()
			return true
		}
		client := gonet.NewUDPConn(&queue, ep)
		go func() {
			defer flows.Done()
			defer func() { <-sem }()
			defer client.Close()
			upstream, err := dial(ctx, "udp", address)
			if err != nil {
				return
			}
			defer upstream.Close()
			stop := context.AfterFunc(ctx, func() { client.Close(); upstream.Close() })
			defer stop()
			relayDatagrams(client, upstream)
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	stop := context.AfterFunc(ctx, func() { device.Close(); closeStack() })
	defer stop()
	defer device.Close()
	var pump sync.WaitGroup
	pump.Add(1)
	var writeErr error
	go func() {
		defer pump.Done()
		for {
			packet := link.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			data := view.AsSlice()
			n, err := device.Write(data)
			if err == nil && n != len(data) {
				err = io.ErrShortWrite
			}
			view.Release()
			packet.DecRef()
			if err != nil {
				writeErr = err
				cancel()
				return
			}
		}
	}()
	if ready != nil {
		ready()
	}
	data := make([]byte, mtu+1)
	var readErr error
	for {
		n, err := device.Read(data)
		if err != nil {
			readErr = err
			break
		}
		if n == 0 || n > mtu {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch data[0] >> 4 {
		case 4:
			protocol = ipv4.ProtocolNumber
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data[:n]...))})
		link.InjectInbound(protocol, packet)
		packet.DecRef()
	}
	cancel()
	device.Close()
	closeStack()
	pump.Wait()
	flowGate.Lock()
	flowGate.Unlock()
	flows.Wait()
	if parent.Err() != nil {
		return nil
	}
	if writeErr != nil {
		return writeErr
	}
	return readErr
}

func relayDatagrams(a, b net.Conn) {
	done := make(chan struct{})
	copyPackets := func(dst, src net.Conn) {
		data := make([]byte, 65507)
		for {
			src.SetReadDeadline(time.Now().Add(time.Minute))
			n, err := src.Read(data)
			if err != nil {
				return
			}
			dst.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := dst.Write(data[:n]); err != nil {
				return
			}
		}
	}
	go func() { defer close(done); copyPackets(b, a); a.Close(); b.Close() }()
	copyPackets(a, b)
	a.Close()
	b.Close()
	<-done
}
