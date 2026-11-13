package tun

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

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
)

type packetDevice struct {
	incoming, outgoing chan []byte
	done               chan struct{}
	once               sync.Once
}

func (d *packetDevice) Read(p []byte) (int, error) {
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case data := <-d.incoming:
		if len(data) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, data), nil
	}
}
func (d *packetDevice) Write(p []byte) (int, error) {
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case d.outgoing <- append([]byte(nil), p...):
		return len(p), nil
	}
}
func (d *packetDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }

func TestPacketStackTCPAndUDPIPv4IPv6AndShutdown(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				io.Copy(conn, conn)
			}()
			echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				buf := make([]byte, 65535)
				for {
					n, a, err := echo.ReadFromUDP(buf)
					if err != nil {
						return
					}
					echo.WriteToUDP(buf[:n], a)
				}
			}()
			device := &packetDevice{incoming: make(chan []byte, 256), outgoing: make(chan []byte, 256), done: make(chan struct{})}
			client := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
			link := channel.New(256, 1500, "")
			if err := client.CreateNIC(1, link); err != nil {
				t.Fatal(err)
			}
			protocol := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
			address, target := tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), tcpip.AddrFrom4([4]byte{192, 0, 2, 53})
			if family == "ipv6" {
				protocol = ipv6.ProtocolNumber
				address = tcpip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
				target = tcpip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53})
			}
			if err := client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: address.WithPrefix()}, stack.AddressProperties{}); err != nil {
				t.Fatal(err)
			}
			client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
			var pumps sync.WaitGroup
			pumps.Add(2)
			go func() {
				defer pumps.Done()
				for {
					packet := link.ReadContext(ctx)
					if packet == nil {
						return
					}
					view := packet.ToView()
					data := append([]byte(nil), view.AsSlice()...)
					view.Release()
					packet.DecRef()
					select {
					case device.incoming <- data:
					case <-ctx.Done():
						return
					}
				}
			}()
			go func() {
				defer pumps.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case data := <-device.outgoing:
						packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
						link.InjectInbound(protocol, packet)
						packet.DecRef()
					}
				}
			}()
			ready := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- Run(ctx, device, 1500, 4, func(ctx context.Context, network, address string) (net.Conn, error) {
					destination := listener.Addr().String()
					if network == "udp" {
						destination = echo.LocalAddr().String()
					}
					return (&net.Dialer{}).DialContext(ctx, network, destination)
				}, func() { close(ready) })
			}()
			t.Cleanup(func() {
				cancel()
				device.Close()
				client.Close()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(3 * time.Second):
					t.Error("TUN did not stop active flows")
				}
				pumps.Wait()
				client.Wait()
				link.Close()
			})
			<-ready
			destination := tcpip.FullAddress{NIC: 1, Addr: target, Port: 53}
			stream, err := gonet.DialContextTCP(ctx, client, destination, protocol)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			stream.SetDeadline(time.Now().Add(3 * time.Second))
			stream.Write([]byte("tcp-through-ip"))
			response := make([]byte, len("tcp-through-ip"))
			if _, err := io.ReadFull(stream, response); err != nil || string(response) != "tcp-through-ip" {
				t.Fatal("TCP packet conversion", err)
			}
			packet, err := gonet.DialUDP(client, nil, &destination, protocol)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			packet.SetDeadline(time.Now().Add(3 * time.Second))
			for _, payload := range []string{"udp-one", "udp-two", ""} {
				if _, err := packet.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				n, err := packet.Read(buf)
				if err != nil || string(buf[:n]) != payload {
					t.Fatal("UDP packet conversion", n, err)
				}
			}
		})
	}
}
