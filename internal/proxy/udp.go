package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/howtomakeaname/svpn-cli/internal/native"
)

// parseUDPAddress does no DNS. FRAG is deliberately unsupported: accepting a
// fragment as a complete datagram can change the application message contents.
func parseUDPAddress(packet []byte) (string, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", nil, errors.New("invalid or fragmented SOCKS UDP packet")
	}
	var host string
	pos := 4
	switch packet[3] {
	case 1:
		if len(packet) < pos+4 {
			return "", nil, io.ErrUnexpectedEOF
		}
		host = net.IP(packet[pos : pos+4]).String()
		pos += 4
	case 4:
		if len(packet) < pos+16 {
			return "", nil, io.ErrUnexpectedEOF
		}
		host = net.IP(packet[pos : pos+16]).String()
		pos += 16
	case 3:
		if len(packet) <= pos {
			return "", nil, io.ErrUnexpectedEOF
		}
		size := int(packet[pos])
		pos++
		if size == 0 || len(packet) < pos+size {
			return "", nil, io.ErrUnexpectedEOF
		}
		host = string(packet[pos : pos+size])
		pos += size
	default:
		return "", nil, errors.New("invalid SOCKS UDP address type")
	}
	if len(packet) < pos+2 {
		return "", nil, io.ErrUnexpectedEOF
	}
	port := binary.BigEndian.Uint16(packet[pos:])
	pos += 2
	address, err := native.CanonicalAddress(net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return "", nil, err
	}
	return address, packet[pos:], nil
}

func udpAddressHeader(address string) []byte {
	host, port, _ := net.SplitHostPort(address)
	number, _ := strconv.Atoi(port)
	packet := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			packet = append(packet, 1)
			packet = append(packet, ip4...)
		} else {
			packet = append(packet, 4)
			packet = append(packet, ip.To16()...)
		}
	} else {
		packet = append(packet, 3, byte(len(host)))
		packet = append(packet, host...)
	}
	return binary.BigEndian.AppendUint16(packet, uint16(number))
}

func (s *Server) serveUDPAssociation(parent context.Context, client net.Conn, requestedHost string, requestedPort uint16) {
	peer, ok := client.RemoteAddr().(*net.TCPAddr)
	local, localOK := client.LocalAddr().(*net.TCPAddr)
	ip := net.ParseIP(requestedHost)
	if !ok || !localOK || ip == nil || (!ip.IsUnspecified() && !ip.Equal(peer.IP)) {
		socksReply(client, 8)
		return
	}
	endpoint, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		socksReply(client, 1)
		return
	}
	defer endpoint.Close()
	bound := endpoint.LocalAddr().String()
	reply := append([]byte{5, 0, 0}, udpAddressHeader(bound)[3:]...)
	if _, err := client.Write(reply); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { endpoint.Close(); client.Close() })
	defer stop()
	controlDone := make(chan struct{})
	go func() { defer close(controlDone); io.Copy(io.Discard, client); cancel() }()
	var mu sync.Mutex
	flows := map[string]net.Conn{}
	var active sync.WaitGroup
	defer func() {
		cancel()
		endpoint.Close()
		client.Close()
		mu.Lock()
		for _, conn := range flows {
			conn.Close()
		}
		mu.Unlock()
		active.Wait()
		<-controlDone
	}()
	var sender *net.UDPAddr
	buffer := make([]byte, 65535)
	for {
		n, source, err := endpoint.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if !source.IP.Equal(peer.IP) || (requestedPort != 0 && int(requestedPort) != source.Port) || (sender != nil && (sender.Port != source.Port || !sender.IP.Equal(source.IP))) {
			continue
		}
		target, payload, err := parseUDPAddress(buffer[:n])
		if err != nil || len(payload) > 65507 {
			continue
		}
		if sender == nil {
			sender = source
		}
		mu.Lock()
		conn := flows[target]
		mu.Unlock()
		if conn == nil {
			if !s.acquire() {
				continue
			}
			conn, err = s.Dial(ctx, "udp", target)
			if err != nil {
				s.release()
				continue
			}
			mu.Lock()
			flows[target] = conn
			mu.Unlock()
			active.Add(1)
			go func(upstream net.Conn, address string, destination *net.UDPAddr) {
				defer active.Done()
				defer s.release()
				defer upstream.Close()
				defer func() {
					mu.Lock()
					if flows[address] == upstream {
						delete(flows, address)
					}
					mu.Unlock()
				}()
				header := udpAddressHeader(address)
				data := make([]byte, len(header)+65507)
				copy(data, header)
				for {
					upstream.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := upstream.Read(data[len(header):])
					if err != nil {
						return
					}
					if _, err = endpoint.WriteToUDP(data[:len(header)+n], destination); err != nil {
						return
					}
				}
			}(conn, target, sender)
		}
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			conn.Close()
		}
	}
}
