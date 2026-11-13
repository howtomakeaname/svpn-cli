// Package policy reads the resource policy issued to the authenticated device.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Area struct {
	ID            string     `json:"areaid"`
	Module        string     `json:"areamodule"`
	Address       string     `json:"connaddr"`
	Ports         string     `json:"connport"`
	Filter        string     `json:"filterport"`
	PortsV1       string     `json:"connport_v1"`
	FilterV1      string     `json:"filterport_v1"`
	Protocol      string     `json:"protocol"`
	Type          string     `json:"type"`
	GatewayIDs    []string   `json:"smartgate_id"`
	Gateways      [][]string `json:"smartgate_server"`
	ConnectorType string     `json:"connector_group_type"`
	SetID         string     `json:"-"`
	addresses     []addressRange
	domains       []string
	ports         []portRange
	allPorts      bool
}
type addressRange struct{ first, last netip.Addr }
type portRange struct{ first, last int }
type Policy struct{ Areas []Area }

// Parse rejects unfamiliar rules instead of silently treating protected hosts
// as public traffic. Policy ordering is preserved.
func Parse(data []byte) (*Policy, error) {
	if len(data) > 2<<20 {
		return nil, errors.New("resource policy too large")
	}
	var envelope struct {
		RetCode      json.RawMessage
		BusinessList []struct {
			BusinessID int
			Data       struct {
				Configs []struct {
					Details struct {
						Switch   string `json:"switch"`
						Areas    []Area `json:"accessiblearea"`
						Gateways []struct {
							ID    string `json:"id"`
							SetID string `json:"set_id"`
						} `json:"smartgate_details"`
					}
				}
			}
		}
	}
	if json.Unmarshal(data, &envelope) != nil || (string(envelope.RetCode) != "0" && string(envelope.RetCode) != `"0"`) {
		return nil, errors.New("invalid or refused resource policy")
	}
	p := &Policy{}
	for _, business := range envelope.BusinessList {
		if business.BusinessID != 143 {
			continue
		}
		for _, config := range business.Data.Configs {
			d := config.Details
			if d.Switch != "1" {
				return nil, errors.New("resource policy is disabled or has an unknown switch")
			}
			sets := map[string]string{}
			for _, g := range d.Gateways {
				sets[g.ID] = g.SetID
			}
			for _, area := range d.Areas {
				if len(p.Areas) >= 10000 {
					return nil, errors.New("too many resource rules")
				}
				if area.ID == "" || (area.Protocol != "" && area.Protocol != "1" && area.Protocol != "2" && area.Protocol != "3") {
					return nil, errors.New("unsupported resource identity or protocol")
				}
				if len(area.GatewayIDs) > 0 {
					area.SetID = sets[area.GatewayIDs[0]]
				}
				if err := area.compile(); err != nil {
					return nil, fmt.Errorf("resource rule %s: %w", area.ID, err)
				}
				p.Areas = append(p.Areas, area)
			}
		}
	}
	if len(p.Areas) == 0 {
		return nil, errors.New("resource policy has no supported rules")
	}
	return p, nil
}

func (a *Area) compile() error {
	filter, ports := a.Filter, a.Ports
	// The resource schema prefers enabled v1 port-range rules.
	if a.FilterV1 == "1" {
		filter, ports = "1", a.PortsV1
	} else if a.FilterV1 != "" && a.FilterV1 != "0" {
		return errors.New("unknown v1 port filter")
	}
	if filter == "0" {
		a.allPorts = true
	} else if filter == "1" {
		for _, part := range strings.Split(ports, ";") {
			ends := strings.Split(part, "-")
			if len(ends) > 2 {
				return errors.New("invalid port range")
			}
			lo, e := strconv.Atoi(ends[0])
			if e != nil || lo < 1 || lo > 65535 {
				return errors.New("invalid port")
			}
			hi := lo
			if len(ends) == 2 {
				hi, e = strconv.Atoi(ends[1])
				if e != nil || hi < lo || hi > 65535 {
					return errors.New("invalid port range")
				}
			}
			a.ports = append(a.ports, portRange{lo, hi})
		}
	} else {
		return errors.New("unknown port filter")
	}
	for _, part := range strings.Split(a.Address, ";") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			return errors.New("empty address")
		}
		switch a.Type {
		case "domain":
			name := strings.TrimPrefix(part, "*.")
			if _, err := netip.ParseAddr(name); err == nil {
				return errors.New("IP in domain rule")
			}
			if strings.Contains(name, "*") {
				return errors.New("unsupported domain wildcard")
			}
			if _, _, err := net.SplitHostPort(net.JoinHostPort(name, "443")); err != nil {
				return errors.New("invalid domain")
			}
			for _, label := range strings.Split(name, ".") {
				if label == "" {
					return errors.New("invalid domain")
				}
				for _, c := range label {
					if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
						return errors.New("invalid domain")
					}
				}
			}
			a.domains = append(a.domains, strings.TrimSuffix(part, "."))
		case "ip":
			if prefix, err := netip.ParsePrefix(part); err == nil {
				prefix = prefix.Masked()
				first := prefix.Addr()
				last := first
				bytes := first.As16()
				bits := prefix.Bits()
				if first.Is4() {
					bits += 96
				}
				for bit := bits; bit < 128; bit++ {
					bytes[bit/8] |= 1 << uint(7-bit%8)
				}
				last = netip.AddrFrom16(bytes).Unmap()
				a.addresses = append(a.addresses, addressRange{first, last})
				continue
			}
			ends := strings.Split(part, "-")
			if len(ends) > 2 {
				return errors.New("invalid IP range")
			}
			lo, err := netip.ParseAddr(ends[0])
			if err != nil {
				return errors.New("invalid IP")
			}
			lo = lo.Unmap()
			hi := lo
			if len(ends) == 2 {
				hi, err = netip.ParseAddr(ends[1])
				hi = hi.Unmap()
				if err != nil || lo.BitLen() != hi.BitLen() || lo.Compare(hi) > 0 {
					return errors.New("invalid IP range")
				}
			}
			a.addresses = append(a.addresses, addressRange{lo, hi})
		default:
			return errors.New("unsupported address type")
		}
	}
	return nil
}

// Match returns a rule and whether the host is protected but the port is not
// permitted. Callers must never direct-connect after a protected match fails.
func (p *Policy) Match(host string, port int) (*Area, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip, ipErr := netip.ParseAddr(host)
	ip = ip.Unmap()
	protected := false
	for i := range p.Areas {
		a := &p.Areas[i]
		if a.Protocol == "1" {
			continue
		} // 1=UDP, 2=TCP, 3/empty=both.
		matched := false
		if ipErr == nil {
			for _, r := range a.addresses {
				if ip.BitLen() == r.first.BitLen() && ip.Compare(r.first) >= 0 && ip.Compare(r.last) <= 0 {
					matched = true
					break
				}
			}
		} else {
			for _, domain := range a.domains {
				if strings.HasPrefix(domain, "*.") {
					suffix := domain[1:]
					matched = strings.HasSuffix(host, suffix) && len(host) > len(suffix)
				} else {
					matched = host == domain
				}
				if matched {
					break
				}
			}
		}
		if !matched {
			continue
		}
		protected = true
		if a.allPorts {
			return a, false
		}
		for _, ports := range a.ports {
			if port >= ports.first && port <= ports.last {
				return a, false
			}
		}
	}
	return nil, protected
}
