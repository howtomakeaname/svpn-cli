package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

func (a *application) runExchange(args []string) error {
	f := a.newFlagSet("auth exchange")
	path := f.String("state", "private/auth.json", "private device state")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	s, err := readAuth(*path)
	if err != nil {
		return err
	}
	c, err := deviceClient(&s)
	if err != nil {
		return err
	}
	var uid, ticket, kind, mid, company string
	var ticketType int
	json.Unmarshal(s.Login["uid"], &uid)
	json.Unmarshal(s.Login["ticket"], &ticket)
	json.Unmarshal(s.Login["device_type"], &kind)
	json.Unmarshal(s.Login["ticket_type"], &ticketType)
	json.Unmarshal(s.Login["mid"], &mid)
	json.Unmarshal(s.Registration["CompanyId"], &company)
	if uid == "" || ticket == "" || mid != s.MID || ticketType != 2 || kind != "Linux" {
		return errors.New("a device-bound Linux login ticket of type 2 is required")
	}
	var domain string
	json.Unmarshal(s.Login["domain_id"], &domain)
	if domain == "" {
		return errors.New("login ticket has no domain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, callErr := c.Call(ctx, "/api/v1/Auth/ExchangeTicketV1", "", map[string]any{
		"UserId": uid, "HostName": s.Machine, "Mac": "", "DeviceId": s.MID,
		"DeviceType": kind, "MenuId": domain, "Ticket": ticket, "TicketType": ticketType,
		"Ip": "127.0.0.1", "Os": "Linux", "Timestamp": time.Now().Unix(), "TenantId": company,
	})
	if r != nil {
		s.Exchange = r
		if err := writeAuth(*path, &s); err != nil {
			return err
		}
	}
	if callErr != nil {
		return callErr
	}
	fmt.Println("Device login ticket exchange response saved privately.")
	return nil
}
