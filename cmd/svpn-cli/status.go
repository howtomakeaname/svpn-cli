package main

import (
	"context"
	"encoding/json"
	"time"
)

func (a *application) runAuthStatus(args []string) error {
	f := a.newFlagSet("auth status")
	path := f.String("state", "private/auth.json", "private device state")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return usageError("unexpected positional arguments")
	}
	s, err := readAuth(*path)
	if err != nil {
		return err
	}
	c, err := deviceClient(&s)
	if err != nil {
		return err
	}
	var data struct {
		UserId, UserName, DeviceId, Ticket, MenuId string
		TicketType                                 int
	}
	if json.Unmarshal(s.Exchange["data"], &data) != nil || data.Ticket == "" || data.DeviceId != s.MID {
		return authRequired("device login ticket required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, callErr := c.Call(ctx, "/api/v1/Auth/GetStatusTicketV1", "", map[string]any{
		"UserId": data.UserId, "UserName": data.UserName, "DeviceId": s.MID, "DeviceType": "LINUX",
		"Ticket": data.Ticket, "TicketType": data.TicketType, "MenuId": data.MenuId, "HostName": s.Machine,
		"Mac": "", "Ip": "127.0.0.1", "Os": "Linux", "Timestamp": time.Now().Unix(), "TenantId": c.TenantID, "DeviceNetworkLocation": 0,
	})
	if r != nil {
		s.Status = r
		if err := writeAuth(*path, &s); err != nil {
			return err
		}
	}
	if callErr != nil {
		return remoteFailure(callErr)
	}
	return a.result("auth status", "Login ticket status response saved privately.", map[string]any{"state_file": *path, "response_saved": true, "credential_validity": "not_interpreted"})
}
