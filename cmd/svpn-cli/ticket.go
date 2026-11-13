package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/howtomakeaname/svpn-cli/internal/control"
	"github.com/howtomakeaname/svpn-cli/internal/native"
	"github.com/howtomakeaname/svpn-cli/internal/privatefs"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := privatefs.CreateTemp(filepath.Dir(path), ".svpn-cli-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (a *application) runTicket(args []string) error {
	f := a.newFlagSet("ticket")
	path := f.String("state", "private/auth.json", "private device state")
	target := f.String("target", "", "explicit authorized TCP resource host:port")
	area := f.String("area", "", "area ID from the caller's issued policy")
	setID := f.String("set-id", "", "gateway set ID from issued policy")
	output := f.String("output", "private/ticket-response.json", "private raw response path")
	if err := a.parseFlags(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *area == "" {
		return errors.New("--area is required from the issued resource policy")
	}
	address, err := native.CanonicalAddress(*target)
	if err != nil {
		return errors.New("--target must be an explicit host:port")
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
		Id         int64
		UserId     string
		DeviceId   string
		Ticket     string
		TicketType int
	}
	if json.Unmarshal(s.Exchange["data"], &data) != nil || data.DeviceId != s.MID || data.UserId == "" || data.Ticket == "" || data.TicketType != 0 {
		return errors.New("a device-bound exchanged login ticket is required")
	}
	id, err := control.UUID()
	if err != nil {
		return err
	}
	// Report this CLI's application identity. No compliance success or device
	// posture claim is synthesized; the server decides the access policy.
	body := map[string]any{
		"areaid": *area, "set_id": *setID,
		"tenant_id": c.TenantID, "request_id": id, "uid": data.Id, "user_id": data.UserId,
		"device_id": s.MID, "tgt": data.Ticket, "tgt_2nd": "", "protocol": "tcp",
		"req_url": address, "os_type": "linux", "app_id": "0", "app_name": "",
		"app_version": "", "req_pid": strconv.Itoa(os.Getpid()), "req_pname": "svpn-cli", "communication_type": 2,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, callErr := c.Call(ctx, "/api/public/clientlogin/apply_st", "", body)
	if r != nil {
		// Preserve the exact application context used for this grant, without
		// copying the TGT into another file. Gateway claims must use this context.
		context := map[string]any{}
		for _, key := range []string{"app_id", "app_name", "app_version", "req_pid", "req_pname", "req_url", "protocol", "areaid", "set_id"} {
			context[key] = body[key]
		}
		r["_svpn_cli_request"], _ = json.Marshal(context)
		if err := writePrivateJSON(*output, r); err != nil {
			return err
		}
	}
	if callErr != nil {
		return callErr
	}
	fmt.Printf("Resource ticket response saved privately to %s; action and grants need verification before connecting.\n", *output)
	return nil
}
