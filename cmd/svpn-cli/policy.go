package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

func (a *application) runPolicy(args []string) error {
	f := a.newFlagSet("policy")
	path := f.String("state", "private/auth.json", "private device state")
	output := f.String("output", "private/policy.json", "private policy response")
	hostPolicy := f.Bool("host", false, "read device policy instead of resource policy")
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
	var data struct {
		Id     int64
		UserId string
	}
	if json.Unmarshal(s.Exchange["data"], &data) != nil || data.Id <= 0 {
		return errors.New("an exchanged login identity is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// An empty BusinessList requests the caller's
	// full policy set, with numeric identity represented as a decimal string.
	command := "10006622"
	body := map[string]any{"PolicyMd5": "", "BusinessList": []any{}, "Uid": strconv.FormatInt(data.Id, 10)}
	if *hostPolicy {
		command = "10006631"
		body = map[string]any{"PolicyMd5": "", "BusinessHashs": []any{}, "IsFullPull": true, "IsForce": true, "AccountID": data.UserId, "IsLoggedIn": 1, "Uid": strconv.FormatInt(data.Id, 10)}
	}
	r, callErr := c.Call(ctx, "/cmd.cgi", command, body)
	if r != nil {
		if err := writePrivateJSON(*output, r); err != nil {
			return err
		}
	}
	if callErr != nil {
		return callErr
	}
	fmt.Println("Device policy response saved privately.")
	return nil
}
