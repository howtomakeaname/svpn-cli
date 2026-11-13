package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/howtomakeaname/svpn-cli/internal/native"
)

// All machine-readable control output uses this versioned envelope. TCP bytes
// from connect never pass through it; errors always go to stderr.
type response struct {
	SchemaVersion int       `json:"schema_version"`
	Command       string    `json:"command"`
	OK            bool      `json:"ok"`
	Event         string    `json:"event,omitempty"`
	Data          any       `json:"data,omitempty"`
	Error         *cliError `json:"error,omitempty"`
}

type nextAction struct {
	Kind    string   `json:"kind"`
	Argv    []string `json:"argv,omitempty"`
	Message string   `json:"message,omitempty"`
}

type cliError struct {
	Code       string      `json:"code"`
	Message    string      `json:"message"`
	Retryable  bool        `json:"retryable"`
	NextAction *nextAction `json:"next_action,omitempty"`
	Details    any         `json:"details,omitempty"`
	exit       int
	cause      error
}

func (e *cliError) Error() string { return e.Message }
func (e *cliError) Unwrap() error { return e.cause }

func usageError(message string) error {
	return &cliError{Code: "INVALID_ARGUMENT", Message: message, exit: 2}
}

func authRequired(message string) error {
	return &cliError{Code: "AUTH_REQUIRED", Message: message, exit: 3}
}

func remoteFailure(err error) error {
	if err == nil {
		return nil
	}
	// Registration and callback submission may have succeeded before a connection
	// failed. Never promise that replaying an authentication request is safe.
	return &cliError{Code: "REMOTE_REQUEST_FAILED", Message: "Remote request failed; its outcome may be unknown. Inspect authentication state before retrying.", exit: 5, cause: err}
}

type application struct {
	out, errOut    io.Writer
	json           bool
	nonInteractive bool
}

func execute(args []string, out, errOut io.Writer) int {
	a := &application{out: out, errOut: errOut}
	f := a.newFlagSet("")
	showVersion := f.Bool("version", false, "show version and build information")
	err := a.parseFlags(f, args)
	if err == nil {
		args = f.Args()
		if *showVersion {
			if len(args) != 0 {
				err = usageError("--version takes no command or positional arguments")
			} else {
				args = []string{"version"}
			}
		}
	}
	if err == nil {
		err = a.run(args)
	}
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	problem := classifyError(err)
	if a.json {
		if writeErr := json.NewEncoder(errOut).Encode(response{SchemaVersion: 1, Command: commandName(args), OK: false, Error: problem}); writeErr != nil {
			return 1
		}
	} else {
		fmt.Fprintln(errOut, "svpn-cli:", err)
		if problem.Details != nil {
			if details, marshalErr := json.Marshal(problem.Details); marshalErr == nil {
				fmt.Fprintln(errOut, string(details))
			}
		}
	}
	return problem.exit
}

func classifyError(err error) *cliError {
	var problem *cliError
	if errors.As(err, &problem) {
		return problem
	}
	var gateway *native.GatewayError
	if errors.As(err, &gateway) {
		return &cliError{Code: "GATEWAY_REJECTED", Message: "Gateway refused the connection.", exit: 5,
			Details: map[string]any{"http_status": gateway.Status}}
	}
	if errors.Is(err, os.ErrNotExist) {
		return &cliError{Code: "FILE_NOT_FOUND", Message: "A required local file does not exist; check the supplied paths.", exit: 4}
	}
	if errors.Is(err, os.ErrPermission) {
		return &cliError{Code: "PERMISSION_DENIED", Message: "Cannot access a required local file with the current permissions.", exit: 4}
	}
	// Error strings from URLs, filesystem paths and server responses can contain
	// credentials. Unknown errors are intentionally not copied into JSON output.
	return &cliError{Code: "OPERATION_FAILED", Message: "Operation failed; check local configuration, authentication and connectivity.", exit: 1}
}

func (a *application) result(command, message string, data any) error {
	if a.json {
		return json.NewEncoder(a.out).Encode(response{SchemaVersion: 1, Command: command, OK: true, Data: data})
	}
	_, err := fmt.Fprintln(a.out, message)
	return err
}

func (a *application) event(command, event string, data any) error {
	return json.NewEncoder(a.out).Encode(response{SchemaVersion: 1, Command: command, OK: true, Event: event, Data: data})
}
