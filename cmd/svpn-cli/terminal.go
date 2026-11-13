package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// A callback contains a short-lived credential. Hide interactive input on all
// supported platforms and restore the terminal even when the user interrupts.
func readCallbackInput() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		old, err := term.GetState(fd)
		if err != nil {
			return nil, errors.New("cannot inspect terminal; use --callback-file")
		}
		interrupted := make(chan os.Signal, 1)
		done := make(chan struct{})
		signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)
		go func() {
			select {
			case <-interrupted:
				term.Restore(fd, old)
				fmt.Fprintln(os.Stderr)
				os.Exit(130)
			case <-done:
			}
		}()
		defer func() { signal.Stop(interrupted); close(done); term.Restore(fd, old); fmt.Fprintln(os.Stderr) }()
		fmt.Fprint(os.Stderr, "Paste callback URL (hidden), then Enter: ")
		data, err := term.ReadPassword(fd)
		if err != nil {
			return nil, errors.New("cannot read hidden callback; use --callback-file")
		}
		if len(data) > 8192 {
			return nil, errors.New("callback URL too large")
		}
		return data, nil
	}
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice != 0 {
		return nil, errors.New("terminal hiding is unavailable; use --callback-file")
	}
	line, err := bufio.NewReader(io.LimitReader(os.Stdin, 8193)).ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, errors.New("cannot read callback")
	}
	if len(line) > 8192 {
		return nil, errors.New("callback URL too large")
	}
	return []byte(line), nil
}
