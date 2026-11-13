//go:build !linux

package tun

import (
	"errors"
	"os"
)

func Open(string, int) (*os.File, string, error) {
	return nil, "", errors.New("TUN device access is currently implemented only on Linux")
}
