//go:build linux

package tun

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func Open(name string, inheritedFD int) (*os.File, string, error) {
	fd := inheritedFD
	if fd < 0 {
		request, err := unix.NewIfreq(name)
		if err != nil {
			return nil, "", err
		}
		request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		fd, err = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, "", err
		}
		if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
			unix.Close(fd)
			return nil, "", err
		}
	} else if fd < 3 {
		return nil, "", errors.New("TUN file descriptor must be at least 3")
	}
	// NewFile must observe O_NONBLOCK so Close can interrupt a pending Read.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "tun")
	if file == nil {
		return nil, "", errors.New("invalid TUN file descriptor")
	}
	request, _ := unix.NewIfreq("")
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, request); err != nil {
		file.Close()
		return nil, "", err
	}
	if request.Uint16()&unix.IFF_TUN == 0 || request.Uint16()&unix.IFF_NO_PI == 0 {
		file.Close()
		return nil, "", errors.New("requires a TUN device without packet information headers")
	}
	return file, request.Name(), nil
}
