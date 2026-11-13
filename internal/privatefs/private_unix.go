//go:build !windows

package privatefs

import (
	"errors"
	"os"
)

func CreateTemp(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }

func checkAccess(_ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("credential file must be private (chmod 600)")
	}
	return nil
}
