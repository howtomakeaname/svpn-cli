// Package privatefs creates and checks credential files using the host's
// native access controls. ACL checks must not be replaced by mode bits on NTFS.
package privatefs

import (
	"errors"
	"os"
)

func Check(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("credential file must be a regular file")
	}
	return checkAccess(file, info)
}
