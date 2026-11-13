package privatefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid.Copy()
}

// Install a protected DACL at creation, before writing any secret bytes. Only
// this user and LocalSystem receive access; no parent ACL is inherited.
func CreateTemp(dir, pattern string) (*os.File, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for attempt := 0; attempt < 10; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		suffix := hex.EncodeToString(nonce[:])
		name := pattern + suffix
		if at := strings.LastIndexByte(pattern, '*'); at >= 0 {
			name = pattern[:at] + suffix + pattern[at+1:]
		}
		path := filepath.Join(dir, name)
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		runtime.KeepAlive(sd)
		if err == windows.ERROR_FILE_EXISTS || err == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(handle), path), nil
	}
	return nil, errors.New("cannot create unique private credential file")
}

func checkAccess(file *os.File, _ os.FileInfo) error {
	self, err := currentSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("credential owner unavailable")
	}
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(self) || sid.String() == "S-1-5-18" || sid.String() == "S-1-5-32-544"
	}
	if !trusted(owner) {
		return errors.New("credential file is owned by another account")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("credential file has no restrictive DACL")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported credential ACL entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask != 0 && !trusted(sid) {
			return errors.New("credential ACL permits another account; restrict it to your user")
		}
	}
	runtime.KeepAlive(sd)
	return nil
}
