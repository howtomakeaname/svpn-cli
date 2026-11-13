package privatefs

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRejectEveryoneACL(t *testing.T) {
	f, err := CreateTemp(t.TempDir(), ".credential-*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Check(f); err == nil {
		t.Fatal("Everyone-readable credential accepted")
	}
}
