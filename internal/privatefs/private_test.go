package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFileSurvivesRename(t *testing.T) {
	dir := t.TempDir()
	f, err := CreateTemp(dir, ".credential-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(f); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("test-secret"); err != nil {
		t.Fatal(err)
	}
	old := f.Name()
	f.Close()
	path := filepath.Join(dir, "auth.json")
	if err := os.Rename(old, path); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Check(f); err != nil {
		t.Fatal("private access did not survive rename:", err)
	}
}
