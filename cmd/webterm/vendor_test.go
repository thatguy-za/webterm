package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vendored libraries must match SHA256SUMS, and every file in the folder
// must be listed, so changing or adding third-party code is always deliberate.
func TestVendoredChecksums(t *testing.T) {
	dir := filepath.Join("web", "vendor")
	raw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("bad line in SHA256SUMS: %q", line)
		}
		data, err := os.ReadFile(filepath.Join(dir, f[1]))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != f[0] {
			t.Errorf("%s changed: update SHA256SUMS and README.md if that was intended", f[1])
		}
		listed[f[1]] = true
	}
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		if err == nil && !d.IsDir() && rel != "SHA256SUMS" && rel != "README.md" && !listed[rel] {
			t.Errorf("%s is not in SHA256SUMS", rel)
		}
		return nil
	})
}
