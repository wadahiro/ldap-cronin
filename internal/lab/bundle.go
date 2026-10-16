package lab

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	imageFileName = "IMAGE"
	imageTarPath  = "images/samba-ad.tar"
	sumsFileName  = "SHA256SUMS"
)

// FindBundleDir locates the carry-in bundle (the directory holding the IMAGE file).
// Precedence: explicit path > current directory > the executable's directory > its parent.
// This finds the bundle whether the executable sits in bin/ or is run from the bundle root.
func FindBundleDir(explicit, cwd, exeDir string) (string, bool) {
	var candidates []string
	if explicit != "" {
		candidates = []string{explicit}
	} else {
		candidates = []string{cwd, exeDir, filepath.Dir(exeDir)}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(c, imageFileName)); err == nil {
			return c, true
		}
	}
	return "", false
}

// VerifyChecksums compares the bundle's SHA256SUMS (sha256sum format) against the actual files.
func VerifyChecksums(dir string) error {
	f, err := os.Open(filepath.Join(dir, sumsFileName))
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		want, name, ok := strings.Cut(line, " ")
		if !ok {
			return fmt.Errorf("malformed line in %s: %q", sumsFileName, line)
		}
		name = strings.TrimLeft(name, " *")
		got, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("cannot verify %s: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("checksum mismatch for %s (it may have been corrupted in transit)", name)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s has no entries", sumsFileName)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
