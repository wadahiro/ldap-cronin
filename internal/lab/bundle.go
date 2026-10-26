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
	// imageTarPath holds every lab image in one docker save, so the base layers they share are stored once.
	imageTarPath = "images/lab.tar"
	// legacyTarPath is the Samba-only tar of earlier bundles.
	legacyTarPath = "images/samba-ad.tar"
	sumsFileName  = "SHA256SUMS"
)

// bundleImage returns the image of a lab profile from the IMAGE file.
func bundleImage(dir, profile string) (string, error) {
	images, err := bundleImages(dir)
	if err != nil {
		return "", err
	}
	if image, ok := images[profile]; ok {
		return image, nil
	}
	return "", fmt.Errorf("the bundle has no image for a %s lab (%s)", profile, filepath.Join(dir, imageFileName))
}

// bundleImages reads the IMAGE file: one "profile=image" line per server. A single line without "=" (earlier
// bundles) is the Samba image.
func bundleImages(dir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, imageFileName))
	if err != nil {
		return nil, err
	}
	images := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, image, ok := strings.Cut(line, "=")
		if !ok {
			key, image = ProfileAD, line
		}
		if key = strings.TrimSpace(key); images[key] == "" {
			images[key] = strings.TrimSpace(image)
		}
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("%s names no image", filepath.Join(dir, imageFileName))
	}
	return images, nil
}

// bundleTar is the image tar of the bundle, or "" when it has none.
func bundleTar(dir string) string {
	for _, p := range []string{imageTarPath, legacyTarPath} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			return filepath.Join(dir, p)
		}
	}
	return ""
}

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
