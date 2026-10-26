package lab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A backup directory holds snapshots of one lab, taken after each slice of a clone (clone -backup), and names the
// latest: a session that loses the lab (a cloud shell's docker data goes with it) restores it and goes on. The
// snapshots are ordinary ones, so lab snapshots and lab restore --snapshot-dir read them too.
const (
	backupPrefix = "backup-"
	// latestFile names the latest backup. It is written last, through a rename, so a backup cut off while being
	// written leaves the one before it the latest.
	latestFile = "LATEST"
)

// Backup takes a snapshot of the lab into dir and makes it the latest, keeping the one before it (the latest
// until now, in case this one proves bad) and removing older ones.
func (l *Lab) Backup(ctx context.Context, dir, note string) (SnapshotMeta, error) {
	prev, err := LatestBackup(dir)
	if err != nil {
		return SnapshotMeta{}, err
	}
	b := *l
	b.Dirs.Snapshots = dir
	meta, err := b.Snapshot(ctx, SnapshotOptions{Name: backupPrefix + l.Now().Format(timestampLayout), Note: note, Force: true})
	if err != nil {
		return meta, err
	}
	tmp := filepath.Join(dir, "."+latestFile+".tmp")
	if err := os.WriteFile(tmp, []byte(meta.Name+"\n"), 0o600); err != nil {
		return meta, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, latestFile)); err != nil {
		return meta, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return meta, err
	}
	for _, e := range entries {
		if n := e.Name(); e.IsDir() && strings.HasPrefix(n, backupPrefix) && n != meta.Name && n != prev {
			if err := os.RemoveAll(filepath.Join(dir, n)); err != nil {
				return meta, err
			}
		}
	}
	l.logf("Backed up to %s: %s (the latest; %s kept before it)", dir, meta.Name, orNone(prev))
	return meta, nil
}

// LatestBackup is the name of the latest backup in dir, "" when it holds none.
func LatestBackup(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, latestFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(raw))
	if err := ValidateSnapshotName(name); err != nil {
		return "", fmt.Errorf("%s: %w", filepath.Join(dir, latestFile), err)
	}
	return name, nil
}

// RestoreBackup restores the latest backup in dir into the lab, which it creates when it does not exist.
func (l *Lab) RestoreBackup(ctx context.Context, dir string, o RestoreOptions) (SnapshotMeta, error) {
	name, err := LatestBackup(dir)
	if err != nil {
		return SnapshotMeta{}, err
	}
	if name == "" {
		return SnapshotMeta{}, fmt.Errorf("%s holds no backup", dir)
	}
	b := *l
	b.Dirs.Snapshots = dir
	return b.RestoreWith(ctx, name, o)
}
