package lab

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Each backup becomes the latest once it is written, the one before it is kept and older ones removed; the
// latest restores a lab that no longer exists (a session that lost its docker data).
func TestBackupsKeepTheLatestAndTheOneBeforeAndRestoreAMissingLab(t *testing.T) {
	ctx := context.Background()
	fx := seededLab(t)
	dir := filepath.Join(t.TempDir(), "backup")
	if name, err := LatestBackup(dir); err != nil || name != "" {
		t.Fatalf("an empty directory: %q %v", name, err)
	}
	var names []string
	for _, data := range []string{"v1", "v2", "v3"} {
		fx.d.volumeData["t-ad-private"] = data
		meta, err := fx.l.Backup(ctx, dir, "clone stopped at -time-limit")
		must(t, err)
		names = append(names, meta.Name)
	}
	latest, err := LatestBackup(dir)
	must(t, err)
	var kept []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			kept = append(kept, e.Name())
		}
	}
	sort.Strings(kept)
	if latest != names[2] || strings.Join(kept, " ") != names[1]+" "+names[2] {
		t.Fatalf("latest %q, kept %v, taken %v", latest, kept, names)
	}

	must(t, fx.l.Reset(ctx, ResetOptions{Yes: true}))
	_, err = fx.l.RestoreBackup(ctx, dir, RestoreOptions{AdminPassword: "Secret-Passw0rd!"})
	must(t, err)
	if !fx.d.containers["t-ad"].running || fx.d.extracted["t-ad-private"] != "v3" {
		t.Fatalf("the lab is made from the latest backup: %q", fx.d.extracted["t-ad-private"])
	}
	if _, err := fx.l.RestoreBackup(ctx, t.TempDir(), RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "holds no backup") {
		t.Fatalf("a directory without one: %v", err)
	}
}
