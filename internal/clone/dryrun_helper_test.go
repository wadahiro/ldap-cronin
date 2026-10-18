package clone

import (
	"io"

	"github.com/wadahiro/ldap-cronin/internal/directory"
	"github.com/wadahiro/ldap-cronin/internal/dryrun"
	"github.com/wadahiro/ldap-cronin/internal/profile"
)

func dryRun(w io.Writer) directory.Directory { return dryrun.New(w, profile.AD) }
