package clone

import (
	"io"

	"github.com/wadahiro/ldap-cronin/internal/directory"
)

func dryRun(w io.Writer) directory.Directory { return directory.DryRun{Out: w} }
