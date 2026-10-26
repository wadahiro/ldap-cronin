package ad

import "testing"

func TestRealmOfDomainRoot(t *testing.T) {
	if got := RealmOf("DC=Corp,DC=Example,DC=LOCAL"); got != "corp.example.local" {
		t.Fatal(got)
	}
}
