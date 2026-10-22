package app

import (
	"context"
	"strings"
	"testing"
)

const ec2LabSection = `[target.lab]
platform = "ec2"
region = "ap-northeast-1"
subnet = "subnet-0123"
instance_profile = "ldap-cronin-lab"
`

// An EC2 lab is like the source: its domain name and NetBIOS name, the marker indexed, LDAPS forwarded to the port
// of [target] url. Making its plan asks for no password: the target's goes to the parameter only when it is made.
func TestEC2LabIsLikeTheSource(t *testing.T) {
	w := newWorld()
	w.src.Put(domain, map[string][]string{"objectGUID": {"0123456789abcdef"}, "objectSid": {"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00"}})
	s := w.openWith(t, ec2LabSection+"instance = \"dev2\"\n")
	e, err := s.EC2Lab(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "ldap-cronin-ad-dev2" || e.Domain != "ad.example.com" || e.NetBIOS != "AD" || e.LocalPort != 636 || e.MarkerAttribute != "adminDisplayName" ||
		e.Subnet != "subnet-0123" {
		t.Fatalf("%+v", e)
	}
	for _, asked := range w.asked {
		if asked == "target" {
			t.Errorf("the target password was asked: %v", w.asked)
		}
	}
}

// A docker lab has no EC2 plan; neither has a generic LDAP source, which Windows Server cannot stand for.
func TestEC2LabRefusesWhatIsNotOne(t *testing.T) {
	if _, err := newWorld().openWith(t, "[target.lab]\n").EC2Lab(context.Background()); err == nil {
		t.Error("a docker lab")
	}
	s, err := newWorld().tryOpen(ec2LabSection)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Job.Profile.Native = nil // as a generic LDAP profile has none
	if _, err := s.EC2Lab(context.Background()); err == nil || !strings.Contains(err.Error(), "for an AD source") {
		t.Errorf("a generic LDAP source: %v", err)
	}
}
