package lab

import (
	"strings"
	"testing"
)

const testPassword = "Lab-Adm1n-Passw0rd!"

func testEC2Lab() EC2Lab {
	return EC2Lab{Name: "ldap-cronin-ad", Domain: "ad.example.com", NetBIOS: "AD", Region: "ap-northeast-1",
		Subnet: "subnet-0123", InstanceProfile: "ldap-cronin-lab", LocalPort: 12636, MarkerAttribute: "adminDisplayName"}
}

// The user data makes the source's domain with the password given, a quote of it doubled for PowerShell.
func TestEC2UserDataMakesTheSourcesDomain(t *testing.T) {
	ud, err := testEC2Lab().UserData("It's-a-Passw0rd")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<powershell>", "</powershell>\n<persist>true</persist>", "$Domain = 'ad.example.com'", "$NetBIOS = 'AD'",
		"$Password = 'It''s-a-Passw0rd'", "$Marker = 'adminDisplayName'", "Install-ADDSForest", `C:\ldap-cronin\ready`} {
		if !strings.Contains(ud, want) {
			t.Errorf("the user data lacks %q", want)
		}
	}
	if strings.Contains(ud, "{{") || strings.Contains(ud, "Get-SSMParameter") {
		t.Errorf("a field is left unfilled, or the parameter is read:\n%s", ud)
	}
	if !strings.Contains(ud, "$PlainLDAP = ''") || !strings.Contains(ud, "$ExtraName = ''") {
		t.Error("without ldap_port and ldaps_name, Windows' own")
	}
	e := testEC2Lab()
	e.LDAPPort = 13389
	if ud, err := e.UserData(testPassword); err != nil || !strings.Contains(ud, "$PlainLDAP = ''") {
		t.Errorf("ldap_port forwards only: %v", err)
	}
	e.LDAPUnsigned = true
	if ud, err := e.UserData(testPassword); err != nil || !strings.Contains(ud, "$PlainLDAP = 'yes'") || !strings.Contains(ud, "LDAPServerIntegrity -Value 1") {
		t.Errorf("ldap_unsigned: %v", err)
	}
	if last := e.UpCommands()[len(e.UpCommands())-1].Shell(); !strings.Contains(last, "'portNumber=389,localPortNumber=13389'") {
		t.Errorf("ldap_port forwarding: %s", last)
	}
	e.LDAPPort = 0
	e.LDAPSName = "ldap.test.example.com"
	if ud, err := e.UserData(testPassword); err != nil || !strings.Contains(ud, "$ExtraName = 'ldap.test.example.com'") {
		t.Errorf("ldaps_name: %v", err)
	}
	if _, err := testEC2Lab().UserData("two\nlines-Passw0rd"); err == nil {
		t.Error("a line break in the password")
	}
}

// The password must pass Windows' complexity rule before anything is made: the Administrator gets it before the
// domain exists.
func TestCheckPasswordIsWindowsComplexityRule(t *testing.T) {
	for pw, ok := range map[string]bool{testPassword: true, "Abcdefg1": true, "abcdefg1!": true, "short1A": false, "alllowercase": false,
		"ALLUPPER123": false, "ALLUPPER123!": true, "Administrator1!": false, "": false} {
		if err := CheckPassword(pw); (err == nil) != ok {
			t.Errorf("%q: %v", pw, err)
		}
	}
}

// What would leave the script's quotes, or a domain Windows cannot create, is refused before anything is made.
func TestEC2LabRefusesWhatTheScriptCannotTake(t *testing.T) {
	for name, change := range map[string]func(*EC2Lab){
		"a dollar in the region":    func(e *EC2Lab) { e.Region = "$(whoami)" },
		"a single-label domain":     func(e *EC2Lab) { e.Domain = "corp" },
		"a quote in the domain":     func(e *EC2Lab) { e.Domain = "ad'.example.com" },
		"a long NetBIOS name":       func(e *EC2Lab) { e.NetBIOS = "ABCDEFGHIJKLMNOP" },
		"no port":                   func(e *EC2Lab) { e.LocalPort = 0 },
		"a quote in ldaps_name":     func(e *EC2Lab) { e.LDAPSName = "ldap.example.com'; whoami; '" },
		"a single-label name":       func(e *EC2Lab) { e.LDAPSName = "ldap" },
		"ldap_port the LDAPS one":   func(e *EC2Lab) { e.LDAPPort = e.LocalPort },
		"a 2025 forest on 2022":     func(e *EC2Lab) { e.ForestLevel, e.DomainLevel = 10, 10 },
		"a 2003 forest":             func(e *EC2Lab) { e.ForestLevel, e.DomainLevel = 2, 2 },
		"a domain below the forest": func(e *EC2Lab) { e.ForestLevel, e.DomainLevel = 7, 6 },
		"a recycle bin on 2008":     func(e *EC2Lab) { e.ForestLevel, e.DomainLevel, e.RecycleBin = 3, 3, true },
		"a brace in the name":       func(e *EC2Lab) { e.Name = "ldap-cronin-ad-x}]" },
		"a disk below the image's":  func(e *EC2Lab) { e.DiskSize = 20 },
		"a security group's name":   func(e *EC2Lab) { e.SecurityGroups = []string{"default"} },
		"the lab's tag in tags":     func(e *EC2Lab) { e.Tags = map[string]string{"ldap-cronin.lab": "other"} },
		"an aws: tag":               func(e *EC2Lab) { e.Tags = map[string]string{"aws:cloudformation:stack-name": "x"} },
		"an empty tag key":          func(e *EC2Lab) { e.Tags = map[string]string{"": "x"} },
	} {
		e := testEC2Lab()
		change(&e)
		if _, err := e.UserData(testPassword); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The commands shown: the lab's instance found by its tag (terminated ones left out), the latest image of its
// Windows Server, the instance with IMDSv2 and the lab's tags, the readiness polled, LDAPS to the port of
// [target] url. No password in any of them.
func TestEC2UpCommands(t *testing.T) {
	e := testEC2Lab()
	var all []string
	for _, c := range e.UpCommands() {
		all = append(all, c.Shell())
	}
	text := strings.Join(all, "\n")
	for _, want := range []string{
		"'Name=tag:ldap-cronin.lab,Values=ldap-cronin-ad' 'Name=instance-state-name,Values=pending,running,stopping,stopped'",
		"--name /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base",
		"--instance-type t3.large", "--subnet-id subnet-0123", "--iam-instance-profile 'Name=ldap-cronin-lab'",
		"'HttpTokens=required'", `{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"ldap-cronin-ad"},{"Key":"ldap-cronin.lab","Value":"ldap-cronin-ad"},{"Key":"ldap-cronin.realm","Value":"ad.example.com"}]}`,
		`{"ResourceType":"volume","Tags":[{"Key":"Name","Value":"ldap-cronin-ad"},`,
		"AWS-RunPowerShellScript", "get-command-invocation", "AWS-StartPortForwardingSession", "'portNumber=636,localPortNumber=12636'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the commands lack %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "put-parameter") || strings.Contains(text, testPassword) {
		t.Errorf("no parameter, no password:\n%s", text)
	}
	if strings.Contains(text, "--block-device-mappings") {
		t.Errorf("without disk_size, the image's volume: %s", text)
	}
	if strings.Contains(text, "--security-group-ids") {
		t.Errorf("without security_groups, the VPC's default: %s", text)
	}
	e.SecurityGroups = []string{"sg-02ed95a0b7fdab87c", "sg-0123456789abcdef0"}
	if run := e.UpCommands()[2].Shell(); !strings.Contains(run, "--security-group-ids sg-02ed95a0b7fdab87c sg-0123456789abcdef0 ") {
		t.Errorf("security_groups: %s", run)
	}
	if strings.Contains(text, "--associate-public-ip-address") {
		t.Errorf("without public_ip, the subnet's own: %s", text)
	}
	e.PublicIP = true
	if run := e.UpCommands()[2].Shell(); !strings.Contains(run, " --associate-public-ip-address ") {
		t.Errorf("public_ip: %s", run)
	}
	e.Windows, e.InstanceType, e.DiskSize = "2025", "m5.xlarge", 80
	if text := e.UpCommands()[1].Shell() + e.UpCommands()[2].Shell(); !strings.Contains(text, "Windows_Server-2025-") || !strings.Contains(text, "m5.xlarge") ||
		!strings.Contains(text, "--block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=80,VolumeType=gp3,DeleteOnTermination=true}'") {
		t.Errorf("windows, instance_type and disk_size: %s", text)
	}
}

// Shell quotes what a shell would take apart, and leaves the placeholders as they are.
func TestAWSCommandShellQuotes(t *testing.T) {
	c := AWSCommand{Args: []string{"ec2", "x", "--a", "it's", "--b", "<instance>", "--c", "plain-value_1.2/3", "--d", ""}}
	if got, want := c.Shell(), `aws ec2 x --a 'it'\''s' --b <instance> --c plain-value_1.2/3 --d ''`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// The forest is made with the source's functional levels, and the Recycle Bin enabled when asked; without them,
// Windows' defaults.
func TestEC2FunctionalLevelsAndRecycleBin(t *testing.T) {
	e := testEC2Lab()
	ud, err := e.UserData(testPassword)
	if err != nil || !strings.Contains(ud, "$ForestMode = ''") || !strings.Contains(ud, "$RecycleBin = ''") {
		t.Fatalf("defaults: %v", err)
	}
	e.ForestLevel, e.DomainLevel, e.RecycleBin = 6, 7, true
	ud, err = e.UserData(testPassword)
	for _, want := range []string{"$ForestMode = 'Win2012R2'", "$DomainMode = 'WinThreshold'", "$RecycleBin = 'yes'", "Install-ADDSForest @forest",
		"Enable-ADOptionalFeature -Credential $cred -Identity $feature -Scope ForestOrConfigurationSet"} {
		if err != nil || !strings.Contains(ud, want) {
			t.Errorf("lacks %q (%v)", want, err)
		}
	}
	e.Windows, e.ForestLevel, e.DomainLevel = "2025", 10, 10
	if ud, err := e.UserData(testPassword); err != nil || !strings.Contains(ud, "$ForestMode = 'Win2025'") {
		t.Errorf("a 2025 forest on 2025: %v", err)
	}
}

// tags go on the instance and its volume after the lab's own, by key, as JSON so that what a value holds needs no
// quoting; a Name among them is the instance's name, the lab's tag unchanged.
func TestEC2TagsAreTheAccountsToo(t *testing.T) {
	e := testEC2Lab()
	e.Tags = map[string]string{"Owner": "wadahiro", "CostCenter": "lab, test [1]", "Name": "my-ad"}
	run := strings.Join(e.runArgs("ami-1", "/tmp/ud"), " ")
	want := `[{"Key":"Name","Value":"my-ad"},{"Key":"ldap-cronin.lab","Value":"ldap-cronin-ad"},{"Key":"ldap-cronin.realm","Value":"ad.example.com"},` +
		`{"Key":"CostCenter","Value":"lab, test [1]"},{"Key":"Owner","Value":"wadahiro"}]`
	if strings.Count(run, want) != 2 || !strings.Contains(run, `"ResourceType":"volume"`) {
		t.Errorf("the tags: %s", run)
	}
	if _, err := e.UserData(testPassword); err != nil {
		t.Error(err)
	}
}
