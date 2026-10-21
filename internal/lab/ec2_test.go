package lab

import (
	"strings"
	"testing"
)

func testEC2Lab() EC2Lab {
	return EC2Lab{Name: "ldap-cronin-ad", Domain: "ad.example.com", NetBIOS: "AD", Region: "ap-northeast-1",
		Subnet: "subnet-0123", InstanceProfile: "ldap-cronin-lab", PasswordParameter: "/ldap-cronin/ldap-cronin-ad/admin-password",
		LocalPort: 12636, MarkerAttribute: "adminDisplayName"}
}

// The user data makes the source's domain and reads the password from the parameter: it never holds the password.
func TestEC2UserDataMakesTheSourcesDomainAndReadsThePasswordFromTheParameter(t *testing.T) {
	ud, err := testEC2Lab().UserData()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<powershell>", "</powershell>\n<persist>true</persist>", "$Domain = 'ad.example.com'", "$NetBIOS = 'AD'",
		"$Parameter = '/ldap-cronin/ldap-cronin-ad/admin-password'", "$Region = 'ap-northeast-1'", "$Marker = 'adminDisplayName'",
		"Get-SSMParameter -Name $Parameter -WithDecryption $true", "Install-ADDSForest", `C:\ldap-cronin\ready`} {
		if !strings.Contains(ud, want) {
			t.Errorf("the user data lacks %q", want)
		}
	}
	if strings.Contains(ud, "{{") {
		t.Errorf("a field is left unfilled:\n%s", ud)
	}
}

// What would leave the script's quotes, or a domain Windows cannot create, is refused before anything is made.
func TestEC2LabRefusesWhatTheScriptCannotTake(t *testing.T) {
	for name, change := range map[string]func(*EC2Lab){
		"a quote in the parameter": func(e *EC2Lab) { e.PasswordParameter = "/x'; Remove-Item C:\\ -Recurse; '" },
		"a dollar in the region":   func(e *EC2Lab) { e.Region = "$(whoami)" },
		"a single-label domain":    func(e *EC2Lab) { e.Domain = "corp" },
		"a quote in the domain":    func(e *EC2Lab) { e.Domain = "ad'.example.com" },
		"a long NetBIOS name":      func(e *EC2Lab) { e.NetBIOS = "ABCDEFGHIJKLMNOP" },
		"no port":                  func(e *EC2Lab) { e.LocalPort = 0 },
	} {
		e := testEC2Lab()
		change(&e)
		if _, err := e.UserData(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The password goes to the parameter on standard input, never as an argument; the instance gets IMDSv2, the lab's
// tags, the latest image of its Windows Server; LDAPS comes to the port of [target] url.
func TestEC2UpCommands(t *testing.T) {
	e := testEC2Lab()
	cmds := e.UpCommands()
	var all []string
	for _, c := range cmds {
		all = append(all, c.Shell())
	}
	text := strings.Join(all, "\n")
	put := cmds[0]
	if put.Args[0] != "ssm" || put.Args[1] != "put-parameter" || !strings.Contains(put.Shell(), "--cli-input-json file:///dev/stdin") ||
		!strings.Contains(put.Stdin, `"SecureString"`) || !strings.Contains(put.Stdin, "<the target password>") {
		t.Errorf("the password parameter: %s / %s", put.Shell(), put.Stdin)
	}
	for _, want := range []string{
		"--name /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base",
		"--instance-type t3.large", "--subnet-id subnet-0123", "--iam-instance-profile 'Name=ldap-cronin-lab'",
		"'HttpTokens=required'", "Key=ldap-cronin.lab,Value=ldap-cronin-ad", "Key=ldap-cronin.realm,Value=ad.example.com",
		"aws ssm delete-parameter --region ap-northeast-1 --name /ldap-cronin/ldap-cronin-ad/admin-password",
		"AWS-StartPortForwardingSession", "'portNumber=636,localPortNumber=12636'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the commands lack %q:\n%s", want, text)
		}
	}
	e.Windows, e.InstanceType = "2025", "m5.xlarge"
	if text := e.UpCommands()[1].Shell() + e.UpCommands()[2].Shell(); !strings.Contains(text, "Windows_Server-2025-") || !strings.Contains(text, "m5.xlarge") {
		t.Errorf("windows and instance_type: %s", text)
	}
}

// Shell quotes what a shell would take apart, and leaves the placeholders as they are.
func TestAWSCommandShellQuotes(t *testing.T) {
	c := AWSCommand{Args: []string{"ec2", "x", "--a", "it's", "--b", "<instance>", "--c", "plain-value_1.2/3", "--d", ""}}
	if got, want := c.Shell(), `aws ec2 x --a 'it'\''s' --b <instance> --c plain-value_1.2/3 --d ''`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
