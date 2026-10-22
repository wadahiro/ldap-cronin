package lab

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"unicode"
)

// ec2UserData is the PowerShell an EC2 lab's instance runs at every boot until it is a ready domain controller.
//
//go:embed ec2_userdata.ps1
var ec2UserData string

var ec2UserDataTemplate = template.Must(template.New("userdata").Parse(ec2UserData))

// EC2Lab is a lab on Amazon EC2: a Windows Server instance that makes itself the only domain controller of a new
// forest with the source's domain name. It is made through the aws command, as a docker lab is through docker.
// Windows lets no one choose a domain SID, so a native import is impossible; the domain name is the source's.
type EC2Lab struct {
	// Name is the lab's name, in the instance's tags (ldap-cronin.lab).
	Name string
	// Domain and NetBIOS are the source's.
	Domain, NetBIOS                                        string
	Region, Subnet, InstanceType, Windows, InstanceProfile string
	// LocalPort is where the port forwarding to the instance's LDAPS listens: the port of [target] url.
	LocalPort int
	// MarkerAttribute, when set, is indexed (searchFlags bit 1), as the Samba lab indexes it.
	MarkerAttribute string
	// LDAPSName, when set, is one more DNS name of the LDAPS certificate, besides the DC's and the domain's: the
	// name a client verifying the certificate connects by.
	LDAPSName string
	// LDAPPort, when set, is the local port LDAP (389) of the instance is forwarded to too, for clients that do not
	// use LDAPS. The instance listens on 389 whatever it is.
	LDAPPort int
	// LDAPUnsigned has the instance take a simple bind on 389 without signing (LDAPServerIntegrity 1), as Windows
	// Server 2019 and 2022 do by default and 2025 does not for a new forest.
	LDAPUnsigned bool
	// ForestLevel and DomainLevel are the source's functional levels (msDS-Behavior-Version: 7 is Windows Server
	// 2016), the forest made with them; 0 leaves the highest the instance's Windows Server makes.
	ForestLevel, DomainLevel int
	// RecycleBin enables the AD Recycle Bin (forest level 4, 2008 R2, or higher).
	RecycleBin bool
	// DiskSize is the root volume's size in GiB (gp3); 0 leaves the image's (30 GiB for Windows Server).
	DiskSize int
	// SecurityGroups are attached to the instance; none leaves the VPC's default group. Systems Manager needs no
	// inbound rule: the instance's agent reaches out.
	SecurityGroups []string

	instance string // the instance, once known (WithInstance)
}

// modes are the names Install-ADDSForest takes for the functional levels a Windows Server of today makes: none
// below 2008 (3), and 2025 (10) from Windows Server 2025 only.
var modes = map[int]string{3: "Win2008", 4: "Win2008R2", 5: "Win2012", 6: "Win2012R2", 7: "WinThreshold", 10: "Win2025"}

// ForestMode and DomainMode are the -ForestMode and -DomainMode of Install-ADDSForest, "" for the default.
func (e EC2Lab) ForestMode() string { return modes[e.ForestLevel] }
func (e EC2Lab) DomainMode() string { return modes[e.DomainLevel] }

// maxLevel is the highest functional level the instance's Windows Server makes.
func (e EC2Lab) maxLevel() int {
	if e.windows() == "2025" {
		return 10
	}
	return 7
}

// AWSCommand is one aws command lab up runs; Stdin, when set, says what it is given on standard input (never shown).
type AWSCommand struct {
	Args  []string
	Stdin string
	Why   string
}

// Defaults of an EC2 lab.
const (
	DefaultInstanceType = "t3.large"
	DefaultWindows      = "2022"
)

var (
	ec2DomainPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
	ec2NetBIOSPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
	securityGroupPattern = regexp.MustCompile(`^sg-[0-9a-f]{8,17}$`)
	ec2NamePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// Check refuses settings the instance could not use, or that would not stay inside the PowerShell's quotes.
func (e EC2Lab) Check() error {
	if !ec2NamePattern.MatchString(e.Name) {
		return fmt.Errorf("lab name %q: lowercase letters, digits and hyphens (the prefix and the instance)", e.Name)
	}
	if !ec2DomainPattern.MatchString(e.Domain) || !strings.Contains(e.Domain, ".") {
		return fmt.Errorf("an EC2 lab needs a DNS domain name (ad.example.com), got %q", e.Domain)
	}
	if e.LDAPSName != "" && (!ec2DomainPattern.MatchString(e.LDAPSName) || !strings.Contains(e.LDAPSName, ".")) {
		return fmt.Errorf("ldaps_name %q: a DNS name (ldap.test.example.com)", e.LDAPSName)
	}
	if !ec2NetBIOSPattern.MatchString(e.NetBIOS) {
		return fmt.Errorf("NetBIOS name %q: letters, digits and hyphens, at most 15", e.NetBIOS)
	}
	for name, v := range map[string]string{"region": e.Region, "marker attribute": e.MarkerAttribute} {
		if strings.ContainsAny(v, "'`$\r\n") {
			return fmt.Errorf("%s %q holds a character the instance's script cannot take", name, v)
		}
	}
	if e.LocalPort <= 0 {
		return fmt.Errorf("[target] url needs a port for the EC2 lab's port forwarding")
	}
	for name, level := range map[string]int{"forest": e.ForestLevel, "domain": e.DomainLevel} {
		switch {
		case level == 0:
		case level > e.maxLevel():
			return fmt.Errorf("the source's %s functional level is %d: Windows Server %s makes %d at most (windows = \"2025\" makes 10)", name, level, e.windows(), e.maxLevel())
		case modes[level] == "":
			return fmt.Errorf("the source's %s functional level is %d, which Windows Server %s cannot make (2008, 3, at least)", name, level, e.windows())
		}
	}
	if e.ForestLevel != 0 && e.DomainLevel != 0 && e.DomainLevel < e.ForestLevel {
		return fmt.Errorf("domain functional level %d below the forest's %d", e.DomainLevel, e.ForestLevel)
	}
	for _, g := range e.SecurityGroups {
		if !securityGroupPattern.MatchString(g) {
			return fmt.Errorf("security_groups: %q is not a security group id (sg-0123456789abcdef0)", g)
		}
	}
	if e.DiskSize != 0 && (e.DiskSize < minDiskSize || e.DiskSize > 16384) {
		return fmt.Errorf("disk_size %d: from %d GiB (the Windows Server image's) to 16384", e.DiskSize, minDiskSize)
	}
	if e.RecycleBin && e.ForestLevel != 0 && e.ForestLevel < 4 {
		return fmt.Errorf("the AD Recycle Bin needs forest functional level 4 (2008 R2) or higher; the source's is %d", e.ForestLevel)
	}
	if e.LDAPPort < 0 || e.LDAPPort > 65535 || e.LDAPPort != 0 && e.LDAPPort == e.LocalPort {
		return fmt.Errorf("ldap_port %d: a local port other than that of [target] url (%d)", e.LDAPPort, e.LocalPort)
	}
	return nil
}

func (e EC2Lab) instanceType() string {
	if e.InstanceType == "" {
		return DefaultInstanceType
	}
	return e.InstanceType
}

func (e EC2Lab) windows() string {
	if e.Windows == "" {
		return DefaultWindows
	}
	return e.Windows
}

// AMIParameter is the public Systems Manager parameter that names the latest AWS Windows Server image.
func (e EC2Lab) AMIParameter() string {
	return "/aws/service/ami-windows-latest/Windows_Server-" + e.windows() + "-English-Full-Base"
}

// PasswordPlaceholder stands for the password in what is shown (lab up --dry-run): the user data shown never holds it.
const PasswordPlaceholder = "<the target password>"

// UserData is the script the instance runs at every boot (EC2Launch v2, persisted), with password as the
// Administrator's (and the directory services restore mode's), in single quotes.
func (e EC2Lab) UserData(password string) (string, error) {
	if err := e.Check(); err != nil {
		return "", err
	}
	if strings.ContainsAny(password, "\r\n") {
		return "", fmt.Errorf("the target password holds a line break, which the instance's script cannot take")
	}
	var b bytes.Buffer
	data := struct {
		EC2Lab
		Password string
	}{e, strings.ReplaceAll(password, "'", "''")}
	if err := ec2UserDataTemplate.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// CheckPassword refuses a password Windows would refuse for the Administrator before its domain exists (the local
// complexity rule): at least 8 characters, of three of upper case, lower case, digits and the others, and not the
// account's name. Refused on the instance, it would stop the forest's creation with nothing to show for it.
func CheckPassword(password string) error {
	kinds := 0
	for _, in := range []func(rune) bool{unicode.IsUpper, unicode.IsLower, unicode.IsDigit,
		func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }} {
		if strings.IndexFunc(password, in) >= 0 {
			kinds++
		}
	}
	if len([]rune(password)) < 8 || kinds < 3 || strings.Contains(strings.ToLower(password), "administrator") {
		return fmt.Errorf("the target password must pass Windows' complexity rule, as it becomes the Administrator's before the domain exists: at least 8 characters, of three of upper case, lower case, digits and symbols, without \"Administrator\"")
	}
	return nil
}

// tags are those of every resource the lab makes: lab down and reset act on what carries them, never on anything else.
func (e EC2Lab) tags() string {
	return fmt.Sprintf("{Key=Name,Value=%s},{Key=ldap-cronin.lab,Value=%s},{Key=ldap-cronin.realm,Value=%s}", e.Name, e.Name, e.Domain)
}

// UpCommands are the aws commands lab up --config runs to make the lab, in order, as lab up --dry-run shows them:
// <ami>, <instance> and <command> stand for what an earlier command returned.
func (e EC2Lab) UpCommands() []AWSCommand {
	cmds := []AWSCommand{
		{Args: e.findArgs(), Why: "the lab's instance, if there is one (by its tag): a running one is used, a stopped one started"},
		{Args: e.amiArgs(), Why: "the latest Windows Server " + e.windows() + " image"},
		{Args: e.runArgs("<ami>", "<the user data above, in a file only its owner reads, removed right after>"),
			Why: "the instance; its user data makes it the domain controller of " + e.Domain + " (about 15 minutes)"},
		{Args: e.awsArgs("ec2", "wait", "instance-running", "--instance-ids", "<instance>"), Why: "until it runs"},
		{Args: e.pollArgs("<instance>"), Why: "every 30 seconds until it says READY (the last line of its setup.log shown meanwhile)"},
		{Args: e.invocationArgs("<command>", "<instance>"), Why: "the answer of the command above"},
	}
	return append(cmds, e.TunnelCommands()...)
}

// TunnelCommands forward the instance's LDAPS (and LDAP, with ldap_port) to this machine, through Systems Manager
// (session-manager-plugin): each runs in its own terminal while the lab is used.
func (e EC2Lab) TunnelCommands() []AWSCommand {
	instance := "<instance>"
	if e.instance != "" {
		instance = e.instance
	}
	cmds := []AWSCommand{{Args: e.awsArgs("ssm", "start-session", "--target", instance, "--document-name", "AWS-StartPortForwardingSession",
		"--parameters", "portNumber=636,localPortNumber="+strconv.Itoa(e.LocalPort)),
		Why: "LDAPS of the instance at localhost:" + strconv.Itoa(e.LocalPort) + " ([target] url)"}}
	if e.LDAPPort > 0 {
		cmds = append(cmds, AWSCommand{Args: e.awsArgs("ssm", "start-session", "--target", instance, "--document-name", "AWS-StartPortForwardingSession",
			"--parameters", "portNumber=389,localPortNumber="+strconv.Itoa(e.LDAPPort)),
			Why: "LDAP of the instance at localhost:" + strconv.Itoa(e.LDAPPort) + " ([target.lab] ldap_port), for clients that do not use LDAPS"})
	}
	return cmds
}

// Instance is the lab's instance, once known ("" before).
func (e EC2Lab) Instance() string { return e.instance }

// WithInstance is e with its instance known, for the commands that name it.
func (e EC2Lab) WithInstance(id string) EC2Lab {
	e.instance = id
	return e
}

func (e EC2Lab) awsArgs(args ...string) []string {
	return append(args, "--region", e.Region)
}

func (e EC2Lab) findArgs() []string {
	return e.awsArgs("ec2", "describe-instances", "--filters", "Name=tag:ldap-cronin.lab,Values="+e.Name,
		"Name=instance-state-name,Values=pending,running,stopping,stopped",
		"--query", "Reservations[].Instances[].[InstanceId,State.Name]", "--output", "text")
}

func (e EC2Lab) amiArgs() []string {
	return e.awsArgs("ssm", "get-parameter", "--name", e.AMIParameter(), "--query", "Parameter.Value", "--output", "text")
}

// minDiskSize is the root volume of the Windows Server images (GiB): a smaller one is refused.
const minDiskSize = 30

func (e EC2Lab) runArgs(ami, userData string) []string {
	args := []string{"ec2", "run-instances", "--image-id", ami, "--instance-type", e.instanceType(), "--subnet-id", e.Subnet,
		"--iam-instance-profile", "Name=" + e.InstanceProfile, "--metadata-options", "HttpTokens=required",
		"--user-data", "file://" + userData,
		"--tag-specifications", "ResourceType=instance,Tags=[" + e.tags() + "]", "ResourceType=volume,Tags=[" + e.tags() + "]"}
	if len(e.SecurityGroups) > 0 {
		args = append(append(args, "--security-group-ids"), e.SecurityGroups...)
	}
	if e.DiskSize > 0 { // the root device of the Windows Server images
		args = append(args, "--block-device-mappings",
			fmt.Sprintf("DeviceName=/dev/sda1,Ebs={VolumeSize=%d,VolumeType=gp3,DeleteOnTermination=true}", e.DiskSize))
	}
	return e.awsArgs(append(args, "--query", "Instances[0].InstanceId", "--output", "text")...)
}

// readyScript answers READY once the user data has finished, else the last line of its log.
const readyScript = `if (Test-Path C:\ldap-cronin\ready) { 'READY' } elseif (Test-Path C:\ldap-cronin\setup.log) { Get-Content C:\ldap-cronin\setup.log -Tail 1 } else { 'starting' }`

func (e EC2Lab) pollArgs(instance string) []string {
	params, _ := json.Marshal(map[string][]string{"commands": {readyScript}})
	return e.awsArgs("ssm", "send-command", "--instance-ids", instance, "--document-name", "AWS-RunPowerShellScript",
		"--parameters", string(params), "--query", "Command.CommandId", "--output", "text")
}

func (e EC2Lab) invocationArgs(command, instance string) []string {
	return e.awsArgs("ssm", "get-command-invocation", "--command-id", command, "--instance-id", instance,
		"--query", "[Status,StandardOutputContent]", "--output", "text")
}

// Shell writes a command as one could type it.
func (c AWSCommand) Shell() string {
	parts := []string{"aws"}
	for _, a := range c.Args {
		if a == "" || strings.ContainsAny(a, " \t\"'[]{}$*?;&|<>(),\\=") && !strings.HasPrefix(a, "<") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}
