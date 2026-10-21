package lab

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"
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
	// Name is the lab's name, in the instance's tags (ldap-cronin.lab) and its parameter.
	Name string
	// Domain and NetBIOS are the source's.
	Domain, NetBIOS                                        string
	Region, Subnet, InstanceType, Windows, InstanceProfile string
	// PasswordParameter carries the Administrator password to the instance (SecureString).
	PasswordParameter string
	// LocalPort is where the port forwarding to the instance's LDAPS listens: the port of [target] url.
	LocalPort int
	// MarkerAttribute, when set, is indexed (searchFlags bit 1), as the Samba lab indexes it.
	MarkerAttribute string
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
	ec2DomainPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
	ec2NetBIOSPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
)

// Check refuses settings the instance could not use, or that would not stay inside the PowerShell's quotes.
func (e EC2Lab) Check() error {
	if !ec2DomainPattern.MatchString(e.Domain) || !strings.Contains(e.Domain, ".") {
		return fmt.Errorf("an EC2 lab needs a DNS domain name (ad.example.com), got %q", e.Domain)
	}
	if !ec2NetBIOSPattern.MatchString(e.NetBIOS) {
		return fmt.Errorf("NetBIOS name %q: letters, digits and hyphens, at most 15", e.NetBIOS)
	}
	for name, v := range map[string]string{"password_parameter": e.PasswordParameter, "region": e.Region, "marker attribute": e.MarkerAttribute} {
		if strings.ContainsAny(v, "'`$\r\n") {
			return fmt.Errorf("%s %q holds a character the instance's script cannot take", name, v)
		}
	}
	if e.LocalPort <= 0 {
		return fmt.Errorf("[target] url needs a port for the EC2 lab's port forwarding")
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

// UserData is the script the instance runs at every boot (EC2Launch v2, persisted).
func (e EC2Lab) UserData() (string, error) {
	if err := e.Check(); err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := ec2UserDataTemplate.Execute(&b, e); err != nil {
		return "", err
	}
	return b.String(), nil
}

// tags are those of every resource the lab makes: lab down and reset act on what carries them, never on anything else.
func (e EC2Lab) tags() string {
	return fmt.Sprintf("{Key=Name,Value=%s},{Key=ldap-cronin.lab,Value=%s},{Key=ldap-cronin.realm,Value=%s}", e.Name, e.Name, e.Domain)
}

// UpCommands are the aws commands lab up --config runs to make the lab, in order. <ami> and <instance> stand for
// what an earlier command returned.
func (e EC2Lab) UpCommands() []AWSCommand {
	region := []string{"--region", e.Region}
	return []AWSCommand{
		{Args: append([]string{"ssm", "put-parameter"}, append(region, "--cli-input-json", "file:///dev/stdin")...),
			Stdin: fmt.Sprintf(`{"Name": %q, "Type": "SecureString", "Overwrite": true, "Value": <the target password>}`, e.PasswordParameter),
			Why:   "the Administrator password, for the instance to read (on standard input: never an argument)"},
		{Args: append([]string{"ssm", "get-parameter"}, append(region, "--name", e.AMIParameter(), "--query", "Parameter.Value", "--output", "text")...),
			Why: "the latest Windows Server " + e.windows() + " image"},
		{Args: append([]string{"ec2", "run-instances"}, append(region,
			"--image-id", "<ami>", "--instance-type", e.instanceType(), "--subnet-id", e.Subnet,
			"--iam-instance-profile", "Name="+e.InstanceProfile, "--metadata-options", "HttpTokens=required",
			"--user-data", "file://<the user data above>",
			"--tag-specifications", "ResourceType=instance,Tags=["+e.tags()+"]", "ResourceType=volume,Tags=["+e.tags()+"]",
			"--query", "Instances[0].InstanceId", "--output", "text")...),
			Why: "the instance; its user data makes it the domain controller of " + e.Domain + " (about 15-20 minutes)"},
		{Args: append([]string{"ec2", "wait", "instance-running"}, append(region, "--instance-ids", "<instance>")...),
			Why: "until it runs (its user data goes on, restarting it once)"},
		{Args: append([]string{"ssm", "send-command"}, append(region, "--instance-ids", "<instance>",
			"--document-name", "AWS-RunPowerShellScript", "--parameters", `commands=["Test-Path C:\ldap-cronin\ready"]`)...),
			Why: "its output read with ssm get-command-invocation, repeated until the instance says True: ready (Systems Manager, so no port is opened)"},
		{Args: append([]string{"ssm", "delete-parameter"}, append(region, "--name", e.PasswordParameter)...),
			Why: "the password, no longer needed by the instance"},
		{Args: append([]string{"ssm", "start-session"}, append(region, "--target", "<instance>",
			"--document-name", "AWS-StartPortForwardingSession",
			"--parameters", "portNumber=636,localPortNumber="+strconv.Itoa(e.LocalPort))...),
			Why: "LDAPS of the instance at localhost:" + strconv.Itoa(e.LocalPort) + " ([target] url), while lab up runs (session-manager-plugin)"},
	}
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
