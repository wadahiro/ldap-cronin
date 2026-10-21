# A Windows Server lab on Amazon EC2 (`[target.lab] platform = "ec2"`)

Status: stage 1 of 4 (the plan only: `lab up --config --dry-run`). **Nothing here has run on AWS yet**: the project
has no AWS account to test on, so every stage is tested by a user and corrected from what they report.

## 1. Goal

The Samba lab stands for an AD, closely but not exactly (no Exchange servers, Samba's own quirks, functional levels).
Some tests need a real Windows Server domain controller. Making one by hand takes an hour of clicks; the goal is the
same experience as the Samba lab: `lab up --config` makes a domain controller of the source's domain, then `check`
and `clone` write it as any lab.

Out of scope: a native import (Windows lets no one choose a domain SID or an objectGUID), more than one domain
controller, and using the lab as a production copy.

## 2. Stages

1. **The plan** (this): `[target.lab]` keys, the user data, and `lab up --config --dry-run`, which prints the user
   data and the aws commands without calling AWS. `lab up --config` without `--dry-run`, `check` and `clone` refuse
   an EC2 lab ("not there yet").
2. **lab up**: run the commands, wait for the instance, delete the parameter, forward LDAPS. The parameter is
   deleted on every way out, a failure or a timeout while waiting included; the target password is checked against
   Windows' complexity rule (4) before it is written.
3. **status, down, snapshot, restore, reset** on the resources tagged with the lab's name.
4. **check and clone** of an EC2 lab, as of a docker one.

## 3. Decisions

| Decision | Choice | Why |
|---|---|---|
| Where the platform is said | `[target.lab] platform = "docker"` (default) or `"ec2"` | A lab is made by `lab up --config` whatever it runs on; `profile` (ad, ldap) is another axis, and "kind" already means the kinds of objects |
| How AWS is called | the `aws` command (v2), not an SDK | Its credentials, profiles and SSO apply as the user has them; the binary stays small; `--dry-run` shows commands one can run by hand |
| The image | the public parameter `/aws/service/ami-windows-latest/Windows_Server-<windows>-English-Full-Base` | The latest patched image of the chosen version, in every region, without an AMI id in the config |
| Making the domain | user data (EC2Launch v2, `<persist>true</persist>`) in two phases: AD DS and `Install-ADDSForest`, a restart, then the rest as the domain's Administrator | A forest needs a restart; persisted user data runs again after it, and a marker file makes each phase run once |
| The password | the target password, put by lab up into a SecureString parameter **on standard input** (`--cli-input-json file:///dev/stdin`), read by the instance with `Get-SSMParameter`, deleted once the lab is ready | Never in the user data (readable from the instance's metadata and by `ec2:DescribeInstanceAttribute`), never an argument (visible in the process list) |
| Readiness | `ssm send-command` running `Test-Path C:\ldap-cronin\ready`, repeated | No inbound port is opened, so the instance's security group can stay closed |
| Reaching LDAPS | `ssm start-session --document-name AWS-StartPortForwardingSession` to `localhost:<port of [target] url>` | Same reason; the url of the config is the same for a docker and an EC2 lab |
| LDAPS certificate | a self-signed one (`New-SelfSignedCertificate`, server authentication), then `Restart-Service NTDS` | As the Samba lab's; AD picks a certificate with server authentication from the computer's store |
| Password policy | complexity off, minimum length 1, no history, no age | So the fixed password of the cloned users is accepted, as in the Samba lab |
| The marker attribute | indexed (`searchFlags` bit 1) when `[mapping]` uses one | As in the Samba lab: diff searches it |
| What the tool may delete | only resources tagged `ldap-cronin.lab = <lab name>` | lab down and reset must never touch anything else in the account |
| What the script takes | domain, NetBIOS name, region, parameter, marker checked before rendering: no quote, `$`, backtick or newline | They are put inside single quotes in PowerShell |

## 4. What the user needs (to be confirmed on AWS)

- The aws command v2 and the Session Manager plugin, credentials allowed to `ssm:PutParameter`, `ssm:GetParameter`,
  `ssm:DeleteParameter`, `ssm:SendCommand`, `ssm:GetCommandInvocation`, `ssm:StartSession`, `ec2:RunInstances`,
  `ec2:CreateTags`, `ec2:DescribeInstances` and `iam:PassRole` for the instance profile.
- A target password Windows accepts: `Set-LocalUser` and `Install-ADDSForest` apply the local complexity rule
  before the domain exists (at least 8 characters, three of upper case, lower case, digits and symbols, and not the
  account name). The second phase relaxes the domain's policy for the cloned users only; a weaker password stops
  the first phase, and the forest is never made.
- `subnet`: a subnet whose instances reach Systems Manager (a NAT gateway, or VPC endpoints for `ssm`,
  `ssmmessages` and `ec2messages`).
- `instance_profile`: a role with `AmazonSSMManagedInstanceCore` (which allows `ssm:GetParameter`), and
  `kms:Decrypt` on the key of the parameter when it is not the default `aws/ssm` key.

## 5. Unverified

- That `Get-SSMParameter` (AWS Tools for PowerShell) is on every listed Windows image, and works under EC2Launch v2
  before the instance profile's credentials are available.
- That `Restart-Computer` from persisted user data runs it again after the restart, rather than `exit 3010`.
- That `Set-ADDefaultDomainPasswordPolicy`, `Get-ADRootDSE` and `Set-ADObject` with `-Credential` work in the second
  phase, which runs as LocalSystem.
- That `Restart-Service NTDS` is enough for LDAPS to use the new certificate.
- How long it takes (an estimate: 15-20 minutes on t3.large).
