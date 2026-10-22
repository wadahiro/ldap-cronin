# A Windows Server lab on Amazon EC2 (`[target.lab] platform = "ec2"`)

Status: stage 3 of 4 (`lab up --config` and `lab reset --config` run the aws command; `check`, `clone` and `diff`
use the lab as any server through its tunnel). `lab up` ran on AWS on 2026-10-23 (Windows Server 2019), and a clone
of a dump into it was diff clean (section 5). The project has no AWS account to test on, so a user tests each stage.

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
2. **lab up and lab reset** (this): the instance found by its tag, used, started or launched; the readiness asked
   until READY; the tunnel commands printed for the user to run; reset terminates the tagged instances. `check`,
   `clone` and `diff` take the lab as any server at `[target] url`.
3. **status, down, snapshot, restore** (this) on the resources tagged with the lab's name: `lab down`, `status`,
   `snapshot`, `snapshots`, `restore`, `snapshot-rm` and `reset --snapshots` take `--config`. A snapshot is an EBS
   snapshot of the root volume, the instance stopped for it (the domain's database closed) and started again; a
   restore replaces the root volume by one made from it (EC2's replace root volume task: the instance keeps its
   id, address and tunnel commands; the replaced volume is deleted), gives the new volume the lab's tags, and waits
   for READY. The lab is its forest's only DC, so returning it to a past disk is safe (no USN rollback).
4. **check and clone** knowing the lab: whether it exists and runs, as for a docker one.

## 3. Decisions

| Decision | Choice | Why |
|---|---|---|
| Where the platform is said | `[target.lab] platform = "docker"` (default) or `"ec2"` | A lab is made by `lab up --config` whatever it runs on; `profile` (ad, ldap) is another axis, and "kind" already means the kinds of objects |
| How AWS is called | the `aws` command (v2), not an SDK | Its credentials, profiles and SSO apply as the user has them; the binary stays small; `--dry-run` shows commands one can run by hand |
| The image | the public parameter `/aws/service/ami-windows-latest/Windows_Server-<windows>-English-Full-Base` | The latest patched image of the chosen version, in every region, without an AMI id in the config |
| Making the domain | user data (EC2Launch v2, `<persist>true</persist>`) in two phases: AD DS and `Install-ADDSForest`, a restart, then the rest as the domain's Administrator | A forest needs a restart; persisted user data runs again after it, and a marker file makes each phase run once |
| The password | the target password, written into the user data, which goes to `aws` in a file only its owner reads, removed right after | The user's choice (2026-10-22), for a lab to test with: no parameter to put and delete, no IAM for it. The user data keeps it (the instance's metadata and `ec2:DescribeInstanceAttribute` read it); it is never an argument (the process list), never logged, and the dry-run shows a placeholder. Before: a SecureString parameter, read by the instance and deleted once ready |
| Readiness | `ssm send-command` answering READY or the last line of `setup.log`, every 30 seconds, 45 minutes at most; an instance Systems Manager does not know yet (its agent registering, the restart) is "not yet" | No inbound port is opened, so the instance's security group can stay closed |
| The tunnels | printed by lab up, run by the user in terminals of their own | They must last as long as the lab is used, longer than lab up |
| Reaching LDAPS | `ssm start-session --document-name AWS-StartPortForwardingSession` to `localhost:<port of [target] url>` | Same reason; the url of the config is the same for a docker and an EC2 lab |
| LDAPS certificate | a self-signed one (`New-SelfSignedCertificate`, server authentication), then `Restart-Service NTDS` | As the Samba lab's; AD picks a certificate with server authentication from the computer's store |
| Password policy | complexity off, minimum length 1, no history, no age | So the fixed password of the cloned users is accepted, as in the Samba lab |
| The marker attribute | indexed (`searchFlags` bit 1) when `[mapping]` uses one | As in the Samba lab: diff searches it |
| What the tool may delete | only resources tagged `ldap-cronin.lab = <lab name>` | lab down and reset must never touch anything else in the account |
| What the script takes | domain, NetBIOS name, region, marker, certificate name checked before rendering: no quote, `$`, backtick or newline; a quote of the password doubled, a line break refused | They are put inside single quotes in PowerShell |

## 4. What the user needs (to be confirmed on AWS)

- The aws command v2 and the Session Manager plugin, credentials allowed to `ec2:DescribeInstances`,
  `ec2:RunInstances`, `ec2:CreateTags`, `ec2:StartInstances`, `ec2:TerminateInstances`, and for stage 3
  `ec2:StopInstances`, `ec2:CreateSnapshot`, `ec2:DescribeSnapshots`, `ec2:DeleteSnapshot`,
  `ec2:CreateReplaceRootVolumeTask`, `ec2:DescribeReplaceRootVolumeTasks`; `ssm:GetParameter` (the
  public image parameter), `ssm:SendCommand`, `ssm:GetCommandInvocation`, `ssm:StartSession` and `iam:PassRole` for
  the instance profile.
- A target password Windows accepts: `Set-LocalUser` and `Install-ADDSForest` apply the local complexity rule
  before the domain exists (at least 8 characters, three of upper case, lower case, digits and symbols, and not the
  account name). The second phase relaxes the domain's policy for the cloned users only; a weaker password stops
  the first phase, and the forest is never made.
- `subnet`: a subnet whose instances reach Systems Manager (a NAT gateway, or VPC endpoints for `ssm`,
  `ssmmessages` and `ec2messages`, or an internet gateway with `public_ip = true`: an instance without a public
  address in a subnet that routes to an internet gateway only never registers, as a user's first lab up showed; without `public_ip` the instance has no public address even where the subnet
  assigns one: a domain controller is not put on the internet unasked).
- `instance_profile`: a role with `AmazonSSMManagedInstanceCore`, for Systems Manager to run the readiness command
  and the tunnels.

## 5. Verified

By `lab up --config` (2026-10-23, Windows Server 2019, t3.large, a user's account), after three failed runs fixed
on the way:

- From nothing to READY in about 20 minutes, two restarts included, unattended; the tunnels printed; `check`,
  `clone` and `diff` of a dump of a Windows Server 2019 domain (`OU=IDM`, forest and domain level 7, the Recycle Bin
  asked for) through the LDAPS tunnel: diff clean.
- `tags` on the instance and its volume (an account whose policy refuses an untagged instance), `security_groups`,
  `disk_size`, and `public_ip`: a subnet without a NAT gateway nor Systems Manager's VPC endpoints has its
  instances never register without a public address.
- The instance profile is the account's own (`AmazonSSMManagedInstanceCore` attached).
- AD cmdlets with `-Credential` and no `-Server` failed once the forest was up, for `AD\SYSTEM` ("The operation
  failed because of a bad parameter") and in an Administrator's session ("the server has rejected the client
  credentials"), while `-Server` with the DC's name or `localhost` took the same credential: the user data names
  the DC for every AD cmdlet. That failure stopped the Recycle Bin's enabling, then the wait for AD.
- NTDS takes the LDAPS certificate at a restart of the computer (the user data no longer restarts NTDS alone).

By hand (2026-10-22, Windows Server 2019, the user data pasted into the console):

- The persisted user data runs again after the forest's restart (EC2Launch v2), as `AD\SYSTEM`; the whole took
  about 13 minutes on t3.large, 4-5 of them waiting for AD Web Services after the restart.
- A self-signed certificate in `LocalMachine\My` alone is not enough: the DC closed every TLS handshake on 636 until
  the certificate was also in its trusted roots (`LocalMachine\Root`). The user data does both now.
- LDAPS through `AWS-StartPortForwardingSession` from another machine works (ldapsearch with `LDAPTLS_REQCERT=never`).

## 6. Unverified

- `Set-ADObject` on the marker's `searchFlags` (the test left the marker out: `[mapping] mode = "file"`).
- Windows Server 2016, 2022 and 2025.
- `lab up` with an instance that is stopped (started) or running (used); `lab reset --config`.
- Stage 3 on AWS: snapshot, restore (whether the replacement volume keeps the original's tags before lab restore
  gives it the lab's, for an account whose policy refuses an untagged volume), down, status.
