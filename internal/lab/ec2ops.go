package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The EC2 lab's life after lab up: its status, down, and snapshots of its root volume restored into it. Everything
// is found by the lab's tag, as lab up and lab reset find the instance. A snapshot is an EBS snapshot of the
// instance's root volume, taken stopped (the domain's database closed), tagged with the lab, its name and its note;
// a restore replaces the instance's root volume by one made from it (EC2's replace root volume), so the instance,
// its address and its tunnels stay. The lab is the forest's only domain controller: a return to a past disk is
// safe for it, as no other DC holds a later state of the domain.

// The tags of a snapshot besides the lab's own.
const (
	snapshotTag = "ldap-cronin.snapshot"
	noteTag     = "ldap-cronin.note"
)

// ec2Instance is an instance as describe-instances gives it.
type ec2Instance struct {
	InstanceID          string `json:"InstanceId"`
	State               struct{ Name string }
	InstanceType        string
	LaunchTime          string
	PrivateIPAddress    string `json:"PrivateIpAddress"`
	PublicIPAddress     string `json:"PublicIpAddress"`
	RootDeviceName      string
	BlockDeviceMappings []struct {
		DeviceName string
		Ebs        struct {
			VolumeID string `json:"VolumeId"`
		}
	}
}

func (i ec2Instance) rootVolume() string {
	for _, m := range i.BlockDeviceMappings {
		if m.DeviceName == i.RootDeviceName {
			return m.Ebs.VolumeID
		}
	}
	return ""
}

// EC2Snapshot is a snapshot of the lab.
type EC2Snapshot struct {
	ID, Name, Note, State, Progress string
	Created                         time.Time
	SizeGiB                         int
}

// describe gives the lab's instances that are not terminated, in full.
func (e EC2Lab) describe(ctx context.Context, aws AWS) ([]ec2Instance, error) {
	out, err := aws.Run(ctx, e.awsArgs("ec2", "describe-instances", "--filters", "Name=tag:"+labTag+",Values="+e.Name,
		"Name=instance-state-name,Values=pending,running,stopping,stopped", "--query", "Reservations[].Instances[]", "--output", "json")...)
	if err != nil {
		return nil, err
	}
	var found []ec2Instance
	if err := json.Unmarshal([]byte(orEmptyList(out)), &found); err != nil {
		return nil, fmt.Errorf("aws ec2 describe-instances: %v", err)
	}
	return found, nil
}

// only is the lab's instance, which an operation on it needs to be one.
func (e EC2Lab) only(ctx context.Context, aws AWS) (ec2Instance, error) {
	found, err := e.describe(ctx, aws)
	if err != nil {
		return ec2Instance{}, err
	}
	switch len(found) {
	case 0:
		return ec2Instance{}, fmt.Errorf("the lab %s has no instance: lab up --config makes it", e.Name)
	case 1:
		return found[0], nil
	}
	var ids []string
	for _, i := range found {
		ids = append(ids, i.InstanceID+" ("+i.State.Name+")")
	}
	return ec2Instance{}, fmt.Errorf("the lab %s has %d instances (%s): lab reset --config removes them", e.Name, len(found), strings.Join(ids, ", "))
}

// Snapshots are the lab's snapshots, oldest first.
func (e EC2Lab) Snapshots(ctx context.Context, aws AWS) ([]EC2Snapshot, error) {
	out, err := aws.Run(ctx, e.awsArgs("ec2", "describe-snapshots", "--owner-ids", "self", "--filters", "Name=tag:"+labTag+",Values="+e.Name,
		"--query", "Snapshots[]", "--output", "json")...)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		SnapshotID string `json:"SnapshotId"`
		StartTime  string
		State      string
		Progress   string
		VolumeSize int
		Tags       []ec2Tag
	}
	if err := json.Unmarshal([]byte(orEmptyList(out)), &raw); err != nil {
		return nil, fmt.Errorf("aws ec2 describe-snapshots: %v", err)
	}
	var list []EC2Snapshot
	for _, r := range raw {
		s := EC2Snapshot{ID: r.SnapshotID, State: r.State, Progress: r.Progress, SizeGiB: r.VolumeSize}
		s.Created, _ = time.Parse(time.RFC3339, r.StartTime)
		for _, t := range r.Tags {
			switch t.Key {
			case snapshotTag:
				s.Name = t.Value
			case noteTag:
				s.Note = t.Value
			}
		}
		list = append(list, s)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	return list, nil
}

func orEmptyList(out string) string {
	if strings.TrimSpace(out) == "" || strings.TrimSpace(out) == "null" {
		return "[]"
	}
	return out
}

// FormatEC2Snapshots is the list for display, oldest first.
func FormatEC2Snapshots(list []EC2Snapshot) string {
	if len(list) == 0 {
		return "No snapshots\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-24s %-19s  %-10s %6s  %-22s  %s\n", "NAME", "CREATED", "STATE", "SIZE", "ID", "NOTE")
	for _, s := range list {
		state := s.State
		if s.State == "pending" && s.Progress != "" {
			state += " " + s.Progress
		}
		fmt.Fprintf(&b, "%-24s %s  %-10s %6s  %-22s  %s\n", s.Name, s.Created.Local().Format("2006-01-02 15:04:05"), state,
			fmt.Sprintf("%dGiB", s.SizeGiB), s.ID, s.Note)
	}
	return b.String()
}

// Status shows the lab's instance and its snapshots.
func (e EC2Lab) Status(ctx context.Context, r EC2Run) error {
	found, err := e.describe(ctx, r.AWS)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		fmt.Fprintf(r.Log, "The lab %s (%s, %s) has no instance\n", e.Name, e.Domain, e.Region)
	}
	for _, i := range found {
		fmt.Fprintf(r.Log, "The lab %s (%s, %s): instance %s, %s\n", e.Name, e.Domain, e.Region, i.InstanceID, i.State.Name)
		fmt.Fprintf(r.Log, "  type %s, launched %s, root volume %s\n", i.InstanceType, i.LaunchTime, i.rootVolume())
		fmt.Fprintf(r.Log, "  private address %s, public address %s\n", orNone(i.PrivateIPAddress), orNone(i.PublicIPAddress))
	}
	list, err := e.Snapshots(ctx, r.AWS)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Log, "Snapshots: %d (lab snapshots --config lists them)\n", len(list))
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// Down stops the lab's instance: the domain stays on its volume, and lab up --config starts it again.
func (e EC2Lab) Down(ctx context.Context, r EC2Run) error {
	found, err := e.describe(ctx, r.AWS)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		fmt.Fprintf(r.Log, "==> The lab %s has no instance\n", e.Name)
		return nil
	}
	for _, i := range found {
		if err := e.stop(ctx, r, i); err != nil {
			return err
		}
	}
	return nil
}

// stop stops an instance and waits until it is stopped.
func (e EC2Lab) stop(ctx context.Context, r EC2Run, i ec2Instance) error {
	switch i.State.Name {
	case "stopped":
		fmt.Fprintf(r.Log, "==> %s is stopped\n", i.InstanceID)
		return nil
	case "pending", "running":
		fmt.Fprintf(r.Log, "==> Stopping %s\n", i.InstanceID)
		if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "stop-instances", "--instance-ids", i.InstanceID)...); err != nil {
			return err
		}
	}
	if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "wait", "instance-stopped", "--instance-ids", i.InstanceID)...); err != nil {
		return err
	}
	fmt.Fprintf(r.Log, "==> %s is stopped\n", i.InstanceID)
	return nil
}

// start starts a stopped instance and waits until it runs.
func (e EC2Lab) start(ctx context.Context, r EC2Run, id string) error {
	fmt.Fprintf(r.Log, "==> Starting %s\n", id)
	if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "start-instances", "--instance-ids", id)...); err != nil {
		return err
	}
	_, err := r.AWS.Run(ctx, e.awsArgs("ec2", "wait", "instance-running", "--instance-ids", id)...)
	return err
}

// EC2SnapshotOptions are lab snapshot's.
type EC2SnapshotOptions struct {
	Name  string // "" names it after the date and time
	Note  string
	Force bool // replaces a snapshot of the same name
	Now   func() time.Time
}

// Snapshot takes a snapshot of the lab's root volume. A running instance is stopped first, so that the domain's
// database is closed, and started again once the snapshot is taken (EBS keeps the volume's state of that moment
// while the snapshot completes in the background).
func (e EC2Lab) Snapshot(ctx context.Context, r EC2Run, o EC2SnapshotOptions) (EC2Snapshot, error) {
	name := o.Name
	if name == "" {
		now := o.Now
		if now == nil {
			now = time.Now
		}
		name = snapshotPrefix + now().Format(timestampLayout)
	}
	if err := ValidateSnapshotName(name); err != nil {
		return EC2Snapshot{}, err
	}
	if len(o.Note) > 256 {
		return EC2Snapshot{}, errors.New("--note: at most 256 characters (it is a tag's value)")
	}
	existing, err := e.Snapshots(ctx, r.AWS)
	if err != nil {
		return EC2Snapshot{}, err
	}
	var replaced []EC2Snapshot
	for _, s := range existing {
		if s.Name == name {
			replaced = append(replaced, s)
		}
	}
	if len(replaced) > 0 && !o.Force {
		return EC2Snapshot{}, fmt.Errorf("snapshot %q already exists (use --force to overwrite)", name)
	}
	i, err := e.only(ctx, r.AWS)
	if err != nil {
		return EC2Snapshot{}, err
	}
	volume := i.rootVolume()
	if volume == "" {
		return EC2Snapshot{}, fmt.Errorf("%s has no root volume to take a snapshot of", i.InstanceID)
	}
	running := i.State.Name == "running" || i.State.Name == "pending"
	if err := e.stop(ctx, r, i); err != nil {
		return EC2Snapshot{}, err
	}
	tags := append(e.instanceTags(), ec2Tag{snapshotTag, name})
	if o.Note != "" {
		tags = append(tags, ec2Tag{noteTag, o.Note})
	}
	spec, _ := json.Marshal([]tagSpec{{"snapshot", tags}})
	out, err := r.AWS.Run(ctx, e.awsArgs("ec2", "create-snapshot", "--volume-id", volume,
		"--description", "ldap-cronin lab "+e.Name+" ("+e.Domain+"): "+name, "--tag-specifications", string(spec),
		"--query", "SnapshotId", "--output", "text")...)
	if err != nil {
		return EC2Snapshot{}, err
	}
	id := strings.TrimSpace(out)
	fmt.Fprintf(r.Log, "==> Snapshot %s (%s) of %s: it completes in the background (lab snapshots --config shows its state)\n", name, id, volume)
	for _, s := range replaced {
		if err := e.deleteSnapshot(ctx, r, s); err != nil {
			return EC2Snapshot{}, err
		}
	}
	if running {
		if err := e.start(ctx, r, i.InstanceID); err != nil {
			return EC2Snapshot{}, err
		}
		if err := e.waitReady(ctx, r, i.InstanceID); err != nil {
			return EC2Snapshot{}, err
		}
	}
	return EC2Snapshot{ID: id, Name: name, Note: o.Note, State: "pending"}, nil
}

func (e EC2Lab) deleteSnapshot(ctx context.Context, r EC2Run, s EC2Snapshot) error {
	if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "delete-snapshot", "--snapshot-id", s.ID)...); err != nil {
		return err
	}
	fmt.Fprintf(r.Log, "==> Deleted the snapshot %s (%s)\n", s.Name, s.ID)
	return nil
}

// find is the newest snapshot of the name; without a name, the list to choose from is in the error.
func (e EC2Lab) find(ctx context.Context, aws AWS, name string) (EC2Snapshot, error) {
	list, err := e.Snapshots(ctx, aws)
	if err != nil {
		return EC2Snapshot{}, err
	}
	if len(list) == 0 {
		return EC2Snapshot{}, fmt.Errorf("the lab %s has no snapshots; take one with lab snapshot --config", e.Name)
	}
	if name == "" {
		return EC2Snapshot{}, fmt.Errorf("specify a snapshot name. Candidates:\n%s", FormatEC2Snapshots(list))
	}
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Name == name {
			return list[i], nil
		}
	}
	return EC2Snapshot{}, fmt.Errorf("the lab %s has no snapshot %q. Candidates:\n%s", e.Name, name, FormatEC2Snapshots(list))
}

// SnapshotRemove deletes the lab's snapshots of the name.
func (e EC2Lab) SnapshotRemove(ctx context.Context, r EC2Run, name string) error {
	list, err := e.Snapshots(ctx, r.AWS)
	if err != nil {
		return err
	}
	n := 0
	for _, s := range list {
		if s.Name == name {
			if err := e.deleteSnapshot(ctx, r, s); err != nil {
				return err
			}
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("the lab %s has no snapshot %q", e.Name, name)
	}
	return nil
}

// RemoveSnapshots deletes all the lab's snapshots, after confirm says yes to them (lab reset --snapshots).
func (e EC2Lab) RemoveSnapshots(ctx context.Context, r EC2Run, confirm func(string) bool) error {
	list, err := e.Snapshots(ctx, r.AWS)
	if err != nil || len(list) == 0 {
		return err
	}
	var names []string
	for _, s := range list {
		names = append(names, s.Name+" ("+s.ID+")")
	}
	if confirm != nil && !confirm(fmt.Sprintf("Delete the snapshots of the lab %s: %s? [y/N]: ", e.Name, strings.Join(names, ", "))) {
		return errors.New("aborted: no snapshot was deleted")
	}
	for _, s := range list {
		if err := e.deleteSnapshot(ctx, r, s); err != nil {
			return err
		}
	}
	return nil
}

// Restore returns the lab to a snapshot: the instance's root volume is replaced by one made from it (the instance
// restarts; the replaced volume is deleted), then the domain controller is waited for, as lab up does. A stopped
// instance is started first, as EC2 replaces the root volume of a running one only. It returns the instance.
func (e EC2Lab) Restore(ctx context.Context, r EC2Run, name string) (string, error) {
	s, err := e.find(ctx, r.AWS, name)
	if err != nil {
		return "", err
	}
	i, err := e.only(ctx, r.AWS)
	if err != nil {
		return "", err
	}
	id := i.InstanceID
	switch i.State.Name {
	case "stopping":
		if err := e.stop(ctx, r, i); err != nil {
			return id, err
		}
		fallthrough
	case "stopped":
		if err := e.start(ctx, r, id); err != nil {
			return id, err
		}
	}
	if s.State != "completed" {
		fmt.Fprintf(r.Log, "==> Waiting for the snapshot %s (%s, %s) to complete\n", s.Name, s.ID, s.State)
		if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "wait", "snapshot-completed", "--snapshot-ids", s.ID)...); err != nil {
			return id, err
		}
	}
	fmt.Fprintf(r.Log, "==> Replacing the root volume of %s by the snapshot %s (%s); the instance restarts\n", id, s.Name, s.ID)
	out, err := r.AWS.Run(ctx, e.awsArgs("ec2", "create-replace-root-volume-task", "--instance-id", id, "--snapshot-id", s.ID,
		"--delete-replaced-root-volume", "--query", "ReplaceRootVolumeTask.ReplaceRootVolumeTaskId", "--output", "text")...)
	if err != nil {
		return id, err
	}
	if err := e.waitReplaced(ctx, r, strings.TrimSpace(out)); err != nil {
		return id, err
	}
	// The new volume is the lab's too: its tags, as lab up gives the first (an account's policy may want them).
	i, err = e.only(ctx, r.AWS)
	if err != nil {
		return id, err
	}
	if volume := i.rootVolume(); volume != "" {
		tags, _ := json.Marshal(e.instanceTags())
		if _, err := r.AWS.Run(ctx, e.awsArgs("ec2", "create-tags", "--resources", volume, "--tags", string(tags))...); err != nil {
			return id, err
		}
	}
	return id, e.waitReady(ctx, r, id)
}

// waitReplaced waits for a replace root volume task to succeed, as long as the domain controller's wait.
func (e EC2Lab) waitReplaced(ctx context.Context, r EC2Run, task string) error {
	now, sleep, timeout := r.clock()
	deadline := now().Add(timeout)
	for {
		out, err := r.AWS.Run(ctx, e.awsArgs("ec2", "describe-replace-root-volume-tasks", "--replace-root-volume-task-ids", task,
			"--query", "ReplaceRootVolumeTasks[0].TaskState", "--output", "text")...)
		if err != nil {
			return err
		}
		switch state := strings.TrimSpace(out); state {
		case "succeeded":
			fmt.Fprintf(r.Log, "==> The root volume is replaced (%s)\n", task)
			return nil
		case "failing", "failed", "failed-detached":
			return fmt.Errorf("the replace root volume task %s %s: aws ec2 describe-replace-root-volume-tasks says more", task, state)
		}
		if now().After(deadline) {
			return fmt.Errorf("the replace root volume task %s did not succeed within %s", task, timeout)
		}
		sleep(readyInterval)
	}
}
