package udsmsg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProcStart reads field 22 of /proc/<pid>/stat, the process start time in
// clock ticks since boot. Together with the pid it identifies a process
// across pid reuse.
func ProcStart(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	// The comm field (2) is parenthesised and may itself contain spaces and
	// parentheses, so fields are counted from the last ')'.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(b[i+1:]))
	// fields[0] is field 3 (state), so field 22 is index 19.
	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return "", fmt.Errorf("/proc/%d/stat has %d fields after comm, want > %d", pid, len(fields), startTimeIdx)
	}
	return fields[startTimeIdx], nil
}

// MachineID returns the host's machine id, the middle component of a pid
// domain.
func MachineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(p)
		if err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("no machine id found")
}

// PIDDomain returns the namespace-qualified pid space of a process, e.g.
// "linux:<machine-id>:pid:[4026532231]". It exists so an identical pid in a
// different namespace cannot impersonate a session.
func PIDDomain(pid int) (string, error) {
	id, err := MachineID()
	if err != nil {
		return "", err
	}
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("linux:%s:%s", id, ns), nil
}

// Alive reports whether pid is running and started at procStart. An empty
// procStart checks only that the pid exists.
func Alive(pid int, procStart string) bool {
	got, err := ProcStart(pid)
	if err != nil {
		return false
	}
	return procStart == "" || got == procStart
}

// bypassFlags are the launch flags that put a session in bypass mode.
var bypassFlags = []string{"--dangerously-skip-permissions", "bypassPermissions"}

// DetectParentMode reads the permission posture of the session that spawned
// this process, from the flags it was launched with.
//
// from_mode is a CLAIM the receiver acts on and cannot check — "a label, not
// an identity proof" — so it must never be invented. This derives it instead:
// the parent's pid comes from the socket it exported, and its command line
// says whether it was started with permissions skipped. An error means the
// posture could not be established, and the caller should then assert NOTHING
// and accept the hold rather than guess, because the only guess that helps is
// the one that launders a user's decision.
//
// Two limits, both in the safe direction. It reads the LAUNCH flags, so a
// mode changed at runtime is invisible — a session that started prompting and
// switched to bypass is reported as prompting, which mismatches and holds
// rather than slipping through. And it needs /proc, so it works where these
// sessions actually run and errors elsewhere instead of assuming.
func DetectParentMode() (Mode, error) {
	sock := os.Getenv(EnvMessagingSocket)
	if sock == "" {
		return "", fmt.Errorf("no parent session: %s is unset", EnvMessagingSocket)
	}
	pid, ok := PIDFromSocketName(filepath.Base(sock))
	if !ok {
		return "", fmt.Errorf("cannot read a pid from the parent socket name %q", filepath.Base(sock))
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", fmt.Errorf("cannot read the parent's command line, so its posture is unknown: %w", err)
	}
	return modeFromCmdline(strings.ReplaceAll(string(raw), "\x00", " ")), nil
}

// modeFromCmdline classifies a launch command line. Anything that is not
// recognisably permission-skipping reads as prompting — the claim that gets a
// message held rather than through.
func modeFromCmdline(cmdline string) Mode {
	for _, f := range bypassFlags {
		if strings.Contains(cmdline, f) {
			return ModeBypass
		}
	}
	return ModePrompting
}
