package main

// telemetry.go synthesizes Wazuh telemetry for a command executed on a Linux
// host or container.
//
// On Linux, command execution reaches Wazuh through the Linux Audit subsystem
// (auditd): the kernel emits an execve() audit event that Wazuh's auditd decoder
// turns into decoded `data.audit.*` fields (exe, comm, execve.a0..aN, cwd, uid,
// pid, ...). CommandToWazuhTelemetry builds that decoded event — both the
// structured fields and the raw multi-line `full_log` in auditd's own format —
// so the result matches what a real Wazuh agent would report, and can be fed
// straight into the rule evaluator (LoadEvent → Evaluate).
//
// Scope: one execve event per call. A shell pipeline or builtin (contains
// |, &, ;, >, <, `, $()) is modeled the way the kernel actually records it — as
// a single `/bin/sh -c "<command>"` execve — since that is the first audit event
// the shell produces. Pass Argv explicitly to synthesize a bare execve instead.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// CommandInput describes a single command execution to synthesize telemetry for.
// Only Command (or Argv) is required; everything else has a sensible default.
type CommandInput struct {
	Command     string    // full command line; parsed into argv when Argv is empty
	Argv        []string  // explicit argv (wins over Command; skips shell wrapping)
	Exe         string    // executable path; defaults to argv[0]
	Cwd         string    // working directory (default "/root" for uid 0, else "/home")
	Host        string    // agent/host name (default "linux-host")
	User        string    // username (best-effort uid mapping when UID is empty)
	UID         string    // numeric uid (wins over User)
	GID         string    // numeric gid (default same as uid)
	AUID        string    // login uid (default same as uid)
	PID         string    // process id (default "1000")
	PPID        string    // parent process id (default "999")
	TTY         string    // controlling tty (default "pts0")
	SessionID   string    // audit session id (default "1")
	Key         string    // audit rule key (default "audit-wazuh-c")
	Arch        string    // audit arch (default "c000003e", x86_64)
	Syscall     string    // syscall number (default "59", execve on x86_64)
	Success     *bool     // syscall success (default true)
	Exit        string    // syscall exit code (default "0")
	ContainerID string    // optional container id (added as data.audit.container_id)
	Timestamp   time.Time // event time (default now)
	EventSerial int64     // audit event serial in msg=audit(ts:serial) (default derived)
}

// CommandToWazuhTelemetry returns the decoded Wazuh auditd execve event as
// indented JSON. The output parses with LoadEvent and can be evaluated by rules.
func CommandToWazuhTelemetry(in CommandInput) ([]byte, error) {
	ev, err := buildAuditEvent(in)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(ev, "", "  ")
}

// CommandToWazuhEvent is the convenience form that returns a ready-to-evaluate
// *Event (command → telemetry → Evaluate in one step).
func CommandToWazuhEvent(in CommandInput) (*Event, error) {
	data, err := CommandToWazuhTelemetry(in)
	if err != nil {
		return nil, err
	}
	return LoadEvent(data), nil
}

func buildAuditEvent(in CommandInput) (map[string]any, error) {
	argv, exe := resolveArgv(in)
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command provided (set Command or Argv)")
	}
	comm := path.Base(exe)

	uid := firstNonEmpty(in.UID, uidForUser(in.User))
	gid := firstNonEmpty(in.GID, uid)
	auid := firstNonEmpty(in.AUID, uid)
	pid := firstNonEmpty(in.PID, "1000")
	ppid := firstNonEmpty(in.PPID, "999")
	tty := firstNonEmpty(in.TTY, "pts0")
	ses := firstNonEmpty(in.SessionID, "1")
	key := firstNonEmpty(in.Key, "audit-wazuh-c")
	arch := firstNonEmpty(in.Arch, "c000003e")
	syscall := firstNonEmpty(in.Syscall, "59")
	exit := firstNonEmpty(in.Exit, "0")
	cwd := firstNonEmpty(in.Cwd, defaultCwd(uid))
	host := firstNonEmpty(in.Host, "linux-host")
	success := "yes"
	if in.Success != nil && !*in.Success {
		success = "no"
	}

	ts := in.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	ts = ts.UTC()
	serial := in.EventSerial
	if serial == 0 {
		serial = ts.UnixNano() / int64(time.Millisecond) % 1000000
	}
	auditID := fmt.Sprintf("%d.%03d:%d", ts.Unix(), ts.Nanosecond()/int(time.Millisecond), serial)

	// Decoded execve args: audit.execve.a0..aN plus argc.
	execve := map[string]any{"argc": strconv.Itoa(len(argv))}
	for i, a := range argv {
		execve["a"+strconv.Itoa(i)] = a
	}

	audit := map[string]any{
		"type":    "EXECVE",
		"arch":    arch,
		"syscall": syscall,
		"success": success,
		"exit":    exit,
		"ppid":    ppid,
		"pid":     pid,
		"auid":    auid,
		"uid":     uid,
		"gid":     gid,
		"euid":    uid,
		"suid":    uid,
		"fsuid":   uid,
		"egid":    gid,
		"sgid":    gid,
		"fsgid":   gid,
		"tty":     tty,
		"ses":     ses,
		"comm":    comm,
		"exe":     exe,
		"key":     key,
		"cwd":     cwd,
		"execve":  execve,
	}
	if strings.TrimSpace(in.ContainerID) != "" {
		audit["container_id"] = in.ContainerID
	}

	fullLog := buildAuditFullLog(auditID, argv, exe, comm, cwd, arch, syscall, success, exit,
		ppid, pid, auid, uid, gid, tty, ses, key)

	event := map[string]any{
		"timestamp": ts.Format("2006-01-02T15:04:05.000Z0700"),
		"agent":     map[string]any{"id": "001", "name": host},
		"manager":   map[string]any{"name": "wazuh-manager"},
		"predecoder": map[string]any{
			"timestamp":    ts.Format("Jan 02 15:04:05"),
			"hostname":     host,
			"program_name": "",
		},
		"decoder":  map[string]any{"name": "auditd"},
		"location": "/var/log/audit/audit.log",
		"data":     map[string]any{"audit": audit},
		"full_log": fullLog,
	}
	return event, nil
}

// resolveArgv returns the argv and executable path, wrapping shell command lines
// in `/bin/sh -c` the way the kernel records them.
func resolveArgv(in CommandInput) (argv []string, exe string) {
	switch {
	case len(in.Argv) > 0:
		argv = append([]string(nil), in.Argv...)
	case looksLikeShell(in.Command):
		argv = []string{"/bin/sh", "-c", strings.TrimSpace(in.Command)}
	default:
		argv = shellSplit(in.Command)
	}
	if len(argv) == 0 {
		return nil, ""
	}
	exe = in.Exe
	if exe == "" {
		exe = resolveExe(argv[0])
	}
	return argv, exe
}

// looksLikeShell reports whether a command uses shell syntax that the kernel
// would record as an `sh -c` execve rather than a bare program execve.
func looksLikeShell(cmd string) bool {
	return strings.ContainsAny(cmd, "|&;<>`") || strings.Contains(cmd, "$(") || strings.Contains(cmd, "&&") || strings.Contains(cmd, "||")
}

// resolveExe turns a bare program name into a plausible absolute path, mirroring
// PATH resolution enough for telemetry (already-absolute paths are kept).
func resolveExe(arg0 string) string {
	if strings.HasPrefix(arg0, "/") || strings.HasPrefix(arg0, "./") || strings.HasPrefix(arg0, "../") {
		return arg0
	}
	return "/usr/bin/" + arg0
}

func uidForUser(user string) string {
	switch strings.ToLower(strings.TrimSpace(user)) {
	case "", "root":
		return "0"
	default:
		return "1000"
	}
}

func defaultCwd(uid string) string {
	if uid == "0" {
		return "/root"
	}
	return "/home/user"
}

// buildAuditFullLog assembles the raw multi-record auditd log for one execve
// event: SYSCALL, EXECVE, CWD, PROCTITLE — as written to /var/log/audit/audit.log.
func buildAuditFullLog(auditID string, argv []string, exe, comm, cwd, arch, syscall, success, exit,
	ppid, pid, auid, uid, gid, tty, ses, key string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "type=SYSCALL msg=audit(%s): arch=%s syscall=%s success=%s exit=%s a0=0 a1=0 a2=0 a3=0 items=%d ppid=%s pid=%s auid=%s uid=%s gid=%s euid=%s suid=%s fsuid=%s egid=%s sgid=%s fsgid=%s tty=%s ses=%s comm=%q exe=%q key=%q",
		auditID, arch, syscall, success, exit, len(argv), ppid, pid, auid, uid, gid, uid, uid, uid, gid, gid, gid, tty, ses, comm, exe, key)
	b.WriteByte('\n')

	fmt.Fprintf(&b, "type=EXECVE msg=audit(%s): argc=%d", auditID, len(argv))
	for i, a := range argv {
		fmt.Fprintf(&b, " a%d=%s", i, quoteAuditArg(a))
	}
	b.WriteByte('\n')

	fmt.Fprintf(&b, "type=CWD msg=audit(%s): cwd=%q", auditID, cwd)
	b.WriteByte('\n')

	fmt.Fprintf(&b, "type=PROCTITLE msg=audit(%s): proctitle=%s", auditID, proctitleHex(argv))
	return b.String()
}

// quoteAuditArg mirrors auditd's field encoding: args with no space/special
// chars are quoted; args with spaces are hex-encoded (as real auditd does).
func quoteAuditArg(a string) string {
	if a != "" && !strings.ContainsAny(a, " \t\n\"'\\") {
		return strconv.Quote(a)
	}
	return strings.ToUpper(hex.EncodeToString([]byte(a)))
}

// proctitleHex is the NUL-joined argv, hex-encoded — auditd's PROCTITLE format.
func proctitleHex(argv []string) string {
	return strings.ToUpper(hex.EncodeToString([]byte(strings.Join(argv, "\x00"))))
}

// shellSplit splits a command line into argv, honoring single/double quotes and
// backslash escapes (a small POSIX-ish tokenizer; not a full shell parser).
func shellSplit(s string) []string {
	var args []string
	var cur strings.Builder
	inArg := false
	quote := byte(0) // 0, '\'' or '"'
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			} else if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inArg = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inArg = true
		case c == ' ' || c == '\t':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args
}
