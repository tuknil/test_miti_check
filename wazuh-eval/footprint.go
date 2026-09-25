package main

// footprint.go expands a command into the LIST of Wazuh telemetry events it would
// realistically generate — not just its own execve, but the child processes it
// spawns and the file-integrity (FIM) events its side effects produce.
//
// This is necessarily a heuristic model: the command is not executed, so the
// footprint is derived from a per-command profile table (commandProfiles) plus
// generic rules (shell pipelines expand to sh -c + each stage; file-reading tools
// emit an audit file-access event). It is meant to approximate what a Wazuh agent
// with auditd (execve + audit watches) and FIM enabled would report, and to feed
// the evaluator. Unknown commands still yield their own execve event.

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// TelemetryEvent is one synthesized Wazuh event with its source and a summary.
type TelemetryEvent struct {
	Source  string          `json:"source"`  // auditd-execve | auditd-file-access | syscheck-fim
	Summary string          `json:"summary"` // human description
	Event   json.RawMessage `json:"event"`   // the decoded Wazuh event
}

const (
	sourceExecve     = "auditd-execve"
	sourceFileAccess = "auditd-file-access"
	sourceFIM        = "syscheck-fim"
)

// CommandTelemetryFootprint returns every telemetry event a command would
// generate, in causal order (parent process first, then children, then files).
func CommandTelemetryFootprint(in CommandInput) ([]TelemetryEvent, error) {
	argv, exe := resolveArgv(in)
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command provided (set Command or Argv)")
	}
	seq := &footprintSeq{in: in, ts: eventTime(in), pid: 1000, ppid: 999, serial: baseSerial(in)}
	var out []TelemetryEvent

	// The command's own execve.
	out = append(out, seq.execve(argv, exe, fmt.Sprintf("process executed: %s", strings.Join(argv, " "))))

	// A shell wrapper (sh -c "<cmd>") spawns each pipeline stage as a child.
	if isShell(path.Base(exe)) && len(argv) >= 3 && argv[1] == "-c" {
		for _, stage := range splitPipeline(argv[2]) {
			stageArgv := shellSplit(stage)
			if len(stageArgv) == 0 {
				continue
			}
			stageExe := resolveExe(stageArgv[0])
			out = append(out, seq.child(stageArgv, stageExe, "child process (pipeline stage)"))
			out = append(out, expandProfile(seq, stageArgv, stageExe)...)
		}
		return out, nil
	}

	out = append(out, expandProfile(seq, argv, exe)...)
	return out, nil
}

// expandProfile appends the child-process and file events a command's profile
// (and the generic file-reader rule) declare.
func expandProfile(seq *footprintSeq, argv []string, exe string) []TelemetryEvent {
	var out []TelemetryEvent
	base := path.Base(exe)
	args := argv[1:]

	if prof, ok := commandProfiles[base]; ok {
		children, files := prof(args)
		for _, ch := range children {
			chExe := resolveExe(ch[0])
			out = append(out, seq.child(ch, chExe, "child process spawned by "+base))
			// One level of grandchildren from a profiled child (e.g. adduser→useradd).
			if gp, ok := commandProfiles[path.Base(chExe)]; ok {
				gchildren, gfiles := gp(ch[1:])
				for _, gch := range gchildren {
					out = append(out, seq.child(gch, resolveExe(gch[0]), "child process spawned by "+path.Base(chExe)))
				}
				files = append(files, gfiles...)
			}
		}
		for _, f := range dedupeFiles(files) {
			out = append(out, seq.fim(f.path, f.event))
		}
	}

	// Generic: a file-reading tool touching a path emits a file-access event.
	if isFileReader(base) {
		for _, a := range args {
			if looksLikePath(a) {
				out = append(out, seq.fileAccess(argv, exe, a))
			}
		}
	}
	return out
}

// ---- per-command profiles --------------------------------------------------

type fileEffect struct{ path, event string } // event: added | modified | deleted

// profileFn maps a command's args to the child processes it spawns and the files
// it changes. args is argv[1:].
type profileFn func(args []string) (children [][]string, files []fileEffect)

// lastArg returns the last non-flag argument (the typical subject: a username,
// group, path), or "" if none.
func lastArg(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !strings.HasPrefix(args[i], "-") {
			return args[i]
		}
	}
	return ""
}

var accountFiles = []fileEffect{
	{"/etc/passwd", "modified"}, {"/etc/shadow", "modified"},
	{"/etc/group", "modified"}, {"/etc/gshadow", "modified"},
}

var commandProfiles = map[string]profileFn{
	// Debian adduser is a Perl wrapper that calls useradd (and passwd).
	"adduser": func(args []string) ([][]string, []fileEffect) {
		u := lastArg(args)
		return [][]string{{"/usr/sbin/useradd", "-m", "-d", "/home/" + u, u}},
			userCreateFiles(u)
	},
	"useradd": func(args []string) ([][]string, []fileEffect) {
		return nil, userCreateFiles(lastArg(args))
	},
	"deluser": func(args []string) ([][]string, []fileEffect) {
		return [][]string{{"/usr/sbin/userdel", lastArg(args)}}, accountFiles
	},
	"userdel": func(args []string) ([][]string, []fileEffect) {
		return nil, accountFiles
	},
	"usermod": func(args []string) ([][]string, []fileEffect) { return nil, accountFiles },
	"passwd": func(args []string) ([][]string, []fileEffect) {
		return nil, []fileEffect{{"/etc/shadow", "modified"}}
	},
	"groupadd": func(args []string) ([][]string, []fileEffect) {
		return nil, []fileEffect{{"/etc/group", "modified"}, {"/etc/gshadow", "modified"}}
	},
	"groupdel": func(args []string) ([][]string, []fileEffect) {
		return nil, []fileEffect{{"/etc/group", "modified"}, {"/etc/gshadow", "modified"}}
	},
	"ssh-keygen": func(args []string) ([][]string, []fileEffect) {
		out := keyPath(args)
		return nil, []fileEffect{{out, "added"}, {out + ".pub", "added"}}
	},
	"crontab": func(args []string) ([][]string, []fileEffect) {
		return nil, []fileEffect{{"/var/spool/cron/crontabs/root", "modified"}}
	},
	"chmod": func(args []string) ([][]string, []fileEffect) { return nil, fimForPaths(args, "modified") },
	"chown": func(args []string) ([][]string, []fileEffect) { return nil, fimForPaths(args, "modified") },
	"rm":    func(args []string) ([][]string, []fileEffect) { return nil, fimForPaths(args, "deleted") },
	"touch": func(args []string) ([][]string, []fileEffect) { return nil, fimForPaths(args, "added") },
	"wget":  func(args []string) ([][]string, []fileEffect) { return nil, downloadFile(args) },
	"curl":  func(args []string) ([][]string, []fileEffect) { return nil, downloadFile(args) },
}

func userCreateFiles(u string) []fileEffect {
	files := append([]fileEffect(nil), accountFiles...)
	if u != "" {
		files = append(files,
			fileEffect{"/home/" + u, "added"},
			fileEffect{"/home/" + u + "/.bashrc", "added"},
			fileEffect{"/home/" + u + "/.profile", "added"},
			fileEffect{"/var/mail/" + u, "added"})
	}
	return files
}

func keyPath(args []string) string {
	for i, a := range args {
		if a == "-f" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return "/root/.ssh/id_rsa"
}

func fimForPaths(args []string, event string) []fileEffect {
	var files []fileEffect
	for _, a := range args {
		if looksLikePath(a) && !strings.HasPrefix(a, "-") {
			files = append(files, fileEffect{a, event})
		}
	}
	return files
}

func downloadFile(args []string) []fileEffect {
	for i, a := range args {
		if (a == "-O" || a == "-o" || a == "--output") && i+1 < len(args) {
			return []fileEffect{{args[i+1], "added"}}
		}
	}
	return nil
}

// ---- event sequencing & builders -------------------------------------------

type footprintSeq struct {
	in     CommandInput
	ts     time.Time
	pid    int
	ppid   int
	serial int64
}

func (s *footprintSeq) next() CommandInput {
	in := s.in
	in.Timestamp = s.ts
	in.PID = strconv.Itoa(s.pid)
	in.PPID = strconv.Itoa(s.ppid)
	in.EventSerial = s.serial
	s.ts = s.ts.Add(time.Millisecond)
	s.pid++
	s.serial++
	return in
}

func (s *footprintSeq) execve(argv []string, exe, summary string) TelemetryEvent {
	in := s.next()
	in.Argv, in.Exe = argv, exe
	ev, _ := buildAuditEvent(in)
	return TelemetryEvent{Source: sourceExecve, Summary: summary, Event: mustJSONRaw(ev)}
}

func (s *footprintSeq) child(argv []string, exe, summary string) TelemetryEvent {
	// Children share the original command as their parent.
	saved := s.ppid
	s.ppid = 1000
	ev := s.execve(argv, exe, summary)
	s.ppid = saved
	return ev
}

func (s *footprintSeq) fim(filePath, event string) TelemetryEvent {
	in := s.next()
	ev := buildSyscheckEvent(in, filePath, event)
	return TelemetryEvent{Source: sourceFIM, Summary: fmt.Sprintf("file %s: %s", event, filePath), Event: mustJSONRaw(ev)}
}

func (s *footprintSeq) fileAccess(argv []string, exe, filePath string) TelemetryEvent {
	in := s.next()
	in.Argv, in.Exe = argv, exe
	ev := buildFileAccessEvent(in, filePath)
	return TelemetryEvent{Source: sourceFileAccess, Summary: "file read: " + filePath, Event: mustJSONRaw(ev)}
}

// buildFileAccessEvent is an auditd openat() event with data.audit.file.name —
// what an audit watch on a file emits when it is opened.
func buildFileAccessEvent(in CommandInput, filePath string) map[string]any {
	in.Syscall = "257" // openat
	in.Key = firstNonEmpty(in.Key, "audit-wazuh-r")
	ev, _ := buildAuditEvent(in)
	audit := ev["data"].(map[string]any)["audit"].(map[string]any)
	audit["file"] = map[string]any{"name": filePath}
	audit["items"] = "1"
	id := auditMsgID(ev)
	ev["full_log"] = fmt.Sprintf("%s\ntype=PATH msg=audit(%s): item=0 name=%q nametype=NORMAL",
		firstLine(ev["full_log"]), id, filePath)
	return ev
}

// buildSyscheckEvent is a Wazuh FIM event for a created/modified/deleted file.
func buildSyscheckEvent(in CommandInput, filePath, event string) map[string]any {
	ts := eventTime(in).UTC()
	host := firstNonEmpty(in.Host, "linux-host")
	uid := firstNonEmpty(in.UID, uidForUser(in.User))
	decoder := map[string]string{
		"added":    "syscheck_new_entry",
		"modified": "syscheck_integrity_changed",
		"deleted":  "syscheck_deleted",
	}[event]
	syscheck := map[string]any{
		"path":  filePath,
		"mode":  "realtime",
		"event": event,
		"uid":   uid,
		"gid":   "0",
		"uname": firstNonEmpty(in.User, "root"),
		"gname": "root",
	}
	full := fmt.Sprintf("File '%s' %s\nMode: realtime", filePath, event)
	if event != "deleted" {
		full += "\nChanged attributes: size,mtime,inode,md5,sha1,sha256"
	}
	return map[string]any{
		"timestamp": ts.Format("2006-01-02T15:04:05.000Z0700"),
		"agent":     map[string]any{"id": "001", "name": host},
		"manager":   map[string]any{"name": "wazuh-manager"},
		"decoder":   map[string]any{"name": decoder},
		"location":  "syscheck",
		"syscheck":  syscheck,
		"full_log":  full,
	}
}

// ---- helpers ---------------------------------------------------------------

func isShell(base string) bool {
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh":
		return true
	}
	return false
}

func isFileReader(base string) bool {
	switch base {
	case "cat", "less", "more", "head", "tail", "grep", "egrep", "awk", "sed",
		"vi", "vim", "nano", "strings", "od", "xxd", "cp", "scp":
		return true
	}
	return false
}

func looksLikePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") || strings.HasPrefix(s, "~/")
}

// splitPipeline splits a shell command on |, &&, ||, ; into stage commands.
func splitPipeline(cmd string) []string {
	fields := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == '|' || r == ';' || r == '&'
	})
	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func dedupeFiles(files []fileEffect) []fileEffect {
	seen := map[string]bool{}
	var out []fileEffect
	for _, f := range files {
		k := f.path + "\x00" + f.event
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func eventTime(in CommandInput) time.Time {
	if in.Timestamp.IsZero() {
		return time.Now()
	}
	return in.Timestamp
}

func baseSerial(in CommandInput) int64 {
	if in.EventSerial != 0 {
		return in.EventSerial
	}
	return eventTime(in).UnixNano() / int64(time.Millisecond) % 1000000
}

func mustJSONRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func firstLine(v any) string {
	s, _ := v.(string)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func auditMsgID(ev map[string]any) string {
	full := firstLine(ev["full_log"])
	const marker = "msg=audit("
	i := strings.Index(full, marker)
	if i < 0 {
		return ""
	}
	rest := full[i+len(marker):]
	if j := strings.IndexByte(rest, ')'); j >= 0 {
		return rest[:j]
	}
	return ""
}
