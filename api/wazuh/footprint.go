package wazuh

// footprint.go expands a command into the LIST of Wazuh telemetry events it would
// realistically generate — not just its own execve, but the child processes it
// spawns and the file-integrity (FIM) events its side effects produce.
//
// This is necessarily a heuristic model: the command is not executed, so the
// process tree and file effects are inferred. The command line is decomposed by
// a pragmatic shell grammar (decomposeShell) into simple commands — one execve
// each — and a per-command profile table (commandProfiles) adds the child
// processes and file-integrity (FIM) events known side effects produce. It
// approximates what a Wazuh agent with auditd (execve + audit watches) and FIM
// enabled would report, and feeds the evaluator. Any input is handled without
// error; an unrecognized program still yields its own execve event.

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

// CommandTelemetryFootprint returns every telemetry event a command line would
// generate, in causal order. It handles an arbitrary Linux shell command line —
// pipelines, sequences (`;`, `&&`, `||`, `&`), redirections, command
// substitution, subshells, `VAR=val` prefixes, wrapper programs (sudo/env/
// nohup/timeout/...), and builtins — decomposing it into the process executions
// (auditd execve) and file effects (FIM, file-access) it produces. It never
// errors and never panics: any input yields a valid list, and an unrecognized
// program still produces its own execve.
func CommandTelemetryFootprint(in CommandInput) ([]TelemetryEvent, error) {
	seq := &footprintSeq{in: in, ts: eventTime(in), pid: 1001, shellPID: 1000, serial: baseSerial(in)}

	var cmds []simpleCommand
	if len(in.Argv) > 0 {
		cmds = []simpleCommand{parseArgv(in.Argv)} // explicit argv: one command, no shell parsing
	} else {
		cmds = decomposeShell(in.Command, 0)
	}

	var out []TelemetryEvent
	for _, sc := range cmds {
		out = append(out, emitCommand(seq, sc)...)
	}
	if len(out) == 0 {
		// Pure builtins / assignments / empty input still describe a shell action;
		// emit the interactive shell's own execve so the list is never empty.
		out = append(out, seq.mainExecve([]string{"/bin/bash"}, "/bin/bash", in.UID,
			"shell command (no external process executed)"))
	}
	return out, nil
}

// emitCommand turns one decomposed simple command into its telemetry: the file
// reads it performs, its execve (unless a builtin), its profile-driven children
// and file effects, and the files it writes via redirection.
func emitCommand(seq *footprintSeq, sc simpleCommand) []TelemetryEvent {
	var out []TelemetryEvent
	uid := sc.uid

	// Input redirections / read targets happen as the process starts.
	for _, r := range sc.reads {
		out = append(out, seq.fileAccess(sc.argv, resolveExeSafe(sc.argv), r, uid))
	}

	if !sc.builtin && len(sc.argv) > 0 {
		exe := resolveExeSafe(sc.argv)
		out = append(out, seq.mainExecve(sc.argv, exe, uid,
			"process executed: "+strings.Join(sc.argv, " ")))
		out = append(out, expandProfile(seq, sc.argv, exe, uid)...)
		// Generic: a file-reading tool touching a path reads it.
		if isFileReader(path.Base(exe)) {
			for _, a := range sc.argv[1:] {
				if looksLikePath(a) {
					out = append(out, seq.fileAccess(sc.argv, exe, a, uid))
				}
			}
		}
	}

	// Output redirections (>, >>, 2>, &>) create/modify their target files.
	for _, f := range dedupeFiles(sc.files) {
		out = append(out, seq.fim(f.path, f.event, uid))
	}
	return out
}

// expandProfile appends the child-process and file events a command's profile
// declares (one level of grandchildren, e.g. adduser→useradd).
func expandProfile(seq *footprintSeq, argv []string, exe, uid string) []TelemetryEvent {
	var out []TelemetryEvent
	base := path.Base(exe)
	prof, ok := commandProfiles[base]
	if !ok {
		return nil
	}
	children, files := prof(argv[1:])
	for _, ch := range children {
		chExe := resolveExe(ch[0])
		out = append(out, seq.child(ch, chExe, uid, "child process spawned by "+base))
		if gp, ok := commandProfiles[path.Base(chExe)]; ok {
			gchildren, gfiles := gp(ch[1:])
			for _, gch := range gchildren {
				out = append(out, seq.child(gch, resolveExe(gch[0]), uid, "child process spawned by "+path.Base(chExe)))
			}
			files = append(files, gfiles...)
		}
	}
	for _, f := range dedupeFiles(files) {
		out = append(out, seq.fim(f.path, f.event, uid))
	}
	return out
}

// ---- shell decomposition ---------------------------------------------------

// simpleCommand is one command in a pipeline/sequence, after redirections and
// wrappers are resolved.
type simpleCommand struct {
	argv    []string     // resolved program + args (wrappers/assignments stripped)
	files   []fileEffect // output-redirection targets
	reads   []string     // input-redirection / read targets
	builtin bool         // a shell builtin (no execve)
	uid     string       // effective uid ("0" under sudo; "" = default)
}

// decomposeShell parses a shell command line into simple commands. It is a
// pragmatic shell grammar (not a full bash parser): it tolerates any input and
// degrades gracefully. depth guards against pathological substitution nesting.
func decomposeShell(line string, depth int) []simpleCommand {
	if depth > 8 || strings.TrimSpace(line) == "" {
		return nil
	}
	toks := shellTokenize(line)
	var cmds []simpleCommand
	var cur []shTok
	flush := func() {
		if len(cur) > 0 {
			cmds = append(cmds, parseSimple(cur, depth)...)
			cur = nil
		}
	}
	for _, t := range toks {
		if t.op {
			switch t.val {
			case "|", "||", "&&", ";", "&", "\n":
				flush()
			case "(", ")", "{", "}":
				// group boundaries: ignore; their contents are ordinary tokens
			default:
				cur = append(cur, t) // redirection operators stay with the command
			}
			continue
		}
		cur = append(cur, t)
	}
	flush()
	return cmds
}

// parseSimple builds the simple command(s) from a token run: any command
// substitutions become separate (earlier) commands, then the main command with
// its redirections, assignments, and wrappers resolved.
func parseSimple(toks []shTok, depth int) []simpleCommand {
	var subCmds []simpleCommand
	var words []string
	var files []fileEffect
	var reads []string

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.op {
			switch t.val {
			case ">", ">|", "1>":
				if i+1 < len(toks) {
					files = append(files, fileEffect{toks[i+1].val, "added"})
					i++
				}
			case ">>", "1>>":
				if i+1 < len(toks) {
					files = append(files, fileEffect{toks[i+1].val, "modified"})
					i++
				}
			case "2>", "2>>", "&>", "&>>":
				if i+1 < len(toks) {
					files = append(files, fileEffect{toks[i+1].val, "modified"})
					i++
				}
			case "<":
				if i+1 < len(toks) {
					reads = append(reads, toks[i+1].val)
					i++
				}
			case "<<", "<<<":
				i++ // here-doc / here-string: skip the delimiter/word
			}
			continue
		}
		// Command substitution inside a word -> its own (earlier) commands.
		for _, inner := range extractSubstitutions(t.val) {
			subCmds = append(subCmds, decomposeShell(inner, depth+1)...)
		}
		words = append(words, t.val)
	}

	main := resolveSimple(words)
	main.files = files
	main.reads = append(main.reads, reads...)
	// Substitutions run before the command that uses their output.
	return append(subCmds, main)
}

// resolveSimple strips leading VAR=val assignments and wrapper programs and
// classifies the result (builtin vs external), returning the effective command.
func resolveSimple(words []string) simpleCommand {
	// Strip leading NAME=value environment assignments.
	i := 0
	for i < len(words) && isAssignment(words[i]) {
		i++
	}
	words = words[i:]
	if len(words) == 0 {
		return simpleCommand{builtin: true} // pure assignment: no process
	}

	uid := ""
	// Unwrap wrapper programs (sudo/env/nohup/timeout/...), which exec the next
	// program; sudo/doas elevate privileges.
	for len(words) > 0 {
		w := path.Base(words[0])
		if w == "sudo" || w == "doas" {
			uid = "0"
			words = stripWrapperArgs(words[1:], w)
			continue
		}
		if _, ok := wrapperCommands[w]; ok {
			words = stripWrapperArgs(words[1:], w)
			continue
		}
		break
	}
	if len(words) == 0 {
		return simpleCommand{builtin: true, uid: uid}
	}
	if isControlKeyword(words[0]) {
		return simpleCommand{builtin: true, uid: uid} // for/if/while/... keyword
	}
	if isBuiltin(path.Base(words[0])) {
		return simpleCommand{argv: words, builtin: true, uid: uid}
	}
	return simpleCommand{argv: words, uid: uid}
}

// parseArgv builds a simple command from an explicit argv (no shell parsing),
// still unwrapping wrappers and classifying builtins.
func parseArgv(argv []string) simpleCommand {
	return resolveSimple(argv)
}

// stripWrapperArgs drops a wrapper's own option arguments so the next word is the
// wrapped program. It skips leading options (-x) and, for wrappers that take one
// value argument, that value (e.g. `timeout 5s`, `nice -n 10`, `sudo -u user`).
func stripWrapperArgs(words []string, wrapper string) []string {
	for len(words) > 0 && strings.HasPrefix(words[0], "-") {
		opt := words[0]
		words = words[1:]
		// `sudo -u user`, `nice -n N`, `ionice -c N` take a following value.
		if len(words) > 0 && !strings.HasPrefix(words[0], "-") &&
			(opt == "-u" || opt == "-n" || opt == "-c" || opt == "-g") {
			words = words[1:]
		}
	}
	// `timeout <duration> cmd` and `flock <path> cmd` take a leading bare value.
	if (wrapper == "timeout" || wrapper == "flock") && len(words) > 1 {
		words = words[1:]
	}
	return words
}

// extractSubstitutions returns the inner command strings of $(...) and `...`
// found in a word (balanced for $()).
func extractSubstitutions(word string) []string {
	var out []string
	for i := 0; i < len(word); i++ {
		if word[i] == '$' && i+1 < len(word) && word[i+1] == '(' {
			depth, j := 1, i+2
			for j < len(word) && depth > 0 {
				switch word[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
				j++
			}
			if depth == 0 {
				out = append(out, word[i+2:j-1])
				i = j - 1
			}
		} else if word[i] == '`' {
			if j := strings.IndexByte(word[i+1:], '`'); j >= 0 {
				out = append(out, word[i+1:i+1+j])
				i = i + 1 + j
			}
		}
	}
	return out
}

// shTok is a shell token: an operator or a word.
type shTok struct {
	op  bool
	val string
}

// shellTokenize splits a command line into word and operator tokens, honoring
// single/double quotes, backslash escapes, $(...) and `...` (kept whole), and
// the shell operators.
func shellTokenize(s string) []shTok {
	var toks []shTok
	var cur strings.Builder
	inWord := false
	emit := func() {
		if inWord {
			toks = append(toks, shTok{val: cur.String()})
			cur.Reset()
			inWord = false
		}
	}
	push := func(op string) { emit(); toks = append(toks, shTok{op: true, val: op}) }

	for i := 0; i < len(s); i++ {
		c := s[i]
		// fd-prefixed redirections (1>, 1>>, 2>, 2>>) when the fd stands alone.
		if !inWord && (c == '1' || c == '2') && i+1 < len(s) && s[i+1] == '>' {
			if i+2 < len(s) && s[i+2] == '>' {
				push(string(c) + ">>")
				i += 2
			} else {
				push(string(c) + ">")
				i++
			}
			continue
		}
		switch c {
		case ' ', '\t':
			emit()
		case '\n', ';', '(', ')', '{', '}':
			push(string(c))
		case '|':
			if i+1 < len(s) && s[i+1] == '|' {
				push("||")
				i++
			} else {
				push("|")
			}
		case '&':
			switch {
			case i+1 < len(s) && s[i+1] == '&':
				push("&&")
				i++
			case i+1 < len(s) && s[i+1] == '>':
				if i+2 < len(s) && s[i+2] == '>' {
					push("&>>")
					i += 2
				} else {
					push("&>")
					i++
				}
			default:
				push("&")
			}
		case '>':
			if i+1 < len(s) && s[i+1] == '>' {
				push(">>")
				i++
			} else if i+1 < len(s) && s[i+1] == '|' {
				push(">|")
				i++
			} else {
				push(">")
			}
		case '<':
			if i+1 < len(s) && s[i+1] == '<' {
				if i+2 < len(s) && s[i+2] == '<' {
					push("<<<")
					i += 2
				} else {
					push("<<")
					i++
				}
			} else {
				push("<")
			}
		case '\'':
			inWord = true
			for i++; i < len(s) && s[i] != '\''; i++ {
				cur.WriteByte(s[i])
			}
		case '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\' || s[i+1] == '$' || s[i+1] == '`') {
					i++
				}
				cur.WriteByte(s[i])
			}
		case '\\':
			if i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
				inWord = true
			}
		case '$':
			// Keep $(...) as part of the word (balanced), so operators inside a
			// substitution do not split the outer command.
			if i+1 < len(s) && s[i+1] == '(' {
				depth, j := 1, i+2
				cur.WriteString("$(")
				for j < len(s) && depth > 0 {
					if s[j] == '(' {
						depth++
					} else if s[j] == ')' {
						depth--
					}
					cur.WriteByte(s[j])
					j++
				}
				i = j - 1
				inWord = true
			} else {
				cur.WriteByte(c)
				inWord = true
			}
		case '`':
			cur.WriteByte(c)
			inWord = true
			for i++; i < len(s) && s[i] != '`'; i++ {
				cur.WriteByte(s[i])
			}
			if i < len(s) {
				cur.WriteByte('`')
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	emit()
	return toks
}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := w[i]
		if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func resolveExeSafe(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return resolveExe(argv[0])
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
	in        CommandInput
	ts        time.Time
	pid       int // next pid to assign
	shellPID  int // the interactive shell that forks each simple command
	parentPID int // pid of the current top-level command (parent of its children)
	serial    int64
}

// next returns a CommandInput stamped with the next pid/serial/time and the
// given effective uid and parent pid.
func (s *footprintSeq) next(uid string, ppid int) (CommandInput, int) {
	in := s.in
	pid := s.pid
	in.Timestamp = s.ts
	in.PID = strconv.Itoa(pid)
	in.PPID = strconv.Itoa(ppid)
	in.EventSerial = s.serial
	if uid != "" {
		in.UID = uid
	}
	s.ts = s.ts.Add(time.Millisecond)
	s.pid++
	s.serial++
	return in, pid
}

// mainExecve is a top-level command forked by the shell; its pid becomes the
// parent of any children the profile expands.
func (s *footprintSeq) mainExecve(argv []string, exe, uid, summary string) TelemetryEvent {
	in, pid := s.next(uid, s.shellPID)
	s.parentPID = pid
	in.Argv, in.Exe = argv, exe
	ev, _ := buildAuditEvent(in)
	return TelemetryEvent{Source: sourceExecve, Summary: summary, Event: mustJSONRaw(ev)}
}

// child is a process spawned by the current top-level command.
func (s *footprintSeq) child(argv []string, exe, uid, summary string) TelemetryEvent {
	in, _ := s.next(uid, s.parentPID)
	in.Argv, in.Exe = argv, exe
	ev, _ := buildAuditEvent(in)
	return TelemetryEvent{Source: sourceExecve, Summary: summary, Event: mustJSONRaw(ev)}
}

func (s *footprintSeq) fim(filePath, event, uid string) TelemetryEvent {
	in, _ := s.next(uid, s.parentPID)
	ev := buildSyscheckEvent(in, filePath, event)
	return TelemetryEvent{Source: sourceFIM, Summary: fmt.Sprintf("file %s: %s", event, filePath), Event: mustJSONRaw(ev)}
}

func (s *footprintSeq) fileAccess(argv []string, exe, filePath, uid string) TelemetryEvent {
	in, _ := s.next(uid, s.shellPID)
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

func isFileReader(base string) bool {
	switch base {
	case "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "awk", "sed",
		"vi", "vim", "nano", "strings", "od", "xxd", "cp", "scp", "diff", "wc", "sort":
		return true
	}
	return false
}

func looksLikePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") || strings.HasPrefix(s, "~/")
}

// wrapperCommands run and then exec another program; the footprint attributes
// the execve to the wrapped program (sudo/doas also elevate privileges).
var wrapperCommands = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nohup": true, "setsid": true,
	"stdbuf": true, "nice": true, "ionice": true, "time": true, "command": true,
	"exec": true, "timeout": true, "watch": true, "flock": true, "xargs": true,
	"chroot": true, "unbuffer": true, "eatmydata": true, "proxychains": true,
}

// isControlKeyword reports a shell control keyword that is not a process.
func isControlKeyword(w string) bool {
	switch w {
	case "for", "while", "until", "if", "then", "else", "elif", "fi", "do", "done",
		"case", "esac", "select", "function", "in", "time", "!", "{", "}", "[[", "]]":
		return true
	}
	return false
}

// shellBuiltins execute inside the shell — no execve is generated (redirections
// they perform still produce file events).
var shellBuiltins = map[string]bool{
	"cd": true, "export": true, "unset": true, "alias": true, "unalias": true,
	"set": true, "shopt": true, "source": true, ".": true, ":": true, "true": true,
	"false": true, "echo": true, "printf": true, "read": true, "test": true,
	"[": true, "let": true, "eval": true, "pwd": true, "umask": true, "ulimit": true,
	"pushd": true, "popd": true, "dirs": true, "local": true, "declare": true,
	"typeset": true, "readonly": true, "trap": true, "shift": true, "getopts": true,
	"wait": true, "jobs": true, "fg": true, "bg": true, "type": true, "hash": true,
	"help": true, "history": true, "return": true, "break": true, "continue": true,
	"times": true, "caller": true, "enable": true, "builtin": true, "logout": true,
	"exit": true, "suspend": true, "disown": true, "complete": true, "compgen": true,
	"mapfile": true, "readarray": true,
}

func isBuiltin(base string) bool { return shellBuiltins[base] }

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
