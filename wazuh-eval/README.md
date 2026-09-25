# wazuh-eval

A standalone, dependency-free Go program that evaluates a defense-generation
candidate's rule against an event and reports whether it **matches**:

- **EDR** — a **Wazuh rule** (ruleset XML) against decoded telemetry.
- **WAF** — a **ModSecurity `SecRule`** against an HTTP request.

It answers one question per rule: *given this event, would this rule fire?* — with
a per-condition breakdown so you can see exactly which condition passed or failed.

Given a defense-generation candidate, it routes to the right evaluator by
**candidate kind** (`selected_control_class` / `candidate_kind` / `artifact_type`).
The WAF path reuses the mitigation-check in-process WAF evaluator (api's
`executor.go`) so a WAF candidate is judged here exactly as the production
in-memory substrate judges it.

Standard library only (`encoding/xml`, `encoding/json`, `regexp`, `net`, `flag`).

## Build

```bash
cd wazuh-eval
go build -o wazuh-eval .
```

## Candidate mode (EDR + WAF)

Pass a defense-generation candidate (a full result document with a
`primary_candidate`, or a bare candidate object) and an event; the tool picks the
evaluator by candidate kind:

```bash
# Auto-routes to EDR (Wazuh) or WAF (ModSecurity) by candidate kind:
wazuh-eval -candidate candidate.json -event event.json
cat event.json | wazuh-eval -candidate candidate.json -json
```

| Candidate | `selected_control_class` / `candidate_kind` / `artifact_type` | Evaluator | Event is |
|-----------|---------------------------------------------------------------|-----------|----------|
| EDR | `edr` / `endpoint-detection-rule` / `wazuh-rule` | Wazuh rule engine (this module) | decoded telemetry JSON |
| WAF | `waf` / `fast-waf-rule` / `modsecurity-rule` | ModSecurity `SecRule` engine (reused from api) | an HTTP request JSON |

`artifact_content` is taken straight from the candidate (the outer JSON parse
un-escapes it). For WAF, `matched=true` means the `SecRule` fired → the request
would be **blocked**.

**HTTP request JSON** (WAF): `{"method","path","headers","body"}` — `path` may
include a `?query` (aliases: `uri`/`url` → `path`, `request_body` → `body`).

## Command → Wazuh telemetry

`CommandToWazuhTelemetry` synthesizes the telemetry a Wazuh agent would report
for a command run on a Linux host or container. On Linux, command execution is
captured by the Audit subsystem (auditd): the kernel emits an `execve()` event
that Wazuh's `auditd` decoder turns into `data.audit.*` fields. The function
produces that decoded event — structured fields **and** the raw multi-record
`full_log` (SYSCALL / EXECVE / CWD / PROCTITLE) — so it round-trips into the
evaluator.

```go
ev, _ := CommandToWazuhEvent(CommandInput{Command: "cat /etc/passwd", User: "root"})
res := Evaluate(rule, ev) // command → telemetry → verdict
```

From the CLI:

```bash
# Print the telemetry for a command:
wazuh-eval -cmd 'cat /etc/passwd'

# Synthesize telemetry AND evaluate a rule against it in one step:
wazuh-eval -rule rules.xml -cmd 'cat /etc/passwd'
```

A shell pipeline or builtin (`|`, `&&`, `;`, `>`, `` ` ``, `$()`) is recorded as a
single `/bin/sh -c "<command>"` execve — the first audit event the kernel
actually produces. Pass `CommandInput.Argv` to synthesize a bare execve instead.
uid/cwd are best-effort from `User` (override with `UID`/`Cwd`); this models
auditd execve, not Sysmon-for-Linux.

## EDR direct mode

```bash
# Event from a JSON file
wazuh-eval -rule rules.xml -event event.json

# Event piped on stdin
cat event.json | wazuh-eval -rule rules.xml

# A raw (non-JSON) log line
wazuh-eval -rule rules.xml -log 'Failed password for root from 10.4.5.6 port 22 ssh2'

# Only one rule from a file with many
wazuh-eval -rule rules.xml -event event.json -id 100100

# Machine-readable output
wazuh-eval -rule rules.xml -event event.json -json
```

**Exit status:** `0` if at least one evaluated rule matched, `1` if none matched,
`2` on a usage or parse error. This makes it usable as a shell test.

### Example

```
Rule 100100 (level 12): MATCH
  description: Encoded PowerShell via Sysmon
  ✓ field:win.system.channel ~ "^Microsoft-Windows-Sysmon"
      field=win.system.channel value=Microsoft-Windows-Sysmon/Operational
  ✓ field:win.eventdata.image ~ "\\powershell\.exe$"
      field=win.eventdata.image value=C:\Windows\...\powershell.exe
  ✓ field:win.eventdata.commandLine ~ "-enc|-EncodedCommand"
      field=win.eventdata.commandLine value=powershell.exe -enc SQBFAFgA
```

## Telemetry input ("all types")

Every kind of Wazuh telemetry — FIM/syscheck, Windows EventChannel & Sysmon,
syscollector, auditd, network, and plain logs — reaches Wazuh's analysis engine
as a set of **decoded key/value fields**. This tool accepts that decoded event as
JSON and flattens it to dot-notation keys, so a rule can address any of them:

| Telemetry              | Example flattened key                 |
|------------------------|---------------------------------------|
| Sysmon / EventChannel  | `win.eventdata.image`, `win.system.channel` |
| FIM / syscheck         | `syscheck.path`, `syscheck.event`     |
| Network / firewall     | `srcip`, `dstip`, `srcport`, `protocol` |
| auditd / generic       | `data.audit.*`, `data.status`, `data.user` |

- A Wazuh alert document that nests everything under `data` is handled: field
  lookups try the exact name **and** a `data.`-prefixed variant, so a rule that
  says `<field name="win.eventdata.image">` matches `data.win.eventdata.image`.
- The raw line is taken from `full_log` (or `message`/`log`) and is what
  `<match>`, `<regex>`, and `<pcre2>` run against.
- Non-JSON input is treated as a raw `full_log` line, so a bare log still works.

## Rule input

Standard Wazuh ruleset XML. A `<group>` wrapper, a bare `<rule>`, or several
rules in one file all parse. All conditions inside a rule are **AND-ed** — the
rule matches only when every condition it declares matches.

**Evaluated per-event conditions:** `decoded_as`, `program_name`, `match`,
`regex`, `pcre2`, `field name="..."`, `srcip`, `dstip`, `srcport`, `dstport`,
`user`, `srcuser`, `dstuser`, `url`, `id`, `status`, `hostname`, `extra_data`,
`system_name`, `action`, `protocol`, `data`, `location`. The `negate="yes"`
attribute inverts any of them, and `type="osmatch|osregex|pcre2"` overrides the
matching engine.

**Reported as notes, not evaluated:** `if_sid`, `if_group`, `if_matched_sid`,
`if_matched_group`, `frequency`/`timeframe`, `same_source_ip`, `same_user`,
`different_url`. These are correlation conditions that span multiple events and
cannot be judged from a single event; they are surfaced as informational notes
and assumed satisfied so the per-event content conditions can still be checked.

## Matching engines (approximations)

Wazuh uses three text-matching engines. This tool implements stdlib-only
approximations. For the overwhelming majority of real rules these are exact;
the caveats below are where they can differ.

| Rule element / `type`     | Wazuh engine | Approximation here |
|---------------------------|--------------|--------------------|
| `<match>`, `osmatch`      | OS_Match     | Literal substring with `\|` alternation and `^`/`$` anchors. |
| `<regex>`, `<field>`, `osregex` | OS_Regex | Wazuh escape classes (`\w \d \s \p \t` …) translated to Go RE2. |
| `<pcre2>`, `pcre2`        | PCRE2        | Go RE2. **Lookaround and backreferences are unsupported** and reported. |

Notes:

- **OS_Match** is a plain string comparison in Wazuh (no regex metacharacters);
  we replicate that, including `^`/`$` anchoring and `|` alternation.
- **OS_Regex** `\p` means *punctuation* in Wazuh (it is `[[:punct:]]` here),
  which differs from PCRE/RE2 where `\p` starts a Unicode class. Other classes
  map directly. When a pattern is rewritten, the note shows the RE2 form used.
- **PCRE2** maps to RE2, which is linear-time and has no lookaround/backreferences.
  A pattern using those fails to compile and the condition is reported as
  non-evaluable rather than silently passing.
- `srcip`/`dstip` accept a plain IP, a CIDR, or a comma/pipe-separated list.

## Test

```bash
go test ./...
```

Covers Sysmon encoded-PowerShell, sshd failed-login with a `srcip` CIDR, FIM
`/etc` change, `negate`, raw-log matching, and correlation-note handling.
