package main

// event.go models a decoded Wazuh event (telemetry of any type) as a flat map of
// dot-notation fields plus the raw full_log.
//
// "All types of Wazuh EDR telemetry" — FIM/syscheck, Windows EventChannel &
// Sysmon, syscollector, auditd, network, plain logs — reach analysisd as a set of
// decoded key/value fields. We accept the telemetry as JSON (a Wazuh alert/event
// document or any decoded event) and flatten it to keys like
// "data.win.eventdata.image", "syscheck.path", "srcip", so a rule's <field> /
// comparators can address them. Non-JSON input is treated as a raw full_log line.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Event is a decoded telemetry event.
type Event struct {
	Fields  map[string]string // flattened, dot-notation, values stringified
	FullLog string            // raw log line (full_log / message)
}

// LoadEvent parses telemetry JSON into an Event. Invalid JSON is taken as a raw
// full_log line so a bare log can still be matched by <match>/<regex>/<pcre2>.
func LoadEvent(data []byte) *Event {
	trimmed := strings.TrimSpace(string(data))
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return &Event{Fields: map[string]string{"full_log": trimmed}, FullLog: trimmed}
	}
	fields := map[string]string{}
	flatten("", v, fields)
	e := &Event{Fields: fields}
	e.FullLog = firstNonEmpty(
		fields["full_log"], fields["data.full_log"],
		fields["message"], fields["data.message"],
		fields["previous_output"], fields["log"],
	)
	if _, ok := fields["full_log"]; !ok && e.FullLog != "" {
		fields["full_log"] = e.FullLog
	}
	return e
}

// get resolves a field name, tolerating the common "data." prefix that Wazuh
// alert documents add: it tries the exact name, the data-prefixed name, and the
// de-prefixed name.
func (e *Event) get(name string) (string, bool) {
	tries := []string{name, "data." + name}
	if s, ok := strings.CutPrefix(name, "data."); ok {
		tries = append(tries, s)
	}
	for _, k := range tries {
		if v, ok := e.Fields[k]; ok {
			return v, true
		}
	}
	return "", false
}

// getAny returns the first field found among several candidate names.
func (e *Event) getAny(names ...string) (string, bool) {
	for _, n := range names {
		if v, ok := e.get(n); ok {
			return v, true
		}
	}
	return "", false
}

// flatten walks arbitrary decoded JSON into dot-notation keys. Arrays are stored
// both element-wise (prefix.0, prefix.1) and joined at the prefix so a rule can
// match either a specific element or the whole list.
func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, val, out)
		}
	case []any:
		parts := make([]string, 0, len(t))
		for i, val := range t {
			flatten(fmt.Sprintf("%s.%d", prefix, i), val, out)
			parts = append(parts, scalarString(val))
		}
		if prefix != "" {
			out[prefix] = strings.Join(parts, ", ")
		}
	case nil:
		if prefix != "" {
			out[prefix] = ""
		}
	default:
		if prefix != "" {
			out[prefix] = scalarString(v)
		}
	}
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case json.Number:
		return t.String()
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
