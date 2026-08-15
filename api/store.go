package main

// store.go is a durable run ledger (LLD §11.1: mitigation_check_run / _result).
// Each run is persisted as one immutable JSON file and reloaded on startup, so
// runs survive API restarts. It keeps the exact submitted request bytes alongside
// the executed outcome.
//
// This is a file-backed prototype of the relational model in the LLD; the same
// RunStore surface can be re-backed by PostgreSQL without touching handlers.

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// RunRecord is one ledger entry: the immutable request and its executed result.
type RunRecord struct {
	RunID         string          `json:"run_id"`
	ResultID      string          `json:"result_id"`
	TerminalState string          `json:"terminal_state"`
	Match         bool            `json:"match"`
	CreatedAt     time.Time       `json:"created_at"`
	Request       json.RawMessage `json:"request"` // exact submitted payload, immutable
	Response      RunOutcome      `json:"response"`
}

// RunSummary is the compact form shown in the left run panel.
type RunSummary struct {
	RunID         string    `json:"run_id"`
	ResultID      string    `json:"result_id"`
	TerminalState string    `json:"terminal_state"`
	Match         bool      `json:"match"`
	CreatedAt     time.Time `json:"created_at"`
	Summary       string    `json:"summary"`
}

type RunStore struct {
	mu    sync.RWMutex
	dir   string
	runs  map[string]*RunRecord
	order []string // run_ids sorted oldest→newest; List returns newest-first
}

// NewRunStore opens (creating if needed) the ledger directory and loads any
// existing run files into memory.
func NewRunStore(dir string) (*RunStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create ledger dir: %w", err)
	}
	s := &RunStore{dir: dir, runs: make(map[string]*RunRecord)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *RunStore) load() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("read ledger dir: %w", err)
	}
	var recs []*RunRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			log.Printf("ledger: skipping %s: %v", e.Name(), err)
			continue
		}
		var rec RunRecord
		if err := json.Unmarshal(data, &rec); err != nil || rec.RunID == "" {
			log.Printf("ledger: skipping malformed %s", e.Name())
			continue
		}
		recs = append(recs, &rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].CreatedAt.Before(recs[j].CreatedAt) })
	for _, r := range recs {
		s.runs[r.RunID] = r
		s.order = append(s.order, r.RunID)
	}
	log.Printf("ledger: loaded %d run(s) from %s", len(recs), s.dir)
	return nil
}

// Add records a run in memory and durably on disk (write-temp-then-rename so a
// completed file is never partially written).
func (s *RunStore) Add(r *RunRecord) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	final := filepath.Join(s.dir, r.RunID+".json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[r.RunID] = r
	s.order = append(s.order, r.RunID)
	return nil
}

func (s *RunStore) Get(id string) (*RunRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runs[id]
	return r, ok
}

func (s *RunStore) List() []RunSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RunSummary, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		r := s.runs[s.order[i]]
		out = append(out, RunSummary{
			RunID:         r.RunID,
			ResultID:      r.ResultID,
			TerminalState: r.TerminalState,
			Match:         r.Match,
			CreatedAt:     r.CreatedAt,
			Summary:       r.Response.ProseSummary,
		})
	}
	return out
}
