package main

import (
	"encoding/json"
	"log"
)

// logLifecycle emits one JSON object per lifecycle event. Identity keys are
// always present so operators can correlate a request before and after result
// creation without parsing free-form messages.
func logLifecycle(event string, run DurableRun, fields map[string]any) {
	entry := map[string]any{
		"event":          event,
		"capability":     "mitigation-check",
		"request_id":     run.RequestID,
		"correlation_id": run.CorrelationID,
		"run_id":         run.RunID,
		"result_id":      value(run.ResultID),
		"status":         run.Status,
		"attempt":        run.Attempt,
	}
	for key, fieldValue := range fields {
		entry[key] = fieldValue
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		log.Printf(`{"event":"lifecycle_log_encoding_failed","capability":"mitigation-check"}`)
		return
	}
	log.Print(string(encoded))
}
