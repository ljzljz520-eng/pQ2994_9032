package audit

import (
	"testing"

	"scanvault/internal/model"
	"scanvault/internal/store"
)

func TestSearchAndFilterAuditEntries(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	recorder := NewRecorder(database, "fixed-time")
	if _, err := recorder.Record("Device", "d1", "register", "alice", "accepted", "registered"); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Record("KeyEnvelope", "e1", "rotate", "alice", "pending", "warehouse"); err != nil {
		t.Fatal(err)
	}
	entries, err := recorder.List()
	if err != nil || len(entries) != 2 {
		t.Fatalf("list failed: %d %v", len(entries), err)
	}
	result := Search(entries, Query{Entity: "KeyEnvelope", Contains: "WARE"})
	if len(result) != 1 || result[0].ID != "audit-000002" {
		t.Fatalf("query failed: %+v", result)
	}
	if len(Filter(entries, "Device", "", "accepted")) != 1 {
		t.Fatal("filter failed")
	}
	if len(Summaries([]model.AuditEntry{entries[0]})) != 1 {
		t.Fatal("summary failed")
	}
}
