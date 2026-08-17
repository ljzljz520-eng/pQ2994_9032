package report

import (
	"strings"
	"testing"

	"scanvault/internal/audit"
	"scanvault/internal/model"
)

func TestReportRowsCSVAndTable(t *testing.T) {
	entries := []model.AuditEntry{{ID: "a1", Entity: "Device", EntityID: "d1", Action: "register", Actor: "alice", Outcome: "accepted", Detail: "one", Sequence: 1, RecordedAt: "fixed"}}
	builder := NewBuilder("audit export")
	rows := builder.FilteredRows(entries, audit.Query{Actor: "alice"})
	if len(rows) != 1 {
		t.Fatal("filtered rows missing")
	}
	csvText, err := RenderCSV(rows)
	if err != nil || !strings.Contains(csvText, "sequence") || !strings.Contains(csvText, "register") {
		t.Fatalf("csv failed: %q %v", csvText, err)
	}
	table := RenderTable(rows)
	if !strings.Contains(table, "Device") || !strings.Contains(builder.Summary(entries), "total=1") {
		t.Fatalf("table summary failed: %q", table)
	}
}
