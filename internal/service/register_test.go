package service

import (
	"testing"

	"scanvault/internal/report"
	"scanvault/internal/store"
)

func TestRegisterRotateAuditExport(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/workflow.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	application := New(database, "workflow", "fixed-time")
	device, err := application.RegisterDevice("SC-100", "Warehouse scanner", "public-key-100", "north", "warehouse", "alice")
	if err != nil {
		t.Fatal(err)
	}
	envelope, request, err := application.RotateSecret(device.ID, "communication-secret", "alice", "scheduled")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.ApproveRotation(request.ID, "bob", "reviewed"); err != nil {
		t.Fatal(err)
	}
	if _, err := application.MarkApplied(request.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	secret, err := application.RecoverSecret(device.ID, "private-key-100", envelope.ID)
	if err != nil || secret != "communication-secret" {
		t.Fatalf("recovery failed: %q %v", secret, err)
	}
	entries, err := application.Audit.List()
	if err != nil || len(entries) != 4 {
		t.Fatalf("audit trail failed: %d %v", len(entries), err)
	}
	text, err := report.RenderCSV(report.NewBuilder("audit").Rows(entries))
	if err != nil || len(text) < 80 {
		t.Fatalf("export failed: %q %v", text, err)
	}
}
