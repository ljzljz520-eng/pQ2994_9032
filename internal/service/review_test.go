package service

import (
	"testing"

	"scanvault/internal/store"
)

func TestRejectAndSuspendWorkflow(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/review.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	application := New(database, "review", "fixed-time")
	device, err := application.RegisterDevice("SC-300", "Scanner", "public-key-300", "west", "ops", "alice")
	if err != nil {
		t.Fatal(err)
	}
	_, request, err := application.RotateSecret(device.ID, "review-secret", "alice", "needs review")
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := application.RejectRotation(request.ID, "bob", "missing ticket")
	if err != nil || rejected.State != "rejected" {
		t.Fatalf("reject failed: %+v %v", rejected, err)
	}
	if err := application.SuspendDevice(device.ID, "alice", "maintenance"); err != nil {
		t.Fatal(err)
	}
	loaded, err := application.GetDevice(device.ID)
	if err != nil || loaded.Status != "suspended" {
		t.Fatalf("suspend failed: %+v %v", loaded, err)
	}
}
