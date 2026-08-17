package service

import (
	"testing"

	"scanvault/internal/store"
)

func TestRotationDeactivatesPreviousEnvelope(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/rotate.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	application := New(database, "rotate", "fixed-time")
	device, err := application.RegisterDevice("SC-200", "Scanner", "public-key-200", "south", "ops", "alice")
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := application.RotateSecret(device.ID, "first-secret", "alice", "first")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := application.RotateSecret(device.ID, "second-secret", "alice", "second")
	if err != nil {
		t.Fatal(err)
	}
	storedFirst, err := store.GetEnvelope(database, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedFirst.Active || !second.Active || second.Version != 2 {
		t.Fatalf("unexpected envelope states: %+v %+v", storedFirst, second)
	}
	if _, err := application.RecoverSecret(device.ID, "private-key", first.ID); err == nil {
		t.Fatal("inactive envelope recovered")
	}
	secret, err := application.RecoverSecret(device.ID, "private-key", second.ID)
	if err != nil || secret != "second-secret" {
		t.Fatalf("current recovery failed: %q %v", secret, err)
	}
}
