package store

import (
	"testing"

	"scanvault/internal/model"
)

func TestPersistenceSurvivesReopen(t *testing.T) {
	path := t.TempDir() + "/scanvault.db"
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	device := model.Device{ID: "device-1", Serial: "SC-001", Name: "One", PublicKey: "public-key", Status: "active", Owner: "ops"}
	if err := SaveDevice(first, device); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	loaded, err := GetDevice(second, device.ID)
	if err != nil || loaded.Serial != device.Serial {
		t.Fatalf("reopen lost device: %+v %v", loaded, err)
	}
}

func TestRepositoryListsAndSequences(t *testing.T) {
	database, err := Open(t.TempDir() + "/list.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for index := 1; index <= 2; index++ {
		device := model.Device{ID: string(rune('a' + index)), Serial: "SC-00" + string(rune('0'+index)), Name: "Device", PublicKey: "public-key", Status: "active", Owner: "ops"}
		if err := SaveDevice(database, device); err != nil {
			t.Fatal(err)
		}
	}
	devices, err := ListDevices(database)
	if err != nil || len(devices) != 2 {
		t.Fatalf("list failed: %d %v", len(devices), err)
	}
	first, err := NextSequence(database)
	if err != nil || first != 1 {
		t.Fatalf("sequence failed: %d %v", first, err)
	}
	second, err := NextSequence(database)
	if err != nil || second != 2 {
		t.Fatalf("sequence failed: %d %v", second, err)
	}
}
