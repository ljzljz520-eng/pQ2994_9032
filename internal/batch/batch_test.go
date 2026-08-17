package batch

import (
	"testing"

	"scanvault/internal/model"
	"scanvault/internal/service"
	"scanvault/internal/store"
)

func prepareImport(t *testing.T) (*service.Service, model.Device, model.KeyEnvelope) {
	t.Helper()
	database, err := store.Open(t.TempDir() + "/batch.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	application := service.New(database, "batch", "fixed-time")
	device, err := application.RegisterDevice("SC-400", "Scanner", "public-key-400", "dock", "ops", "alice")
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := application.RotateSecret(device.ID, "batch-secret", "alice", "batch")
	if err != nil {
		t.Fatal(err)
	}
	return application, device, envelope
}

func TestBatchImportAuditTrail(t *testing.T) {
	application, device, envelope := prepareImport(t)
	importer := NewImporter(application)
	records := []model.ScanRecord{
		{Line: 1, Serial: device.Serial, DeviceID: device.ID, PrivateKey: "private-key-400", Ciphertext: envelope.Wrapped, Operator: "alice"},
		{Line: 2, Serial: device.Serial, DeviceID: device.ID, PrivateKey: "private-key-400", Ciphertext: envelope.Wrapped, Operator: "alice"},
		{Line: 3, Serial: device.Serial, DeviceID: device.ID, PrivateKey: "private-key-400", Ciphertext: "bad-ciphertext-value", Operator: "alice"},
	}
	batch, results, err := importer.Import(records, "devices.csv", "alice")
	if err != nil {
		t.Fatalf("batch import failed: %v results=%+v batch=%+v", err, results, batch)
	}
	if batch.Succeeded != 2 || batch.Failed != 1 {
		t.Fatalf("unexpected batch: %+v", batch)
	}
}

func TestImportRejectsBadCiphertext(t *testing.T) {
	application, device, _ := prepareImport(t)
	importer := NewImporter(application)
	records := []model.ScanRecord{{Line: 1, Serial: device.Serial, DeviceID: device.ID, PrivateKey: "private-key-400", Ciphertext: "bad-ciphertext-value", Operator: "alice"}}
	batch, results, err := importer.Import(records, "bad.csv", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if batch.Failed != 1 || len(results) != 1 || results[0].Status != "failed" {
		t.Fatalf("bad record was accepted: %+v %+v", batch, results)
	}
}
