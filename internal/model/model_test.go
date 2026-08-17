package model

import "testing"

func TestDeviceValidationAndNormalization(t *testing.T) {
	device := Device{ID: "d1", Serial: " sc-001 ", Name: "Scanner", PublicKey: "public-key", Owner: "ops"}
	device.Serial = NormalizeSerial(device.Serial)
	if err := ValidateDevice(device); err != nil {
		t.Fatal(err)
	}
	if device.Serial != "SC-001" || !device.IsUsable() {
		t.Fatalf("unexpected device: %+v", device)
	}
	if NormalizeStatus("bogus") != "unknown" {
		t.Fatal("unknown status was not normalized")
	}
}

func TestValidationRejectsMalformedRecords(t *testing.T) {
	if err := ValidateSecret("short"); err == nil {
		t.Fatal("short secret accepted")
	}
	if err := ValidateImportRecord(ScanRecord{Line: 0}); err == nil {
		t.Fatal("empty record accepted")
	}
	if err := CheckStateTransition("approved", "pending"); err == nil {
		t.Fatal("invalid transition accepted")
	}
}
