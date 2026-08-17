package crypto

import (
	"testing"

	"scanvault/internal/model"
)

func TestSealOpenAndFingerprint(t *testing.T) {
	sealer := NewSealer("test")
	wrapped, fingerprint, err := sealer.SealCommunicationSecret("public-key-1", "secret-value-1")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := sealer.OpenCommunicationSecret("private-key-1", "public-key-1", wrapped)
	if err != nil || secret != "secret-value-1" {
		t.Fatalf("recovery failed: %q %v", secret, err)
	}
	if !VerifyFingerprint("public-key-1", secret, fingerprint) {
		t.Fatal("fingerprint mismatch")
	}
}

func TestEnvelopeCodecAndRecordChecksum(t *testing.T) {
	envelope := model.KeyEnvelope{ID: "e1", DeviceID: "d1", Version: 1, Wrapped: "wrapped-value", Fingerprint: "fingerprint", Active: true}
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvelope(encoded)
	if err != nil || decoded.Device != "d1" {
		t.Fatalf("codec failed: %+v %v", decoded, err)
	}
	record := model.ScanRecord{Serial: "SC-001", DeviceID: "d1", PrivateKey: "private-key", Ciphertext: "ciphertext-value", Operator: "ops"}
	if !VerifyRecordChecksum(record, Checksum(CanonicalRecord(record))) {
		t.Fatal("record checksum failed")
	}
}
