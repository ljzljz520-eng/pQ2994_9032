package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var serialPattern = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{3,31}$`)

func ValidateDevice(device Device) error {
	if strings.TrimSpace(device.ID) == "" {
		return errors.New("device id is required")
	}
	if !serialPattern.MatchString(strings.ToUpper(strings.TrimSpace(device.Serial))) {
		return fmt.Errorf("invalid serial %q", device.Serial)
	}
	if strings.TrimSpace(device.Name) == "" {
		return errors.New("device name is required")
	}
	if strings.TrimSpace(device.PublicKey) == "" {
		return errors.New("public key is required")
	}
	if strings.TrimSpace(device.Owner) == "" {
		return errors.New("owner is required")
	}
	if len(device.PublicKey) < 8 {
		return errors.New("public key is too short")
	}
	return nil
}

func NormalizeSerial(serial string) string {
	return strings.ToUpper(strings.TrimSpace(serial))
}

func ValidateSecret(secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return errors.New("communication secret is required")
	}
	if len(secret) < 8 {
		return errors.New("communication secret must contain eight characters")
	}
	if strings.ContainsAny(secret, "\n\r\x00") {
		return errors.New("communication secret contains a control character")
	}
	return nil
}

func ValidatePrivateKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("private key is required")
	}
	if len(key) < 8 {
		return errors.New("private key is too short")
	}
	return nil
}

func ValidateCiphertext(ciphertext string) error {
	if strings.TrimSpace(ciphertext) == "" {
		return errors.New("ciphertext is required")
	}
	if len(ciphertext) < 16 {
		return errors.New("ciphertext is too short")
	}
	return nil
}

func ValidateImportRecord(record ScanRecord) error {
	if record.Line < 1 {
		return errors.New("line must be positive")
	}
	if NormalizeSerial(record.Serial) == "" && strings.TrimSpace(record.DeviceID) == "" {
		return errors.New("serial or device id is required")
	}
	if err := ValidatePrivateKey(record.PrivateKey); err != nil {
		return err
	}
	return ValidateCiphertext(record.Ciphertext)
}

func ValidateRotation(request RotationRequest) error {
	if request.ID == "" || request.DeviceID == "" || request.EnvelopeID == "" {
		return errors.New("rotation identity is incomplete")
	}
	if request.RequestedBy == "" {
		return errors.New("requester is required")
	}
	if request.State != "pending" && request.State != "approved" && request.State != "rejected" && request.State != "applied" {
		return errors.New("invalid rotation state")
	}
	return nil
}

func ValidateAudit(entry AuditEntry) error {
	if entry.ID == "" || entry.Entity == "" || entry.EntityID == "" {
		return errors.New("audit identity is incomplete")
	}
	if entry.Action == "" || entry.Actor == "" || entry.Outcome == "" {
		return errors.New("audit event fields are required")
	}
	if entry.Sequence < 1 {
		return errors.New("audit sequence must be positive")
	}
	return nil
}

func CheckStateTransition(from, to string) error {
	if from == to {
		return errors.New("state did not change")
	}
	if from == "pending" && (to == "approved" || to == "rejected") {
		return nil
	}
	if from == "approved" && to == "applied" {
		return nil
	}
	return fmt.Errorf("transition %s -> %s is not allowed", from, to)
}

func ValidateEnvelope(envelope KeyEnvelope) error {
	if envelope.ID == "" || envelope.DeviceID == "" {
		return errors.New("envelope identity is required")
	}
	if envelope.Version < 1 {
		return errors.New("envelope version must be positive")
	}
	if envelope.Wrapped == "" || envelope.Fingerprint == "" {
		return errors.New("envelope payload is required")
	}
	if envelope.Algorithm == "" {
		return errors.New("envelope algorithm is required")
	}
	return nil
}

func ValidateBatch(batch ImportBatch) error {
	if strings.TrimSpace(batch.ID) == "" {
		return errors.New("batch id is required")
	}
	if strings.TrimSpace(batch.Source) == "" {
		return errors.New("batch source is required")
	}
	if batch.Total < 0 || batch.Succeeded < 0 || batch.Failed < 0 {
		return errors.New("batch counts cannot be negative")
	}
	if batch.Succeeded+batch.Failed > batch.Total {
		return errors.New("batch results exceed total")
	}
	if batch.State != "processing" && batch.State != "completed" && batch.State != "completed_with_errors" {
		return errors.New("invalid batch state")
	}
	return nil
}

func NormalizeOperator(operator string) string {
	return strings.ToLower(strings.TrimSpace(operator))
}

func NormalizeReason(reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	if reason == "" {
		return "unspecified"
	}
	if len(reason) > 200 {
		return reason[:200]
	}
	return reason
}

func IsTerminalStatus(status string) bool {
	return status == "retired" || status == "rejected" || status == "applied" || status == "completed" || status == "completed_with_errors"
}

func StatusAllowsRotation(status string) bool {
	return NormalizeStatus(status) == "active"
}

func ValidateReportRow(row ReportRow) error {
	if row.Sequence == "" || row.Actor == "" || row.Action == "" {
		return errors.New("report row identity is incomplete")
	}
	if row.Entity == "" || row.EntityID == "" {
		return errors.New("report row entity is incomplete")
	}
	return nil
}
