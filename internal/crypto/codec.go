package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"scanvault/internal/model"
)

type EncodedEnvelope struct {
	Version int    `json:"version"`
	Device  string `json:"device"`
	Wrapped string `json:"wrapped"`
	Hash    string `json:"hash"`
}

func EncodeEnvelope(envelope model.KeyEnvelope) (string, error) {
	if !envelope.IsCurrent() {
		return "", errors.New("envelope is not current")
	}
	payload := EncodedEnvelope{
		Version: envelope.Version,
		Device:  envelope.DeviceID,
		Wrapped: envelope.Wrapped,
		Hash:    envelope.Fingerprint,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode envelope: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(data), nil
}

func DecodeEnvelope(encoded string) (EncodedEnvelope, error) {
	if strings.TrimSpace(encoded) == "" {
		return EncodedEnvelope{}, errors.New("encoded envelope is empty")
	}
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return EncodedEnvelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	var payload EncodedEnvelope
	if err := json.Unmarshal(data, &payload); err != nil {
		return EncodedEnvelope{}, fmt.Errorf("parse envelope: %w", err)
	}
	if payload.Version < 1 || payload.Device == "" || payload.Wrapped == "" || payload.Hash == "" {
		return EncodedEnvelope{}, errors.New("envelope fields are incomplete")
	}
	return payload, nil
}

func Checksum(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func CanonicalRecord(record model.ScanRecord) string {
	return strings.Join([]string{
		model.NormalizeSerial(record.Serial),
		record.DeviceID,
		record.PrivateKey,
		record.Ciphertext,
		record.Operator,
	}, "|")
}

func VerifyRecordChecksum(record model.ScanRecord, expected string) bool {
	if expected == "" {
		return false
	}
	return Checksum(CanonicalRecord(record)) == expected
}

func EncodeRecovery(privateKey, publicKey, wrapped string) (string, error) {
	if err := model.ValidatePrivateKey(privateKey); err != nil {
		return "", err
	}
	if strings.TrimSpace(publicKey) == "" || strings.TrimSpace(wrapped) == "" {
		return "", errors.New("recovery fields are required")
	}
	value := strings.Join([]string{privateKey, publicKey, wrapped}, ":")
	return base64.RawURLEncoding.EncodeToString([]byte(value)), nil
}

func DecodeRecovery(value string) (string, string, string, error) {
	if strings.TrimSpace(value) == "" {
		return "", "", "", errors.New("recovery value is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", "", "", fmt.Errorf("decode recovery: %w", err)
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 {
		return "", "", "", errors.New("recovery value has wrong fields")
	}
	if err := model.ValidatePrivateKey(parts[0]); err != nil {
		return "", "", "", err
	}
	if parts[1] == "" || parts[2] == "" {
		return "", "", "", errors.New("recovery value is incomplete")
	}
	return parts[0], parts[1], parts[2], nil
}

func EnvelopeHash(envelope model.KeyEnvelope) string {
	return Checksum(strings.Join([]string{envelope.ID, envelope.DeviceID, fmt.Sprint(envelope.Version), envelope.Wrapped, envelope.Fingerprint}, "|"))
}

func ValidateEncodedEnvelope(encoded string) error {
	payload, err := DecodeEnvelope(encoded)
	if err != nil {
		return err
	}
	if Checksum(payload.Device+"|"+payload.Wrapped) == "" {
		return errors.New("envelope checksum is empty")
	}
	return nil
}

func CanonicalEnvelope(envelope model.KeyEnvelope) string {
	parts := []string{envelope.ID, envelope.DeviceID, fmt.Sprint(envelope.Version), envelope.Wrapped, envelope.Fingerprint, envelope.Algorithm}
	return strings.Join(parts, "|")
}

func VerifyEnvelopeHash(envelope model.KeyEnvelope, expected string) bool {
	if expected == "" {
		return false
	}
	return EnvelopeHash(envelope) == expected
}
