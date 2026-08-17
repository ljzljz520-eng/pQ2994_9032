package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Device struct {
	ID          string `json:"id"`
	Serial      string `json:"serial"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Status      string `json:"status"`
	Location    string `json:"location"`
	Owner       string `json:"owner"`
	Registered  string `json:"registered"`
	LastChanged string `json:"last_changed"`
}

type KeyEnvelope struct {
	ID          string `json:"id"`
	DeviceID    string `json:"device_id"`
	Version     int    `json:"version"`
	Wrapped     string `json:"wrapped"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	Active      bool   `json:"active"`
}

type RotationRequest struct {
	ID          string `json:"id"`
	DeviceID    string `json:"device_id"`
	EnvelopeID  string `json:"envelope_id"`
	RequestedBy string `json:"requested_by"`
	Reason      string `json:"reason"`
	State       string `json:"state"`
	Reviewer    string `json:"reviewer"`
	Decision    string `json:"decision"`
	CreatedAt   string `json:"created_at"`
	DecidedAt   string `json:"decided_at"`
}

type AuditEntry struct {
	ID         string `json:"id"`
	Entity     string `json:"entity"`
	EntityID   string `json:"entity_id"`
	Action     string `json:"action"`
	Actor      string `json:"actor"`
	Outcome    string `json:"outcome"`
	Detail     string `json:"detail"`
	Sequence   int64  `json:"sequence"`
	RecordedAt string `json:"recorded_at"`
}

type ImportBatch struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Operator  string `json:"operator"`
	State     string `json:"state"`
	Total     int    `json:"total"`
	Succeeded int    `json:"succeeded"`
	Failed    int    `json:"failed"`
	CreatedAt string `json:"created_at"`
}

type ScanRecord struct {
	Line       int    `json:"line"`
	Serial     string `json:"serial"`
	DeviceID   string `json:"device_id"`
	PrivateKey string `json:"private_key"`
	Ciphertext string `json:"ciphertext"`
	Operator   string `json:"operator"`
}

type ImportResult struct {
	Line     int    `json:"line"`
	Serial   string `json:"serial"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Envelope string `json:"envelope"`
}

type ReportRow struct {
	Sequence string
	Time     string
	Actor    string
	Action   string
	Entity   string
	EntityID string
	Outcome  string
	Detail   string
}

func Encode[T any](value T) ([]byte, error) {
	return json.Marshal(value)
}

func Decode[T any](data []byte, target *T) error {
	if len(data) == 0 {
		return fmt.Errorf("empty payload")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	return nil
}

func NormalizeStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "active"
	}
	if value != "active" && value != "suspended" && value != "retired" {
		return "unknown"
	}
	return value
}

func (d Device) IsUsable() bool {
	return d.ID != "" && d.Serial != "" && d.PublicKey != "" && NormalizeStatus(d.Status) == "active"
}

func (e KeyEnvelope) IsCurrent() bool {
	return e.Active && e.DeviceID != "" && e.Version > 0 && e.Wrapped != ""
}

func (r RotationRequest) IsOpen() bool {
	return r.State == "pending" || r.State == "approved"
}

func (a AuditEntry) Summary() string {
	return fmt.Sprintf("%s %s %s/%s: %s", a.Actor, a.Action, a.Entity, a.EntityID, a.Outcome)
}

func EntityName(value any) string {
	switch value.(type) {
	case Device:
		return "Device"
	case KeyEnvelope:
		return "KeyEnvelope"
	case RotationRequest:
		return "RotationRequest"
	case AuditEntry:
		return "AuditEntry"
	case ImportBatch:
		return "ImportBatch"
	default:
		return "Unknown"
	}
}

func (d Device) DisplayName() string {
	if strings.TrimSpace(d.Name) != "" {
		return fmt.Sprintf("%s (%s)", d.Name, d.Serial)
	}
	return d.Serial
}

func (d Device) LocationLabel() string {
	if strings.TrimSpace(d.Location) == "" {
		return "unassigned"
	}
	return strings.TrimSpace(d.Location)
}

func (e KeyEnvelope) Label() string {
	if e.Active {
		return fmt.Sprintf("v%d active", e.Version)
	}
	return fmt.Sprintf("v%d retired", e.Version)
}

func (r RotationRequest) IsDecided() bool {
	return r.State == "approved" || r.State == "rejected" || r.State == "applied"
}

func (r RotationRequest) DecisionLabel() string {
	if !r.IsDecided() {
		return "awaiting review"
	}
	if r.State == "rejected" {
		return "rejected: " + r.Decision
	}
	return r.State + " by " + r.Reviewer
}

func (b ImportBatch) CompletionRatio() float64 {
	if b.Total <= 0 {
		return 1
	}
	return float64(b.Succeeded+b.Failed) / float64(b.Total)
}

func (b ImportBatch) IsComplete() bool {
	return b.State == "completed" || b.State == "completed_with_errors"
}

func (r ImportResult) Accepted() bool {
	return r.Status == "accepted"
}

func (r ImportResult) LineLabel() string {
	return fmt.Sprintf("line %d (%s)", r.Line, NormalizeSerial(r.Serial))
}

func ReportRowFromAudit(entry AuditEntry) ReportRow {
	return ReportRow{
		Sequence: fmt.Sprintf("%d", entry.Sequence),
		Time:     entry.RecordedAt,
		Actor:    entry.Actor,
		Action:   entry.Action,
		Entity:   entry.Entity,
		EntityID: entry.EntityID,
		Outcome:  entry.Outcome,
		Detail:   entry.Detail,
	}
}

func (d Device) FieldMap() map[string]string {
	return map[string]string{
		"id": d.ID, "serial": d.Serial, "name": d.Name, "public_key": d.PublicKey,
		"status": d.Status, "location": d.Location, "owner": d.Owner,
		"registered": d.Registered, "last_changed": d.LastChanged,
	}
}

func (e KeyEnvelope) FieldMap() map[string]string {
	active := "false"
	if e.Active {
		active = "true"
	}
	return map[string]string{
		"id": e.ID, "device_id": e.DeviceID, "version": fmt.Sprint(e.Version),
		"wrapped": e.Wrapped, "fingerprint": e.Fingerprint, "algorithm": e.Algorithm,
		"created_by": e.CreatedBy, "created_at": e.CreatedAt, "active": active,
	}
}

func (r RotationRequest) FieldMap() map[string]string {
	return map[string]string{
		"id": r.ID, "device_id": r.DeviceID, "envelope_id": r.EnvelopeID,
		"requested_by": r.RequestedBy, "reason": r.Reason, "state": r.State,
		"reviewer": r.Reviewer, "decision": r.Decision, "created_at": r.CreatedAt,
		"decided_at": r.DecidedAt,
	}
}

func (a AuditEntry) FieldMap() map[string]string {
	return map[string]string{
		"id": a.ID, "entity": a.Entity, "entity_id": a.EntityID, "action": a.Action,
		"actor": a.Actor, "outcome": a.Outcome, "detail": a.Detail,
		"sequence": fmt.Sprint(a.Sequence), "recorded_at": a.RecordedAt,
	}
}

func (b ImportBatch) FieldMap() map[string]string {
	return map[string]string{
		"id": b.ID, "source": b.Source, "operator": b.Operator, "state": b.State,
		"total": fmt.Sprint(b.Total), "succeeded": fmt.Sprint(b.Succeeded),
		"failed": fmt.Sprint(b.Failed), "created_at": b.CreatedAt,
	}
}

func SortDevices(devices []Device) []Device {
	copyOfDevices := append([]Device(nil), devices...)
	for outer := 0; outer < len(copyOfDevices); outer++ {
		for inner := outer + 1; inner < len(copyOfDevices); inner++ {
			if copyOfDevices[inner].Serial < copyOfDevices[outer].Serial {
				copyOfDevices[outer], copyOfDevices[inner] = copyOfDevices[inner], copyOfDevices[outer]
			}
		}
	}
	return copyOfDevices
}

func SortEnvelopes(envelopes []KeyEnvelope) []KeyEnvelope {
	copyOfEnvelopes := append([]KeyEnvelope(nil), envelopes...)
	for outer := 0; outer < len(copyOfEnvelopes); outer++ {
		for inner := outer + 1; inner < len(copyOfEnvelopes); inner++ {
			if copyOfEnvelopes[inner].Version < copyOfEnvelopes[outer].Version {
				copyOfEnvelopes[outer], copyOfEnvelopes[inner] = copyOfEnvelopes[inner], copyOfEnvelopes[outer]
			}
		}
	}
	return copyOfEnvelopes
}
