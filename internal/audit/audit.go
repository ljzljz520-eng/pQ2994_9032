package audit

import (
	"fmt"
	"strings"

	"scanvault/internal/model"
	"scanvault/internal/store"
)

type Recorder struct {
	Store *store.Store
	Stamp string
}

func NewRecorder(database *store.Store, stamp string) *Recorder {
	if strings.TrimSpace(stamp) == "" {
		stamp = "static-audit-time"
	}
	return &Recorder{Store: database, Stamp: stamp}
}

func (r *Recorder) Record(entity, entityID, action, actor, outcome, detail string) (model.AuditEntry, error) {
	sequence, err := store.NextSequence(r.Store)
	if err != nil {
		return model.AuditEntry{}, fmt.Errorf("allocate audit sequence: %w", err)
	}
	entry := model.AuditEntry{
		ID:         fmt.Sprintf("audit-%06d", sequence),
		Entity:     entity,
		EntityID:   entityID,
		Action:     action,
		Actor:      actor,
		Outcome:    outcome,
		Detail:     detail,
		Sequence:   sequence,
		RecordedAt: r.Stamp,
	}
	if err := store.SaveAudit(r.Store, entry); err != nil {
		return model.AuditEntry{}, fmt.Errorf("save audit entry: %w", err)
	}
	return entry, nil
}

func (r *Recorder) List() ([]model.AuditEntry, error) {
	return store.ListAudits(r.Store)
}

func (r *Recorder) Count() (int, error) {
	entries, err := r.List()
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func Filter(entries []model.AuditEntry, entity, action, outcome string) []model.AuditEntry {
	result := make([]model.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		if entity != "" && entry.Entity != entity {
			continue
		}
		if action != "" && entry.Action != action {
			continue
		}
		if outcome != "" && entry.Outcome != outcome {
			continue
		}
		result = append(result, entry)
	}
	return result
}
