package batch

import (
	"errors"
	"fmt"
	"strings"

	"scanvault/internal/model"
	"scanvault/internal/service"
	"scanvault/internal/store"
)

type Importer struct {
	Service *service.Service
}

func NewImporter(application *service.Service) *Importer {
	return &Importer{Service: application}
}

func (i *Importer) Import(records []model.ScanRecord, source, operator string) (model.ImportBatch, []model.ImportResult, error) {
	if i == nil || i.Service == nil {
		return model.ImportBatch{}, nil, errors.New("import service is required")
	}
	if err := i.Service.ValidateOperator(operator); err != nil {
		return model.ImportBatch{}, nil, err
	}
	if strings.TrimSpace(source) == "" {
		return model.ImportBatch{}, nil, errors.New("source is required")
	}
	batch := model.ImportBatch{
		ID:        i.Service.StorePath() + "|" + source,
		Source:    source,
		Operator:  operator,
		State:     "processing",
		Total:     len(records),
		CreatedAt: i.Service.Stamp,
	}
	if err := store.SaveBatch(i.Service.Store, batch); err != nil {
		return model.ImportBatch{}, nil, err
	}
	results := make([]model.ImportResult, 0, len(records))
	for _, record := range records {
		// Acquiring and releasing the record slot is scoped to a single record so
		// the slot is freed before the next record is read. Deferring release inside
		// the loop would hold every slot until Import returned and exhaust the pool
		// after the first record, so the work happens in processRecordWithSlot.
		result, err := i.processRecordWithSlot(record, operator)
		if err != nil {
			batch.Failed++
			results = append(results, result)
			_ = store.SaveBatch(i.Service.Store, batch)
			return batch, results, err
		}
		results = append(results, result)
		if result.Status == "accepted" {
			batch.Succeeded++
		} else {
			batch.Failed++
		}
	}
	if batch.Failed == 0 {
		batch.State = "completed"
	} else {
		batch.State = "completed_with_errors"
	}
	if err := store.SaveBatch(i.Service.Store, batch); err != nil {
		return batch, results, err
	}
	return batch, results, nil
}

// processRecordWithSlot acquires a record slot, processes a single record, and
// releases the slot before returning. Because release runs at the end of this
// method (not at the end of Import), each record frees its resources immediately
// after it completes, so the next record can acquire its slot.
func (i *Importer) processRecordWithSlot(record model.ScanRecord, operator string) (model.ImportResult, error) {
	release, err := i.Service.OpenRecord()
	if err != nil {
		return model.ImportResult{Line: record.Line, Serial: record.Serial, Status: "failed", Message: err.Error()}, fmt.Errorf("import line %d: %w", record.Line, err)
	}
	defer release()
	return i.processRecord(record, operator), nil
}

func (i *Importer) processRecord(record model.ScanRecord, operator string) model.ImportResult {
	result := model.ImportResult{Line: record.Line, Serial: record.Serial, Status: "failed"}
	if err := model.ValidateImportRecord(record); err != nil {
		result.Message = err.Error()
		return result
	}
	device, err := store.FindDeviceBySerial(i.Service.Store, record.Serial)
	if err != nil {
		result.Message = fmt.Sprintf("find device: %v", err)
		return result
	}
	envelope, err := i.Service.CurrentEnvelope(device.ID)
	if err != nil {
		result.Message = fmt.Sprintf("find envelope: %v", err)
		return result
	}
	secret, err := i.Service.Sealer.OpenCommunicationSecret(record.PrivateKey, device.PublicKey, record.Ciphertext)
	if err != nil {
		result.Message = fmt.Sprintf("recover secret: %v", err)
		return result
	}
	if !i.Service.Sealer.VerifyFingerprint(device.PublicKey, secret, envelope.Fingerprint) {
		result.Message = "secret fingerprint mismatch"
		return result
	}
	if _, err := i.Service.Audit.Record("ImportBatch", record.Serial, "recover", operator, "accepted", envelope.ID); err != nil {
		result.Message = err.Error()
		return result
	}
	result.Status = "accepted"
	result.Envelope = envelope.ID
	result.Message = "secret recovered"
	return result
}

func CountAccepted(results []model.ImportResult) int {
	count := 0
	for _, result := range results {
		if result.Status == "accepted" {
			count++
		}
	}
	return count
}

func CountRejected(results []model.ImportResult) int {
	count := 0
	for _, result := range results {
		if result.Status != "accepted" {
			count++
		}
	}
	return count
}
