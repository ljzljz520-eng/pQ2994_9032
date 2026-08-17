package store

import (
	"errors"
	"fmt"
	"sort"
	"strconv"

	"go.etcd.io/bbolt"
	"scanvault/internal/model"
)

func saveJSON[T any](s *Store, bucket, key string, value T) error {
	data, err := model.Encode(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", bucket, err)
	}
	return s.Put(bucket, key, data)
}

func loadJSON[T any](s *Store, bucket, key string) (T, error) {
	var zero T
	data, err := s.Get(bucket, key)
	if err != nil {
		return zero, err
	}
	var value T
	if err := model.Decode(data, &value); err != nil {
		return zero, err
	}
	return value, nil
}

func SaveDevice(s *Store, device model.Device) error {
	if err := model.ValidateDevice(device); err != nil {
		return err
	}
	return saveJSON(s, DevicesBucket, device.ID, device)
}

func GetDevice(s *Store, id string) (model.Device, error) {
	if id == "" {
		return model.Device{}, errors.New("device id is required")
	}
	return loadJSON[model.Device](s, DevicesBucket, id)
}

func FindDeviceBySerial(s *Store, serial string) (model.Device, error) {
	serial = model.NormalizeSerial(serial)
	if serial == "" {
		return model.Device{}, errors.New("serial is required")
	}
	devices, err := ListDevices(s)
	if err != nil {
		return model.Device{}, err
	}
	for _, device := range devices {
		if model.NormalizeSerial(device.Serial) == serial {
			return device, nil
		}
	}
	return model.Device{}, ErrNotFound
}

func ListDevices(s *Store) ([]model.Device, error) {
	var devices []model.Device
	err := s.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(DevicesBucket))
		return bucket.ForEach(func(_, value []byte) error {
			if value == nil {
				return nil
			}
			var device model.Device
			if err := model.Decode(value, &device); err != nil {
				return err
			}
			devices = append(devices, device)
			return nil
		})
	})
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	return devices, err
}

func SaveEnvelope(s *Store, envelope model.KeyEnvelope) error {
	if err := model.ValidateEnvelope(envelope); err != nil {
		return err
	}
	return saveJSON(s, EnvelopesBucket, envelope.ID, envelope)
}

func GetEnvelope(s *Store, id string) (model.KeyEnvelope, error) {
	if id == "" {
		return model.KeyEnvelope{}, errors.New("envelope id is required")
	}
	return loadJSON[model.KeyEnvelope](s, EnvelopesBucket, id)
}

func ListEnvelopesForDevice(s *Store, deviceID string) ([]model.KeyEnvelope, error) {
	var values []model.KeyEnvelope
	err := eachJSON(s, EnvelopesBucket, func(value model.KeyEnvelope) bool {
		if value.DeviceID == deviceID {
			values = append(values, value)
		}
		return true
	})
	sort.Slice(values, func(i, j int) bool { return values[i].Version < values[j].Version })
	return values, err
}

func DeactivateEnvelopes(s *Store, deviceID string) (int, error) {
	envelopes, err := ListEnvelopesForDevice(s, deviceID)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, envelope := range envelopes {
		if envelope.Active {
			envelope.Active = false
			if err := SaveEnvelope(s, envelope); err != nil {
				return changed, err
			}
			changed++
		}
	}
	return changed, nil
}

func ActiveEnvelope(s *Store, deviceID string) (model.KeyEnvelope, error) {
	envelopes, err := ListEnvelopesForDevice(s, deviceID)
	if err != nil {
		return model.KeyEnvelope{}, err
	}
	for index := len(envelopes) - 1; index >= 0; index-- {
		if envelopes[index].Active {
			return envelopes[index], nil
		}
	}
	return model.KeyEnvelope{}, ErrNotFound
}

func SaveRotation(s *Store, request model.RotationRequest) error {
	if err := model.ValidateRotation(request); err != nil {
		return err
	}
	return saveJSON(s, RotationsBucket, request.ID, request)
}

func GetRotation(s *Store, id string) (model.RotationRequest, error) {
	if id == "" {
		return model.RotationRequest{}, errors.New("rotation id is required")
	}
	return loadJSON[model.RotationRequest](s, RotationsBucket, id)
}

func ListRotations(s *Store) ([]model.RotationRequest, error) {
	var values []model.RotationRequest
	err := eachJSON(s, RotationsBucket, func(value model.RotationRequest) bool {
		values = append(values, value)
		return true
	})
	sort.SliceStable(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, err
}

func ListPendingRotations(s *Store) ([]model.RotationRequest, error) {
	values, err := ListRotations(s)
	if err != nil {
		return nil, err
	}
	pending := make([]model.RotationRequest, 0, len(values))
	for _, value := range values {
		if value.State == "pending" {
			pending = append(pending, value)
		}
	}
	return pending, nil
}

func SaveBatch(s *Store, batch model.ImportBatch) error {
	if batch.ID == "" || batch.Total < 0 {
		return errors.New("batch is incomplete")
	}
	return saveJSON(s, BatchesBucket, batch.ID, batch)
}

func GetBatch(s *Store, id string) (model.ImportBatch, error) {
	return loadJSON[model.ImportBatch](s, BatchesBucket, id)
}

func ListBatches(s *Store) ([]model.ImportBatch, error) {
	var values []model.ImportBatch
	err := eachJSON(s, BatchesBucket, func(value model.ImportBatch) bool {
		values = append(values, value)
		return true
	})
	sort.SliceStable(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values, err
}

func UpdateBatch(s *Store, id, state string, succeeded, failed int) (model.ImportBatch, error) {
	value, err := GetBatch(s, id)
	if err != nil {
		return model.ImportBatch{}, err
	}
	value.State = state
	value.Succeeded = succeeded
	value.Failed = failed
	if err := model.ValidateBatch(value); err != nil {
		return model.ImportBatch{}, err
	}
	if err := SaveBatch(s, value); err != nil {
		return model.ImportBatch{}, err
	}
	return value, nil
}

func FindBatchBySource(s *Store, source string) (model.ImportBatch, error) {
	values, err := ListBatches(s)
	if err != nil {
		return model.ImportBatch{}, err
	}
	for _, value := range values {
		if value.Source == source {
			return value, nil
		}
	}
	return model.ImportBatch{}, ErrNotFound
}

func CountEntities(s *Store) (map[string]int, error) {
	counts := make(map[string]int)
	for entity, bucket := range EntityBuckets() {
		var count int
		err := s.View(func(tx *bbolt.Tx) error {
			value := tx.Bucket([]byte(bucket))
			if value == nil {
				return fmt.Errorf("bucket %s does not exist", bucket)
			}
			return value.ForEach(func(key, raw []byte) error {
				if key != nil && raw != nil {
					count++
				}
				return nil
			})
		})
		if err != nil {
			return nil, err
		}
		counts[entity] = count
	}
	return counts, nil
}

func CopyStoreValue(s *Store, fromBucket, fromKey, toBucket, toKey string) error {
	value, err := s.Get(fromBucket, fromKey)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return errors.New("source value is empty")
	}
	return s.Put(toBucket, toKey, value)
}

func SaveAudit(s *Store, entry model.AuditEntry) error {
	if err := model.ValidateAudit(entry); err != nil {
		return err
	}
	return saveJSON(s, AuditsBucket, auditKey(entry.Sequence, entry.ID), entry)
}

func auditKey(sequence int64, id string) string {
	return fmt.Sprintf("%020d-%s", sequence, id)
}

func ListAudits(s *Store) ([]model.AuditEntry, error) {
	var entries []model.AuditEntry
	err := eachJSON(s, AuditsBucket, func(value model.AuditEntry) bool {
		entries = append(entries, value)
		return true
	})
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Sequence == entries[j].Sequence {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Sequence < entries[j].Sequence
	})
	return entries, err
}

func NextSequence(s *Store) (int64, error) {
	var next int64
	err := s.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(MetaBucket))
		current := bucket.Get([]byte("audit_sequence"))
		if len(current) > 0 {
			parsed, err := strconv.ParseInt(string(current), 10, 64)
			if err != nil {
				return err
			}
			next = parsed + 1
		} else {
			next = 1
		}
		return bucket.Put([]byte("audit_sequence"), []byte(strconv.FormatInt(next, 10)))
	})
	return next, err
}

func eachJSON[T any](s *Store, bucketName string, visit func(T) bool) error {
	return s.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket %s does not exist", bucketName)
		}
		return bucket.ForEach(func(_, raw []byte) error {
			if raw == nil {
				return nil
			}
			var value T
			if err := model.Decode(raw, &value); err != nil {
				return err
			}
			if !visit(value) {
				return errors.New("iteration stopped")
			}
			return nil
		})
	})
}
