package store

const (
	DevicesBucket   = "devices"
	EnvelopesBucket = "key_envelopes"
	RotationsBucket = "rotation_requests"
	AuditsBucket    = "audit_entries"
	BatchesBucket   = "import_batches"
	MetaBucket      = "metadata"
)

func bucketNames() []string {
	return []string{
		DevicesBucket,
		EnvelopesBucket,
		RotationsBucket,
		AuditsBucket,
		BatchesBucket,
		MetaBucket,
	}
}

func bucketForEntity(entity string) string {
	switch entity {
	case "Device":
		return DevicesBucket
	case "KeyEnvelope":
		return EnvelopesBucket
	case "RotationRequest":
		return RotationsBucket
	case "AuditEntry":
		return AuditsBucket
	case "ImportBatch":
		return BatchesBucket
	default:
		return ""
	}
}

func EntityBuckets() map[string]string {
	result := make(map[string]string, 5)
	for _, entity := range []string{"Device", "KeyEnvelope", "RotationRequest", "AuditEntry", "ImportBatch"} {
		result[entity] = bucketForEntity(entity)
	}
	return result
}
