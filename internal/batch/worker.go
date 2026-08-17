package batch

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"scanvault/internal/model"
)

type Queue struct {
	items []model.ScanRecord
}

func NewQueue(records []model.ScanRecord) *Queue {
	copyOfRecords := append([]model.ScanRecord(nil), records...)
	sort.SliceStable(copyOfRecords, func(i, j int) bool { return copyOfRecords[i].Line < copyOfRecords[j].Line })
	return &Queue{items: copyOfRecords}
}

func (q *Queue) Empty() bool {
	return q == nil || len(q.items) == 0
}

func (q *Queue) Size() int {
	if q == nil {
		return 0
	}
	return len(q.items)
}

func (q *Queue) Next() (model.ScanRecord, error) {
	if q == nil || len(q.items) == 0 {
		return model.ScanRecord{}, errors.New("queue is empty")
	}
	value := q.items[0]
	q.items = q.items[1:]
	return value, nil
}

func ParseDelimited(lines []string, separator string) ([]model.ScanRecord, error) {
	if separator == "" {
		return nil, errors.New("separator is required")
	}
	result := make([]model.ScanRecord, 0, len(lines))
	for index, line := range lines {
		fields := strings.Split(line, separator)
		if len(fields) != 5 {
			return nil, fmt.Errorf("line %d has %d fields", index+1, len(fields))
		}
		result = append(result, model.ScanRecord{
			Line:       index + 1,
			Serial:     strings.TrimSpace(fields[0]),
			DeviceID:   strings.TrimSpace(fields[1]),
			PrivateKey: strings.TrimSpace(fields[2]),
			Ciphertext: strings.TrimSpace(fields[3]),
			Operator:   strings.TrimSpace(fields[4]),
		})
	}
	return result, nil
}

func Summarize(results []model.ImportResult) string {
	return fmt.Sprintf("accepted=%d rejected=%d total=%d", CountAccepted(results), CountRejected(results), len(results))
}

func ValidateLines(records []model.ScanRecord) []error {
	errorsFound := make([]error, 0)
	for _, record := range records {
		if err := model.ValidateImportRecord(record); err != nil {
			errorsFound = append(errorsFound, fmt.Errorf("line %d: %w", record.Line, err))
		}
	}
	return errorsFound
}

func GroupBySerial(records []model.ScanRecord) map[string][]model.ScanRecord {
	result := make(map[string][]model.ScanRecord)
	for _, record := range records {
		key := model.NormalizeSerial(record.Serial)
		if key == "" {
			key = record.DeviceID
		}
		result[key] = append(result[key], record)
	}
	return result
}

func SortResults(results []model.ImportResult) []model.ImportResult {
	copyOfResults := append([]model.ImportResult(nil), results...)
	sort.SliceStable(copyOfResults, func(i, j int) bool { return copyOfResults[i].Line < copyOfResults[j].Line })
	return copyOfResults
}

func StatusCounts(results []model.ImportResult) map[string]int {
	counts := make(map[string]int)
	for _, result := range results {
		counts[result.Status]++
	}
	return counts
}

func FormatErrors(results []model.ImportResult) string {
	parts := make([]string, 0)
	for _, result := range results {
		if result.Status != "accepted" {
			parts = append(parts, result.LineLabel()+": "+result.Message)
		}
	}
	return strings.Join(parts, "; ")
}

func CloneRecords(records []model.ScanRecord) []model.ScanRecord {
	copyOfRecords := make([]model.ScanRecord, len(records))
	copy(copyOfRecords, records)
	return copyOfRecords
}

func FindRecord(records []model.ScanRecord, line int) (model.ScanRecord, error) {
	for _, record := range records {
		if record.Line == line {
			return record, nil
		}
	}
	return model.ScanRecord{}, fmt.Errorf("line %d was not found", line)
}

func ReplaceRecord(records []model.ScanRecord, replacement model.ScanRecord) ([]model.ScanRecord, error) {
	copyOfRecords := CloneRecords(records)
	for index, record := range copyOfRecords {
		if record.Line == replacement.Line {
			copyOfRecords[index] = replacement
			return copyOfRecords, nil
		}
	}
	return nil, fmt.Errorf("line %d was not found", replacement.Line)
}

func RemoveRejected(records []model.ScanRecord, results []model.ImportResult) []model.ScanRecord {
	rejected := make(map[int]bool)
	for _, result := range results {
		if result.Status != "accepted" {
			rejected[result.Line] = true
		}
	}
	filtered := make([]model.ScanRecord, 0, len(records))
	for _, record := range records {
		if !rejected[record.Line] {
			filtered = append(filtered, record)
		}
	}
	return filtered
}
