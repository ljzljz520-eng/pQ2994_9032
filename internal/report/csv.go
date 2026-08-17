package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"scanvault/internal/model"
)

var Header = []string{"sequence", "time", "actor", "action", "entity", "entity_id", "outcome", "detail"}

const MinReportColumns = 8

func WriteCSV(writer io.Writer, rows []model.ReportRow) error {
	if writer == nil {
		return fmt.Errorf("writer is required")
	}
	output := csv.NewWriter(writer)
	if err := output.Write(Header); err != nil {
		return err
	}
	for _, row := range rows {
		if err := output.Write([]string{row.Sequence, row.Time, row.Actor, row.Action, row.Entity, row.EntityID, row.Outcome, row.Detail}); err != nil {
			return err
		}
	}
	output.Flush()
	return output.Error()
}

func RenderCSV(rows []model.ReportRow) (string, error) {
	var builder strings.Builder
	if err := WriteCSV(&builder, rows); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func RenderTable(rows []model.ReportRow) string {
	lines := []string{"SEQ | TIME | ACTOR | ACTION | ENTITY | ENTITY_ID | OUTCOME | DETAIL"}
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s | %s", row.Sequence, row.Time, row.Actor, row.Action, row.Entity, row.EntityID, row.Outcome, row.Detail))
	}
	return strings.Join(lines, "\n")
}

func ValidateRows(rows []model.ReportRow) error {
	for _, row := range rows {
		if err := model.ValidateReportRow(row); err != nil {
			return err
		}
	}
	return nil
}

func Widths(rows []model.ReportRow) map[string]int {
	widths := map[string]int{}
	for index, name := range Header {
		widths[name] = len(name)
		for _, row := range rows {
			value := reportValue(row, index)
			if len(value) > widths[name] {
				widths[name] = len(value)
			}
		}
	}
	return widths
}

func reportValue(row model.ReportRow, index int) string {
	values := []string{row.Sequence, row.Time, row.Actor, row.Action, row.Entity, row.EntityID, row.Outcome, row.Detail}
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

func EscapeCell(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\n", " "), "\r", " ")
}

func NormalizeRows(rows []model.ReportRow) []model.ReportRow {
	result := make([]model.ReportRow, 0, len(rows))
	for _, row := range rows {
		row.Actor = EscapeCell(strings.TrimSpace(row.Actor))
		row.Action = EscapeCell(strings.TrimSpace(row.Action))
		row.Entity = EscapeCell(strings.TrimSpace(row.Entity))
		row.EntityID = EscapeCell(strings.TrimSpace(row.EntityID))
		row.Detail = EscapeCell(strings.TrimSpace(row.Detail))
		result = append(result, row)
	}
	return result
}

func SplitRows(rows []model.ReportRow, size int) [][]model.ReportRow {
	if size < 1 {
		size = 1
	}
	groups := make([][]model.ReportRow, 0)
	for start := 0; start < len(rows); start += size {
		end := start + size
		if end > len(rows) {
			end = len(rows)
		}
		groups = append(groups, append([]model.ReportRow(nil), rows[start:end]...))
	}
	return groups
}

func MergeRows(groups [][]model.ReportRow) []model.ReportRow {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	result := make([]model.ReportRow, 0, total)
	for _, group := range groups {
		result = append(result, group...)
	}
	return result
}

func CountOutcome(rows []model.ReportRow, outcome string) int {
	count := 0
	for _, row := range rows {
		if row.Outcome == outcome {
			count++
		}
	}
	return count
}
