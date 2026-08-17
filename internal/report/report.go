package report

import (
	"fmt"
	"sort"
	"strings"

	"scanvault/internal/audit"
	"scanvault/internal/model"
)

type Builder struct {
	Title string
}

func NewBuilder(title string) *Builder {
	if strings.TrimSpace(title) == "" {
		title = "ScanVault audit export"
	}
	return &Builder{Title: title}
}

func (b *Builder) Rows(entries []model.AuditEntry) []model.ReportRow {
	ordered := append([]model.AuditEntry(nil), entries...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Sequence < ordered[j].Sequence })
	rows := make([]model.ReportRow, 0, len(ordered))
	for _, entry := range ordered {
		rows = append(rows, model.ReportRow{
			Sequence: fmt.Sprintf("%d", entry.Sequence),
			Time:     entry.RecordedAt,
			Actor:    entry.Actor,
			Action:   entry.Action,
			Entity:   entry.Entity,
			EntityID: entry.EntityID,
			Outcome:  entry.Outcome,
			Detail:   entry.Detail,
		})
	}
	return rows
}

func (b *Builder) FilteredRows(entries []model.AuditEntry, query audit.Query) []model.ReportRow {
	return b.Rows(audit.Search(entries, query))
}

func (b *Builder) Summary(entries []model.AuditEntry) string {
	accepted := 0
	rejected := 0
	for _, entry := range entries {
		if entry.Outcome == "accepted" || entry.Outcome == "pending" {
			accepted++
		} else {
			rejected++
		}
	}
	return fmt.Sprintf("%s: total=%d accepted=%d other=%d", b.Title, len(entries), accepted, rejected)
}
