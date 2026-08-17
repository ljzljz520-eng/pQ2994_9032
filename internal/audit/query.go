package audit

import (
	"sort"
	"strings"

	"scanvault/internal/model"
)

type Query struct {
	Entity   string
	EntityID string
	Actor    string
	Action   string
	Outcome  string
	Contains string
}

func Match(entry model.AuditEntry, query Query) bool {
	if query.Entity != "" && entry.Entity != query.Entity {
		return false
	}
	if query.EntityID != "" && entry.EntityID != query.EntityID {
		return false
	}
	if query.Actor != "" && entry.Actor != query.Actor {
		return false
	}
	if query.Action != "" && entry.Action != query.Action {
		return false
	}
	if query.Outcome != "" && entry.Outcome != query.Outcome {
		return false
	}
	if query.Contains != "" && !strings.Contains(strings.ToLower(entry.Detail), strings.ToLower(query.Contains)) {
		return false
	}
	return true
}

func Search(entries []model.AuditEntry, query Query) []model.AuditEntry {
	result := make([]model.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		if Match(entry, query) {
			result = append(result, entry)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Sequence < result[j].Sequence })
	return result
}

func Summaries(entries []model.AuditEntry) []string {
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Summary())
	}
	return result
}

func GroupByEntity(entries []model.AuditEntry) map[string][]model.AuditEntry {
	result := make(map[string][]model.AuditEntry)
	for _, entry := range entries {
		result[entry.Entity] = append(result[entry.Entity], entry)
	}
	for key := range result {
		sort.SliceStable(result[key], func(i, j int) bool { return result[key][i].Sequence < result[key][j].Sequence })
	}
	return result
}

func OutcomeCounts(entries []model.AuditEntry) map[string]int {
	result := make(map[string]int)
	for _, entry := range entries {
		result[entry.Outcome]++
	}
	return result
}

func LatestByEntity(entries []model.AuditEntry) map[string]model.AuditEntry {
	result := make(map[string]model.AuditEntry)
	for _, entry := range entries {
		current, exists := result[entry.Entity+"|"+entry.EntityID]
		if !exists || entry.Sequence > current.Sequence {
			result[entry.Entity+"|"+entry.EntityID] = entry
		}
	}
	return result
}

func ActionNames(entries []model.AuditEntry) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, entry := range entries {
		if !seen[entry.Action] {
			seen[entry.Action] = true
			result = append(result, entry.Action)
		}
	}
	sort.Strings(result)
	return result
}
