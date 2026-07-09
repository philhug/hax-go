package server

import "strings"

// builtinTypes is the registry of shipped HAX template types, derived from
// the hax artifact components.
var builtinTypes = []map[string]any{
	{"name": "text-approval-v1", "description": "Simple approve/deny text approval", "tags": []string{"approval", "text"}, "pack": "core"},
	{"name": "code-approval-v1", "description": "Review and approve code changes", "tags": []string{"approval", "code"}, "pack": "core"},
	{"name": "form-builder", "description": "Structured form with typed fields", "tags": []string{"form", "input"}, "pack": "core"},
	{"name": "plan-review-v2", "description": "SWE-AF plan review with issues, architecture, PRD", "tags": []string{"approval", "plan", "swe-af"}, "pack": "core"},
	{"name": "pr-af-review-v1", "description": "PR-AF review with findings, post/rerun/reject", "tags": []string{"approval", "review", "pr-af"}, "pack": "core"},
	{"name": "details", "description": "Dashboard with stats, substats, and tables", "tags": []string{"artifact", "dashboard"}, "pack": "artifacts"},
	{"name": "findings", "description": "Research findings panel with source attribution", "tags": []string{"artifact", "research"}, "pack": "artifacts"},
	{"name": "timeline", "description": "Chronological timeline of events", "tags": []string{"artifact", "timeline"}, "pack": "artifacts"},
	{"name": "thinking-process", "description": "Multi-step reasoning trace", "tags": []string{"artifact", "reasoning"}, "pack": "artifacts"},
	{"name": "contextual-explanation", "description": "Contextual explanation with highlights", "tags": []string{"artifact", "explanation"}, "pack": "artifacts"},
	{"name": "data-visualizer", "description": "Data visualization chart", "tags": []string{"artifact", "chart"}, "pack": "artifacts"},
	{"name": "mindmap", "description": "Mind map diagram", "tags": []string{"artifact", "diagram"}, "pack": "artifacts"},
	{"name": "diagnostic-report", "description": "Diagnostic report with sections", "tags": []string{"artifact", "report"}, "pack": "artifacts"},
	{"name": "source-attribution", "description": "Source attribution panel", "tags": []string{"artifact", "sources"}, "pack": "artifacts"},
	{"name": "rationale", "description": "Decision rationale panel", "tags": []string{"artifact", "rationale"}, "pack": "artifacts"},
	{"name": "inline-rationale", "description": "Inline rationale annotation", "tags": []string{"artifact", "rationale"}, "pack": "artifacts"},
	{"name": "capability-manifest", "description": "Agent capability manifest", "tags": []string{"artifact", "manifest"}, "pack": "artifacts"},
	{"name": "workshop-card", "description": "Workshop card with actions", "tags": []string{"artifact", "card"}, "pack": "artifacts"},
	{"name": "code-editor", "description": "Interactive code editor", "tags": []string{"artifact", "code"}, "pack": "artifacts"},
}

func filterTypes(q string, tags []string, pack string, limit int) []map[string]any {
	result := make([]map[string]any, 0, len(builtinTypes))
	for _, t := range builtinTypes {
		if q != "" {
			name, _ := t["name"].(string)
			desc, _ := t["description"].(string)
			if !containsCI(name, q) && !containsCI(desc, q) {
				continue
			}
		}
		if pack != "" {
			p, _ := t["pack"].(string)
			if p != pack {
				continue
			}
		}
		if len(tags) > 0 {
			tTags := getTags(t)
			if !hasAnyTag(tTags, tags) {
				continue
			}
		}
		result = append(result, t)
	}
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result
}

func getTags(t map[string]any) []string {
	if raw, ok := t["tags"].([]string); ok {
		return raw
	}
	if raw, ok := t["tags"].([]any); ok {
		tags := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				tags = append(tags, s)
			}
		}
		return tags
	}
	return nil
}

func hasAnyTag(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
