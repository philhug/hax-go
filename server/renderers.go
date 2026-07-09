package server

import (
	"fmt"
	"strings"
)

// --- plan-review-v2 renderer ---
// Payload: {planSummary, issues: [{name, title, description, dependsOn,
//   filesToModify, filesToCreate, acceptanceCriteria}], architecture (markdown),
//   prd (markdown), metadata, revisionNumber, revisionHistory}
// Response: {decision: "approve"|"request_changes", feedback: "..."}

func renderPlanReviewForm(req *storedRequest) string {
	var sb strings.Builder

	planSummary, _ := req.Payload["planSummary"].(string)
	prd, _ := req.Payload["prd"].(string)
	architecture, _ := req.Payload["architecture"].(string)
	issues, _ := req.Payload["issues"].([]any)
	revisionNumber := 0
	if rn, ok := req.Payload["revisionNumber"]; ok {
		revisionNumber = int(toInt64(rn))
	}

	// Revision banner.
	if revisionNumber > 0 {
		sb.WriteString(`<div class="status-banner held">`)
		sb.WriteString(fmt.Sprintf("Revision %d — previous feedback requested changes", revisionNumber))
		sb.WriteString(`</div>`)

		// Revision history.
		if history, ok := req.Payload["revisionHistory"].([]any); ok && len(history) > 0 {
			sb.WriteString(`<div class="payload-section"><h2>Revision History</h2>`)
			for _, h := range history {
				if entry, ok := h.(map[string]any); ok {
					iter, _ := entry["iteration"].(float64)
					feedback, _ := entry["feedback"].(string)
					sb.WriteString(fmt.Sprintf(`<div class="revision-entry"><span class="meta-label">Revision %d feedback:</span> %s</div>`,
						int(iter), escapeHTML(feedback)))
				}
			}
			sb.WriteString(`</div>`)
		}
	}

	// Plan summary.
	if planSummary != "" {
		sb.WriteString(`<div class="payload-section">
<h2>Plan Summary</h2>
<div class="payload-text">`)
		sb.WriteString(escapeHTML(planSummary))
		sb.WriteString(`</div>
</div>`)
	}

	// PRD markdown.
	if prd != "" {
		sb.WriteString(`<div class="payload-section">
<h2>PRD</h2>
<div class="payload-markdown">`)
		sb.WriteString(renderMarkdown(prd))
		sb.WriteString(`</div>
</div>`)
	}

	// Architecture markdown.
	if architecture != "" {
		sb.WriteString(`<div class="payload-section">
<h2>Architecture</h2>
<div class="payload-markdown">`)
		sb.WriteString(renderMarkdown(architecture))
		sb.WriteString(`</div>
</div>`)
	}

	// Issues list.
	if len(issues) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="payload-section">
<h2>Issues (%d)</h2>`, len(issues)))
		for i, issue := range issues {
			issueMap, ok := issue.(map[string]any)
			if !ok {
				continue
			}
			name, _ := issueMap["name"].(string)
			title, _ := issueMap["title"].(string)
			desc, _ := issueMap["description"].(string)
			dependsOn, _ := issueMap["dependsOn"].([]any)
			filesToModify, _ := issueMap["filesToModify"].([]any)
			filesToCreate, _ := issueMap["filesToCreate"].([]any)
			acceptance, _ := issueMap["acceptanceCriteria"].([]any)

			sb.WriteString(fmt.Sprintf(`<div class="issue-card">
<div class="issue-header">
<span class="issue-num">#%d</span>
<span class="issue-name">%s</span>
</div>`, i+1, escapeHTML(name)))
			if title != "" {
				sb.WriteString(fmt.Sprintf(`<div class="issue-title">%s</div>`, escapeHTML(title)))
			}
			if desc != "" {
				sb.WriteString(fmt.Sprintf(`<div class="issue-desc">%s</div>`, escapeHTML(desc)))
			}
			if len(dependsOn) > 0 {
				sb.WriteString(`<div class="issue-meta"><span class="meta-label">Depends on:</span> `)
				parts := make([]string, 0, len(dependsOn))
				for _, d := range dependsOn {
					if s, ok := d.(string); ok {
						parts = append(parts, escapeHTML(s))
					}
				}
				sb.WriteString(strings.Join(parts, ", "))
				sb.WriteString(`</div>`)
			}
			if len(filesToModify) > 0 {
				sb.WriteString(`<div class="issue-meta"><span class="meta-label">Modify:</span> `)
				for j, f := range filesToModify {
					if s, ok := f.(string); ok {
						if j > 0 {
							sb.WriteString(", ")
						}
						sb.WriteString(fmt.Sprintf(`<code class="file-tag">%s</code>`, escapeHTML(s)))
					}
				}
				sb.WriteString(`</div>`)
			}
			if len(filesToCreate) > 0 {
				sb.WriteString(`<div class="issue-meta"><span class="meta-label">Create:</span> `)
				for j, f := range filesToCreate {
					if s, ok := f.(string); ok {
						if j > 0 {
							sb.WriteString(", ")
						}
						sb.WriteString(fmt.Sprintf(`<code class="file-tag">%s</code>`, escapeHTML(s)))
					}
				}
				sb.WriteString(`</div>`)
			}
			if len(acceptance) > 0 {
				sb.WriteString(`<div class="issue-ac"><span class="meta-label">Acceptance Criteria:</span><ul>`)
				for _, a := range acceptance {
					if s, ok := a.(string); ok {
						sb.WriteString(fmt.Sprintf(`<li>%s</li>`, escapeHTML(s)))
					}
				}
				sb.WriteString(`</ul></div>`)
			}
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</div>`)
	}

	// Response form: approve / request changes + feedback.
	sb.WriteString(`<form method="POST" action="">
<div class="form-group">
<label for="feedback">Feedback</label>
<textarea id="feedback" name="feedback" placeholder="Provide feedback or instructions for changes..." rows="4"></textarea>
</div>
<div class="btn-row">
<button type="submit" name="decision" value="approve" class="btn btn-approve">Approve Plan</button>
<button type="submit" name="decision" value="request_changes" class="btn btn-deny">Request Changes</button>
</div>
</form>`)

	return sb.String()
}

// --- pr-af-review-v1 renderer ---
// Payload: {title, intent, reviewSummary, findings: [{id, severity, title,
//   defaultSelected, filePath, lineStart, lineEnd, body, suggestion, dimension,
//   confidence}], postLabel, rerunLabel, rejectLabel, instructionsPlaceholder, pr, revision}
// Response: {action: "post_selected"|"rerun"|"reject", findings_to_post: [...], instructions: "..."}

func renderPraFReviewForm(req *storedRequest) string {
	var sb strings.Builder

	intent, _ := req.Payload["intent"].(string)
	reviewSummary, _ := req.Payload["reviewSummary"].(string)
	findings, _ := req.Payload["findings"].([]any)
	postLabel, _ := req.Payload["postLabel"].(string)
	if postLabel == "" {
		postLabel = "Post Selected"
	}
	rerunLabel, _ := req.Payload["rerunLabel"].(string)
	if rerunLabel == "" {
		rerunLabel = "Re-review with Instructions"
	}
	rejectLabel, _ := req.Payload["rejectLabel"].(string)
	if rejectLabel == "" {
		rejectLabel = "Reject"
	}
	instructionsPlaceholder, _ := req.Payload["instructionsPlaceholder"].(string)
	if instructionsPlaceholder == "" {
		instructionsPlaceholder = "Instructions for re-review..."
	}

	// Revision info.
	if rev, ok := req.Payload["revision"].(map[string]any); ok {
		iter, _ := rev["iteration"].(float64)
		prior, _ := rev["priorInstructions"].([]any)
		if len(prior) > 0 {
			sb.WriteString(`<div class="status-banner held">`)
			sb.WriteString(fmt.Sprintf("Revision %d — %d prior instruction(s)", int(iter), len(prior)))
			sb.WriteString(`</div>`)
		}
	}

	// Intent.
	if intent != "" {
		sb.WriteString(`<div class="payload-section">
<h2>PR Intent</h2>
<div class="payload-markdown">`)
		sb.WriteString(renderMarkdown(intent))
		sb.WriteString(`</div>
</div>`)
	}

	// Review summary.
	if reviewSummary != "" {
		sb.WriteString(fmt.Sprintf(`<div class="payload-section">
<h2>Review Summary</h2>
<div class="payload-text">%s</div>
</div>`, escapeHTML(reviewSummary)))
	}

	// Findings.
	if len(findings) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="payload-section">
<h2>Findings (%d)</h2>`, len(findings)))
		for _, f := range findings {
			finding, ok := f.(map[string]any)
			if !ok {
				continue
			}
			id, _ := finding["id"].(string)
			severity, _ := finding["severity"].(string)
			title, _ := finding["title"].(string)
			filePath, _ := finding["filePath"].(string)
			lineStart, _ := finding["lineStart"].(float64)
			lineEnd, _ := finding["lineEnd"].(float64)
			body, _ := finding["body"].(string)
			suggestion, _ := finding["suggestion"].(string)
			dimension, _ := finding["dimension"].(string)
			confidence, _ := finding["confidence"].(float64)
			defaultSelected, _ := finding["defaultSelected"].(bool)
			checked := ""
			if defaultSelected {
				checked = " checked"
			}

			severityClass := severityColorClass(severity)

			sb.WriteString(fmt.Sprintf(`<div class="finding-card">
<div class="finding-header">
<label class="finding-check">
<input type="checkbox" name="findings_to_post" value="%s"%s>
</label>
<span class="finding-severity %s">%s</span>
<span class="finding-title">%s</span>
</div>`,
				escapeHTML(id), checked,
				severityClass, escapeHTML(severity),
				escapeHTML(title)))

			if filePath != "" {
				loc := escapeHTML(filePath)
				if lineStart > 0 {
					loc += fmt.Sprintf(":%d", int(lineStart))
					if lineEnd > 0 && lineEnd != lineStart {
						loc += fmt.Sprintf("-%d", int(lineEnd))
					}
				}
				sb.WriteString(fmt.Sprintf(`<div class="finding-meta"><code class="file-tag">%s</code></div>`, loc))
			}
			if dimension != "" {
				sb.WriteString(fmt.Sprintf(`<div class="finding-meta"><span class="meta-label">Dimension:</span> %s</div>`, escapeHTML(dimension)))
			}
			if confidence > 0 {
				sb.WriteString(fmt.Sprintf(`<div class="finding-meta"><span class="meta-label">Confidence:</span> %.0f%%</div>`, confidence*100))
			}
			if body != "" {
				sb.WriteString(fmt.Sprintf(`<div class="finding-body">%s</div>`, renderMarkdown(body)))
			}
			if suggestion != "" {
				sb.WriteString(fmt.Sprintf(`<div class="finding-suggestion"><span class="meta-label">Suggestion:</span> %s</div>`, escapeHTML(suggestion)))
			}
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</div>`)
	}

	// Response form: instructions + 3 action buttons.
	sb.WriteString(fmt.Sprintf(`<form method="POST" action="">
<div class="form-group">
<label for="instructions">Instructions (for re-review)</label>
<textarea id="instructions" name="instructions" placeholder="%s" rows="3"></textarea>
</div>
<div class="btn-row">
<button type="submit" name="action" value="post_selected" class="btn btn-approve">%s</button>
<button type="submit" name="action" value="rerun" class="btn btn-secondary">%s</button>
<button type="submit" name="action" value="reject" class="btn btn-deny">%s</button>
</div>
</form>`,
		escapeHTML(instructionsPlaceholder),
		escapeHTML(postLabel),
		escapeHTML(rerunLabel),
		escapeHTML(rejectLabel)))

	return sb.String()
}

// severityColorClass returns a CSS class for a severity string.
func severityColorClass(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "sev1":
		return "sev-critical"
	case "high", "sev2":
		return "sev-high"
	case "medium", "sev3":
		return "sev-medium"
	case "low", "sev4":
		return "sev-low"
	default:
		return "sev-info"
	}
}

// renderMarkdown converts basic markdown to HTML (headings, bold, code, lists).
// This is intentionally minimal — not a full markdown parser.
func renderMarkdown(s string) string {
	lines := strings.Split(s, "\n")
	var sb strings.Builder
	inList := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "### ") {
			if inList {
				sb.WriteString("</ul>")
				inList = false
			}
			sb.WriteString(fmt.Sprintf("<h4>%s</h4>", escapeHTML(trimmed[4:])))
		} else if strings.HasPrefix(trimmed, "## ") {
			if inList {
				sb.WriteString("</ul>")
				inList = false
			}
			sb.WriteString(fmt.Sprintf("<h3>%s</h3>", escapeHTML(trimmed[3:])))
		} else if strings.HasPrefix(trimmed, "# ") {
			if inList {
				sb.WriteString("</ul>")
				inList = false
			}
			sb.WriteString(fmt.Sprintf("<h3>%s</h3>", escapeHTML(trimmed[2:])))
		} else if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			if !inList {
				sb.WriteString("<ul>")
				inList = true
			}
			content := trimmed[2:]
			content = renderInlineMarkdown(content)
			sb.WriteString(fmt.Sprintf("<li>%s</li>", content))
		} else if strings.HasPrefix(trimmed, "```") {
			if inList {
				sb.WriteString("</ul>")
				inList = false
			}
			sb.WriteString("</p><pre><code>")
		} else if trimmed == "" {
			if inList {
				sb.WriteString("</ul>")
				inList = false
			}
			if sb.Len() > 0 && !strings.HasSuffix(sb.String(), "<p>") {
				sb.WriteString("</p>")
			}
			sb.WriteString("<p>")
		} else {
			if inList {
				sb.WriteString("</ul>")
				inList = false
			}
			if !strings.HasSuffix(sb.String(), "<p>") && sb.Len() == 0 {
				sb.WriteString("<p>")
			}
			content := renderInlineMarkdown(trimmed)
			if !strings.HasSuffix(sb.String(), "<p>") && !strings.HasSuffix(sb.String(), "</li>") && !strings.HasSuffix(sb.String(), "</ul>") && !strings.HasSuffix(sb.String(), "</h3>") && !strings.HasSuffix(sb.String(), "</h4>") {
				sb.WriteString("<br>")
			}
			sb.WriteString(content)
		}
	}
	if inList {
		sb.WriteString("</ul>")
	}
	if strings.HasSuffix(sb.String(), "<p>") {
		sb.WriteString("</p>")
	}
	return sb.String()
}

// renderInlineMarkdown handles bold, code, and links in a line of text.
func renderInlineMarkdown(s string) string {
	s = escapeHTML(s)
	// Bold: **text**
	s = strings.ReplaceAll(s, "**", "\x00BOLD\x00")
	parts := strings.Split(s, "\x00BOLD\x00")
	var sb strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			sb.WriteString("<strong>")
			sb.WriteString(p)
			sb.WriteString("</strong>")
		} else {
			sb.WriteString(p)
		}
	}
	// Inline code: `text`
	result := sb.String()
	result = strings.ReplaceAll(result, "`", "\x00CODE\x00")
	parts = strings.Split(result, "\x00CODE\x00")
	sb.Reset()
	for i, p := range parts {
		if i%2 == 1 {
			sb.WriteString("<code>")
			sb.WriteString(p)
			sb.WriteString("</code>")
		} else {
			sb.WriteString(p)
		}
	}
	return sb.String()
}
