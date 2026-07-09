package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	hax "github.com/philhug/hax-go"
)

// registerUIRoutes registers the human-facing UI routes (no auth required).
func (s *Server) registerUIRoutes() {
	s.mux.HandleFunc("GET /hub/r/{id}", s.handleUIRequest)
	s.mux.HandleFunc("POST /hub/r/{id}", s.handleUIRespond)
}

// handleUIRequest renders the request page as HTML.
func (s *Server) handleUIRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.store.getAndExpire(id)
	if !ok {
		writeHTML(w, http.StatusNotFound, notFoundHTML(id))
		return
	}
	// Mark as opened when a human views it.
	if s.store.markOpened(id) {
		req, _ = s.store.get(id)
		if req != nil {
			s.dispatchWebhook("opened", req)
		}
	}
	writeHTML(w, http.StatusOK, renderRequestHTML(req))
}

func (s *Server) handleUIRespond(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.store.getAndExpire(id)
	if !ok {
		writeHTML(w, http.StatusNotFound, notFoundHTML(id))
		return
	}

	if err := r.ParseForm(); err != nil {
		writeHTML(w, http.StatusBadRequest, errorHTML("Failed to parse form", err.Error()))
		return
	}

	response := buildResponseFromForm(req, r.Form)

	now := timestamp()
	req.Response = response
	req.Status = "completed"
	req.UpdatedAt = now
	respondedBy := "human"
	req.RespondedBy = &respondedBy
	req.RespondedAt = &now

	// Encrypt if public key present.
	if req.PublicKey != nil {
		encrypted, err := hax.EncryptWithPublicKey(response, req.PublicKey)
		if err == nil {
			req.Response = map[string]any{"_encrypted": encrypted}
		}
	}

	// Fire webhook.
	s.dispatchWebhook("completed", req)

	writeHTML(w, http.StatusOK, renderResponseHTML(req))
}

// buildResponseFromForm converts submitted form data into the appropriate
// response structure based on the request type.
func buildResponseFromForm(req *storedRequest, form url.Values) map[string]any {
	switch req.Type {
	case "text-approval-v1", "code-approval-v1":
		decision := form.Get("decision")
		comment := form.Get("comment")
		resp := map[string]any{"decision": decision}
		if comment != "" {
			resp["comment"] = comment
		}
		return resp

	case "plan-review-v2":
		decision := form.Get("decision")
		feedback := form.Get("feedback")
		resp := map[string]any{"decision": decision}
		if feedback != "" {
			resp["feedback"] = feedback
		}
		return resp

	case "pr-af-review-v1":
		action := form.Get("action")
		instructions := form.Get("instructions")
		findingsToPost := form["findings_to_post"]
		resp := map[string]any{
			"action":          action,
			"findings_to_post": findingsToPost,
		}
		if instructions != "" {
			resp["instructions"] = instructions
		}
		return resp

	case "form-builder":
		values := map[string]any{}
		if payload, ok := req.Payload["fields"].([]any); ok {
			for _, f := range payload {
				field, ok := f.(map[string]any)
				if !ok {
					continue
				}
				fieldID, _ := field["id"].(string)
				fieldType, _ := field["type"].(string)
				if fieldID == "" {
					continue
				}
				values[fieldID] = parseFieldValue(fieldType, fieldID, form)
			}
		}
		return map[string]any{
			"values": values,
			"meta": map[string]any{
				"submittedAt": time.Now().UTC().Format(time.RFC3339Nano),
			},
		}

	default:
		// Generic: collect all form values.
		values := map[string]any{}
		for key := range form {
			if key == "_generic_json" {
				raw := form.Get(key)
				if raw != "" {
					var parsed map[string]any
					if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
						return parsed
					}
				}
				continue
			}
			values[key] = form.Get(key)
		}
		return values
	}
}

// parseFieldValue parses a form field value based on its type.
func parseFieldValue(fieldType, fieldID string, form url.Values) any {
	switch fieldType {
	case "checkbox", "switch":
		return form.Get(fieldID) == "on" || form.Get(fieldID) == "true"
	case "number", "slider":
		s := form.Get(fieldID)
		if s == "" {
			return float64(0)
		}
		var f float64
		fmt.Sscanf(s, "%f", &f)
		return f
	case "checkbox-group":
		return form[fieldID]
	default:
		return form.Get(fieldID)
	}
}

func writeHTML(w http.ResponseWriter, status int, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(html))
}

// --- HTML rendering ---

func renderRequestHTML(req *storedRequest) string {
	var sb strings.Builder

	title := "HAX Request"
	if req.Title != nil {
		title = *req.Title
	}

	canRespond := req.Status == "pending" || req.Status == "opened"

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>`)
	sb.WriteString(escapeHTML(title))
	sb.WriteString(`</title>
<style>
:root {
  --bg: #0f1117;
  --surface: #1a1d28;
  --surface2: #222634;
  --border: #2d3245;
  --text: #e4e6ed;
  --text-dim: #8b8fa3;
  --accent: #6366f1;
  --accent-hover: #5558e9;
  --success: #22c55e;
  --danger: #ef4444;
  --warning: #f59e0b;
  --radius: 10px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 20px;
}
.container {
  max-width: 640px;
  margin: 40px auto;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 32px;
  margin-bottom: 20px;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
}
.card-header h1 {
  font-size: 22px;
  font-weight: 600;
}
.badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 100px;
  font-size: 13px;
  font-weight: 500;
}
.badge.pending { background: rgba(99,102,241,0.15); color: #818cf8; }
.badge.held { background: rgba(245,158,11,0.15); color: #fbbf24; }
.badge.completed { background: rgba(34,197,94,0.15); color: #4ade80; }
.badge.expired { background: rgba(239,68,68,0.15); color: #f87171; }
.badge.cancelled { background: rgba(107,114,128,0.15); color: #9ca3af; }
.description {
  color: var(--text-dim);
  margin-bottom: 20px;
  font-size: 15px;
}
.payload-section {
  background: var(--surface2);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 20px;
}
.payload-section h2 {
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-dim);
  margin-bottom: 12px;
}
.payload-text {
  font-size: 16px;
  line-height: 1.7;
}
.payload-json {
  font-family: "SF Mono", Monaco, monospace;
  font-size: 13px;
  white-space: pre-wrap;
  word-break: break-all;
  color: #c4c7d4;
}
.meta-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  font-size: 14px;
}
.meta-label { color: var(--text-dim); }
.meta-value { font-weight: 500; }
.form-group {
  margin-bottom: 18px;
}
.form-group label {
  display: block;
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 6px;
}
.form-group label .req { color: var(--danger); margin-left: 2px; }
.field-desc { font-size: 12px; color: var(--text-dim); margin: 4px 0 6px; }
.form-group input[type="text"],
.form-group input[type="email"],
.form-group input[type="number"],
.form-group input[type="date"],
.form-group textarea,
.form-group select {
  width: 100%;
  padding: 10px 14px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  font-size: 15px;
  font-family: inherit;
  outline: none;
  transition: border-color 0.15s;
}
.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus {
  border-color: var(--accent);
}
.form-group textarea { resize: vertical; min-height: 80px; }
.form-group input[type="range"] {
  width: 100%;
  accent-color: var(--accent);
}
.checkbox-group {
  display: flex;
  align-items: center;
  gap: 10px;
}
.checkbox-group input { width: 18px; height: 18px; accent-color: var(--accent); }
.checkbox-group label { margin: 0; cursor: pointer; }
.radio-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.radio-option {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  transition: border-color 0.15s;
}
.radio-option:hover { border-color: var(--accent); }
.radio-option input { accent-color: var(--accent); }
.radio-option label { margin: 0; cursor: pointer; flex: 1; }
.btn-row {
  display: flex;
  gap: 12px;
  margin-top: 24px;
}
.btn {
  flex: 1;
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.15s, transform 0.05s;
}
.btn:active { transform: scale(0.98); }
.btn-approve {
  background: var(--success);
  color: #fff;
}
.btn-approve:hover { background: #16a34a; }
.btn-deny {
  background: var(--danger);
  color: #fff;
}
.btn-deny:hover { background: #dc2626; }
.btn-submit {
  background: var(--accent);
  color: #fff;
}
.btn-submit:hover { background: var(--accent-hover); }
.btn-secondary {
  background: var(--surface2);
  color: var(--text);
  border: 1px solid var(--border);
}
.btn-secondary:hover { background: var(--border); }
.status-banner {
  text-align: center;
  padding: 16px;
  border-radius: var(--radius);
  margin-bottom: 20px;
  font-size: 16px;
  font-weight: 500;
}
.status-banner.completed {
  background: rgba(34,197,94,0.1);
  color: #4ade80;
  border: 1px solid rgba(34,197,94,0.3);
}
.status-banner.expired {
  background: rgba(239,68,68,0.1);
  color: #f87171;
  border: 1px solid rgba(239,68,68,0.3);
}
.status-banner.cancelled {
  background: rgba(107,114,128,0.1);
  color: #9ca3af;
  border: 1px solid rgba(107,114,128,0.3);
}
.status-banner.held {
  background: rgba(245,158,11,0.1);
  color: #fbbf24;
  border: 1px solid rgba(245,158,11,0.3);
}
.response-section {
  background: var(--surface2);
  border-radius: var(--radius);
  padding: 20px;
  margin-top: 20px;
}
.response-section h2 {
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-dim);
  margin-bottom: 12px;
}
.response-value {
  display: flex;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid var(--border);
  font-size: 15px;
}
.response-value:last-child { border-bottom: none; }
.response-key { color: var(--text-dim); }
.response-val { font-weight: 500; }
.decision-approve { color: #4ade80; }
.decision-deny { color: #f87171; }
.footer {
  text-align: center;
  color: var(--text-dim);
  font-size: 13px;
  margin-top: 30px;
}
.footer a { color: var(--accent); text-decoration: none; }
.payload-markdown { font-size: 14px; line-height: 1.7; color: #c4c7d4; }
.payload-markdown h3 { font-size: 16px; margin: 16px 0 8px; color: var(--text); }
.payload-markdown h4 { font-size: 14px; margin: 12px 0 6px; color: var(--text); }
.payload-markdown ul { margin: 4px 0 8px 20px; }
.payload-markdown li { margin: 2px 0; }
.payload-markdown p { margin: 4px 0; }
.payload-markdown code { font-family: "SF Mono", Monaco, monospace; font-size: 13px; background: var(--surface2); padding: 1px 4px; border-radius: 3px; }
.payload-markdown strong { color: var(--text); }
.issue-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 10px; }
.issue-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.issue-num { font-weight: 700; color: var(--accent); font-size: 14px; }
.issue-name { font-weight: 600; font-size: 14px; }
.issue-title { font-size: 14px; color: var(--text); margin-bottom: 4px; }
.issue-desc { font-size: 13px; color: var(--text-dim); margin-bottom: 6px; }
.issue-meta { font-size: 13px; margin: 3px 0; }
.issue-ac ul { margin: 4px 0 0 20px; font-size: 13px; }
.file-tag { font-family: "SF Mono", Monaco, monospace; font-size: 12px; background: var(--surface2); padding: 1px 6px; border-radius: 4px; color: #7dd3fc; }
.revision-entry { padding: 6px 0; font-size: 13px; border-bottom: 1px solid var(--border); }
.finding-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 10px; }
.finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.finding-check input { width: 18px; height: 18px; accent-color: var(--accent); }
.finding-severity { display: inline-block; padding: 2px 10px; border-radius: 100px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
.sev-critical { background: rgba(239,68,68,0.2); color: #f87171; }
.sev-high { background: rgba(245,158,11,0.2); color: #fbbf24; }
.sev-medium { background: rgba(99,102,241,0.2); color: #818cf8; }
.sev-low { background: rgba(34,197,94,0.2); color: #4ade80; }
.sev-info { background: rgba(107,114,128,0.2); color: #9ca3af; }
.finding-title { font-weight: 600; font-size: 14px; flex: 1; }
.finding-meta { font-size: 13px; margin: 3px 0; }
.finding-body { font-size: 13px; color: var(--text-dim); margin: 6px 0; }
.finding-suggestion { font-size: 13px; margin: 4px 0; }
</style>
</head>
<body>
<div class="container">
`)

	// Status banner for non-respondable requests.
	if !canRespond {
		bannerClass := req.Status
		bannerText := ""
		switch req.Status {
		case "completed":
			bannerText = "✓ This request has been completed"
		case "expired":
			bannerText = "⚠ This request has expired"
		case "cancelled":
			bannerText = "✕ This request was cancelled"
		case "held":
			bannerText = "⏳ This request is held pending sender acceptance"
		}
		if bannerText != "" {
			sb.WriteString(fmt.Sprintf(`<div class="status-banner %s">%s</div>`, bannerClass, escapeHTML(bannerText)))
		}
	}

	// Main card.
	sb.WriteString(`<div class="card">
<div class="card-header">
<h1>`)
	sb.WriteString(escapeHTML(title))
	sb.WriteString(`</h1>
<span class="badge `)
	sb.WriteString(req.Status)
	sb.WriteString(`">`)
	sb.WriteString(req.Status)
	sb.WriteString(`</span>
</div>
`)

	// Description.
	if req.Description != nil && *req.Description != "" {
		sb.WriteString(fmt.Sprintf(`<div class="description">%s</div>`, escapeHTML(*req.Description)))
	}

	// Meta info.
	sb.WriteString(`<div class="payload-section">
<h2>Details</h2>
<div class="meta-row"><span class="meta-label">Type</span><span class="meta-value">`)
	sb.WriteString(escapeHTML(req.Type))
	sb.WriteString(`</span></div>
<div class="meta-row"><span class="meta-label">Request ID</span><span class="meta-value" style="font-family:monospace;font-size:12px">`)
	sb.WriteString(escapeHTML(req.ID))
	sb.WriteString(`</span></div>
<div class="meta-row"><span class="meta-label">Created</span><span class="meta-value">`)
	sb.WriteString(escapeHTML(req.CreatedAt))
	sb.WriteString(`</span></div>
`)
	if req.ExpiresAt != nil {
		sb.WriteString(fmt.Sprintf(`<div class="meta-row"><span class="meta-label">Expires</span><span class="meta-value">%s</span></div>`, escapeHTML(*req.ExpiresAt)))
	}
	sb.WriteString(`</div>
`)

	// Render type-specific content.
	if canRespond {
		sb.WriteString(renderResponseForm(req))
	} else if req.Response != nil {
		sb.WriteString(renderExistingResponse(req))
	}

	sb.WriteString(`</div>
<div class="footer">
  Powered by <a href="https://github.com/philhug/hax-go">HAX Go SDK</a>
</div>
</div>
</body>
</html>`)
	return sb.String()
}

// renderResponseForm renders the type-specific response form.
func renderResponseForm(req *storedRequest) string {
	switch req.Type {
	case "text-approval-v1", "code-approval-v1":
		return renderApprovalForm(req)
	case "form-builder":
		return renderFormBuilderForm(req)
	case "plan-review-v2":
		return renderPlanReviewForm(req)
	case "pr-af-review-v1":
		return renderPraFReviewForm(req)
	default:
		return renderGenericForm(req)
	}
}

func renderApprovalForm(req *storedRequest) string {
	var sb strings.Builder

	text := ""
	if t, ok := req.Payload["text"].(string); ok {
		text = t
	}
	approveLabel := "Approve"
	if l, ok := req.Payload["approveLabel"].(string); ok && l != "" {
		approveLabel = l
	}
	denyLabel := "Deny"
	if l, ok := req.Payload["denyLabel"].(string); ok && l != "" {
		denyLabel = l
	}

	sb.WriteString(`<div class="payload-section">
<h2>Request</h2>
<div class="payload-text">`)
	sb.WriteString(escapeHTML(text))
	sb.WriteString(`</div>
</div>
<form method="POST" action="">
<div class="form-group">
<label for="comment">Comment (optional)</label>
<textarea id="comment" name="comment" placeholder="Add a comment..."></textarea>
</div>
<div class="btn-row">
<button type="submit" name="decision" value="approve" class="btn btn-approve">`)
	sb.WriteString(escapeHTML(approveLabel))
	sb.WriteString(`</button>
<button type="submit" name="decision" value="deny" class="btn btn-deny">`)
	sb.WriteString(escapeHTML(denyLabel))
	sb.WriteString(`</button>
</div>
</form>`)
	return sb.String()
}

func renderFormBuilderForm(req *storedRequest) string {
	var sb strings.Builder

	fields, ok := req.Payload["fields"].([]any)
	if !ok {
		return renderGenericForm(req)
	}

	// Form title/description from config.
	if t, ok := req.Payload["title"].(string); ok && t != "" {
		sb.WriteString(fmt.Sprintf(`<div class="payload-section"><h2>%s</h2></div>`, escapeHTML(t)))
	}
	if d, ok := req.Payload["description"].(string); ok && d != "" {
		sb.WriteString(fmt.Sprintf(`<div class="description">%s</div>`, escapeHTML(d)))
	}

	sb.WriteString(`<form method="POST" action="">`)

	for _, f := range fields {
		field, ok := f.(map[string]any)
		if !ok {
			continue
		}
		sb.WriteString(renderFormField(field))
	}

	// Submit label.
	submitLabel := "Submit"
	if l, ok := req.Payload["submitLabel"].(string); ok && l != "" {
		submitLabel = l
	}
	sb.WriteString(fmt.Sprintf(`
<div class="btn-row">
<button type="submit" class="btn btn-submit">%s</button>
</div>
</form>`, escapeHTML(submitLabel)))

	return sb.String()
}

func renderFormField(field map[string]any) string {
	fieldType, _ := field["type"].(string)
	fieldID, _ := field["id"].(string)
	label, _ := field["label"].(string)
	// SWE-AF uses checkboxLabel/switchLabel for checkbox/switch fields.
	if label == "" {
		label, _ = field["checkboxLabel"].(string)
	}
	if label == "" {
		label, _ = field["switchLabel"].(string)
	}
	if label == "" {
		label = fieldID
	}
	description, _ := field["description"].(string)
	placeholder, _ := field["placeholder"].(string)
	required, _ := field["required"].(bool)
	requiredStr := ""
	if required {
		requiredStr = ` <span class="req">*</span>`
	}
	defaultValue := field["defaultValue"]
	defaultStr := ""
	if dv, ok := defaultValue.(string); ok && dv != "" {
		defaultStr = fmt.Sprintf(` value="%s"`, escapeHTML(dv))
	}

	// labelBlock renders label + optional description for non-checkbox fields.
	labelBlock := fmt.Sprintf(`<label for="%s">%s%s</label>`, escapeHTML(fieldID), escapeHTML(label), requiredStr)
	if description != "" {
		labelBlock += fmt.Sprintf(`<p class="field-desc">%s</p>`, escapeHTML(description))
	}

	var sb strings.Builder

	switch fieldType {
	case "input":
		variant, _ := field["variant"].(string)
		inputType := "text"
		if variant == "email" {
			inputType = "email"
		} else if variant == "tel" {
			inputType = "tel"
		} else if variant == "url" {
			inputType = "url"
		}
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
%s
<input type="%s" id="%s" name="%s" placeholder="%s"%s%s>
</div>`,
			labelBlock,
			inputType, escapeHTML(fieldID), escapeHTML(fieldID), escapeHTML(placeholder),
			defaultStr, requiredAttr(required)))

	case "textarea":
		rows := 4
		if r, ok := field["rows"]; ok {
			n := toInt64(r)
			if n > 0 {
				rows = int(n)
			}
		}
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label for="%s">%s%s</label>
<textarea id="%s" name="%s" placeholder="%s" rows="%d"%s></textarea>
</div>`,
			escapeHTML(fieldID), escapeHTML(label), requiredStr,
			escapeHTML(fieldID), escapeHTML(fieldID), escapeHTML(placeholder), rows,
			requiredAttr(required)))

	case "number":
		minStr, maxStr, stepStr := "", "", ""
		if min, ok := field["min"]; ok {
			minStr = fmt.Sprintf(` min="%v"`, min)
		}
		if max, ok := field["max"]; ok {
			maxStr = fmt.Sprintf(` max="%v"`, max)
		}
		if step, ok := field["step"]; ok {
			stepStr = fmt.Sprintf(` step="%v"`, step)
		}
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label for="%s">%s%s</label>
<input type="number" id="%s" name="%s" placeholder="%s"%s%s%s%s>
</div>`,
			escapeHTML(fieldID), escapeHTML(label), requiredStr,
			escapeHTML(fieldID), escapeHTML(fieldID), escapeHTML(placeholder),
			minStr, maxStr, stepStr, requiredAttr(required)))

	case "select":
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label for="%s">%s%s</label>
<select id="%s" name="%s"%s>
<option value="">-- Select --</option>`,
			escapeHTML(fieldID), escapeHTML(label), requiredStr,
			escapeHTML(fieldID), escapeHTML(fieldID), requiredAttr(required)))
		if options, ok := field["options"].([]any); ok {
			for _, opt := range options {
				if m, ok := opt.(map[string]any); ok {
					val, _ := m["value"].(string)
					lbl, _ := m["label"].(string)
					sb.WriteString(fmt.Sprintf(`<option value="%s">%s</option>`, escapeHTML(val), escapeHTML(lbl)))
				} else if s, ok := opt.(string); ok {
					sb.WriteString(fmt.Sprintf(`<option value="%s">%s</option>`, escapeHTML(s), escapeHTML(s)))
				}
			}
		}
		sb.WriteString(`</select></div>`)

	case "radio-group":
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label>%s%s</label>
<div class="radio-group">`, escapeHTML(label), requiredStr))
		if options, ok := field["options"].([]any); ok {
			for i, opt := range options {
				if m, ok := opt.(map[string]any); ok {
					val, _ := m["value"].(string)
					lbl, _ := m["label"].(string)
					sb.WriteString(fmt.Sprintf(`<div class="radio-option">
<input type="radio" id="%s_%d" name="%s" value="%s"%s>
<label for="%s_%d">%s</label>
</div>`, escapeHTML(fieldID), i, escapeHTML(fieldID), escapeHTML(val),
						requiredAttr(required), escapeHTML(fieldID), i, escapeHTML(lbl)))
				} else if s, ok := opt.(string); ok {
					sb.WriteString(fmt.Sprintf(`<div class="radio-option">
<input type="radio" id="%s_%d" name="%s" value="%s"%s>
<label for="%s_%d">%s</label>
</div>`, escapeHTML(fieldID), i, escapeHTML(fieldID), escapeHTML(s),
						requiredAttr(required), escapeHTML(fieldID), i, escapeHTML(s)))
				}
			}
		}
		sb.WriteString(`</div></div>`)

	case "checkbox":
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<div class="checkbox-group">
<input type="checkbox" id="%s" name="%s">
<label for="%s">%s</label>
</div>
</div>`, escapeHTML(fieldID), escapeHTML(fieldID), escapeHTML(fieldID), escapeHTML(label)))

	case "switch":
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<div class="checkbox-group">
<input type="checkbox" id="%s" name="%s" role="switch">
<label for="%s">%s</label>
</div>
</div>`, escapeHTML(fieldID), escapeHTML(fieldID), escapeHTML(fieldID), escapeHTML(label)))

	case "checkbox-group":
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label>%s%s</label>
<div class="radio-group">`, escapeHTML(label), requiredStr))
		if options, ok := field["options"].([]any); ok {
			for i, opt := range options {
				if m, ok := opt.(map[string]any); ok {
					val, _ := m["value"].(string)
					lbl, _ := m["label"].(string)
					sb.WriteString(fmt.Sprintf(`<div class="radio-option">
<input type="checkbox" id="%s_%d" name="%s" value="%s">
<label for="%s_%d">%s</label>
</div>`, escapeHTML(fieldID), i, escapeHTML(fieldID), escapeHTML(val),
						escapeHTML(fieldID), i, escapeHTML(lbl)))
				} else if s, ok := opt.(string); ok {
					sb.WriteString(fmt.Sprintf(`<div class="radio-option">
<input type="checkbox" id="%s_%d" name="%s" value="%s">
<label for="%s_%d">%s</label>
</div>`, escapeHTML(fieldID), i, escapeHTML(fieldID), escapeHTML(s),
						escapeHTML(fieldID), i, escapeHTML(s)))
				}
			}
		}
		sb.WriteString(`</div></div>`)

	case "slider":
		min, max, step := 0, 100, 1
		if v, ok := field["min"]; ok {
			min = int(toInt64(v))
		}
		if v, ok := field["max"]; ok {
			max = int(toInt64(v))
		}
		if v, ok := field["step"]; ok {
			n := int(toInt64(v))
			if n > 0 {
				step = n
			}
		}
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label for="%s">%s%s</label>
<input type="range" id="%s" name="%s" min="%d" max="%d" step="%d">
</div>`,
			escapeHTML(fieldID), escapeHTML(label), requiredStr,
			escapeHTML(fieldID), escapeHTML(fieldID), min, max, step))

	case "date":
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label for="%s">%s%s</label>
<input type="date" id="%s" name="%s"%s>
</div>`,
			escapeHTML(fieldID), escapeHTML(label), requiredStr,
			escapeHTML(fieldID), escapeHTML(fieldID), requiredAttr(required)))

	case "hidden":
		value, _ := field["value"].(string)
		sb.WriteString(fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`,
			escapeHTML(fieldID), escapeHTML(value)))

	default:
		// Unknown field type: render as text input.
		sb.WriteString(fmt.Sprintf(`<div class="form-group">
<label for="%s">%s%s</label>
<input type="text" id="%s" name="%s"%s>
</div>`,
			escapeHTML(fieldID), escapeHTML(label), requiredStr,
			escapeHTML(fieldID), escapeHTML(fieldID), requiredAttr(required)))
	}

	return sb.String()
}

func renderGenericForm(req *storedRequest) string {
	var sb strings.Builder

	// Show payload as JSON.
	payloadJSON, _ := json.MarshalIndent(req.Payload, "", "  ")
	sb.WriteString(`<div class="payload-section">
<h2>Payload</h2>
<div class="payload-json">`)
	sb.WriteString(escapeHTML(string(payloadJSON)))
	sb.WriteString(`</div>
</div>
<form method="POST" action="">
<div class="form-group">
<label for="_generic_json">Response (JSON)</label>
<textarea id="_generic_json" name="_generic_json" placeholder='{"decision": "approve"}' rows="6"></textarea>
</div>
<div class="btn-row">
<button type="submit" class="btn btn-submit">Submit Response</button>
</div>
</form>`)
	return sb.String()
}

func renderExistingResponse(req *storedRequest) string {
	var sb strings.Builder
	sb.WriteString(`<div class="response-section">
<h2>Response</h2>
`)
	for k, v := range req.Response {
		valStr := fmt.Sprintf("%v", v)
		class := "response-val"
		if k == "decision" {
			if valStr == "approve" {
				class += " decision-approve"
			} else if valStr == "deny" {
				class += " decision-deny"
			}
		}
		sb.WriteString(fmt.Sprintf(`<div class="response-value"><span class="response-key">%s</span><span class="%s">%s</span></div>`,
			escapeHTML(k), class, escapeHTML(valStr)))
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

func renderResponseHTML(req *storedRequest) string {
	var sb strings.Builder

	title := "Response Submitted"
	if req.Title != nil && *req.Title != "" {
		title = *req.Title
	}

	// Determine the form title from payload (form-builder).
	formTitle := ""
	if t, ok := req.Payload["title"].(string); ok {
		formTitle = t
	}
	if formTitle == "" && req.Title != nil {
		formTitle = *req.Title
	}

	// Build a label lookup from form fields.
	labels := map[string]string{}
	if fields, ok := req.Payload["fields"].([]any); ok {
		for _, f := range fields {
			if field, ok := f.(map[string]any); ok {
				id, _ := field["id"].(string)
				label, _ := field["label"].(string)
				if id != "" && label != "" {
					labels[id] = label
				}
			}
		}
	}

	// Extract the values map to display.
	displayValues := map[string]any{}
	if req.Type == "form-builder" {
		if req.Response != nil {
			if vals, ok := req.Response["values"].(map[string]any); ok {
				displayValues = vals
			}
		}
	} else if req.Response != nil {
		displayValues = req.Response
	}

	// Check if it's an approval decision.
	decision := ""
	if d, ok := displayValues["decision"].(string); ok {
		decision = d
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>`)
	sb.WriteString(escapeHTML(title))
	sb.WriteString(`</title>
<style>
:root {
  --bg: #0f1117;
  --surface: #1a1d28;
  --surface2: #222634;
  --border: #2d3245;
  --text: #e4e6ed;
  --text-dim: #8b8fa3;
  --accent: #6366f1;
  --success: #22c55e;
  --danger: #ef4444;
  --radius: 10px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 20px;
  min-height: 100vh;
}
.container {
  max-width: 580px;
  margin: 40px auto;
}
.success-banner {
  background: linear-gradient(135deg, rgba(34,197,94,0.12), rgba(34,197,94,0.04));
  border: 1px solid rgba(34,197,94,0.3);
  border-radius: var(--radius);
  padding: 36px 32px;
  text-align: center;
  margin-bottom: 20px;
}
.success-banner.deny {
  background: linear-gradient(135deg, rgba(239,68,68,0.12), rgba(239,68,68,0.04));
  border-color: rgba(239,68,68,0.3);
}
.checkmark {
  width: 56px;
  height: 56px;
  border-radius: 50%;
  background: var(--success);
  margin: 0 auto 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 28px;
  color: #fff;
}
.success-banner.deny .checkmark { background: var(--danger); }
.success-banner h1 {
  font-size: 22px;
  font-weight: 600;
  margin-bottom: 6px;
}
.success-banner .subtitle {
  color: var(--text-dim);
  font-size: 15px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px 32px;
}
.card-header {
  padding-bottom: 20px;
  margin-bottom: 20px;
  border-bottom: 1px solid var(--border);
}
.card-header h2 {
  font-size: 16px;
  font-weight: 600;
}
.card-header .form-title {
  color: var(--text-dim);
  font-size: 14px;
  margin-top: 4px;
}
.field-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 14px 0;
  border-bottom: 1px solid var(--border);
  gap: 20px;
}
.field-row:last-child { border-bottom: none; }
.field-label {
  color: var(--text-dim);
  font-size: 14px;
  white-space: nowrap;
  flex-shrink: 0;
}
.field-value {
  font-weight: 500;
  font-size: 15px;
  text-align: right;
  word-break: break-word;
}
.field-empty {
  color: #4a4d5e;
  font-style: italic;
  font-weight: 400;
}
.badge-bool {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 100px;
  font-size: 13px;
  font-weight: 500;
}
.badge-true {
  background: rgba(34,197,94,0.15);
  color: #4ade80;
}
.badge-false {
  background: rgba(107,114,128,0.15);
  color: #9ca3af;
}
.badge-decision-approve {
  display: inline-block;
  padding: 6px 20px;
  border-radius: 100px;
  font-size: 15px;
  font-weight: 600;
  background: rgba(34,197,94,0.15);
  color: #4ade80;
}
.badge-decision-deny {
  display: inline-block;
  padding: 6px 20px;
  border-radius: 100px;
  font-size: 15px;
  font-weight: 600;
  background: rgba(239,68,68,0.15);
  color: #f87171;
}
.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  justify-content: flex-end;
}
.tag {
  display: inline-block;
  padding: 3px 10px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 13px;
}
.meta-section {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
}
.meta-section .field-label { font-size: 13px; }
.meta-section .field-value { font-size: 13px; color: var(--text-dim); }
.footer {
  text-align: center;
  color: var(--text-dim);
  font-size: 13px;
  margin-top: 30px;
}
.footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>
<div class="container">
`)

	// Success banner.
	bannerClass := ""
	icon := "✓"
	bannerTitle := "Response Submitted"
	if decision == "approve" {
		bannerTitle = "Approved"
	} else if decision == "deny" {
		bannerClass = " deny"
		icon = "✕"
		bannerTitle = "Denied"
	}
	sb.WriteString(fmt.Sprintf(`<div class="success-banner%s">
<div class="checkmark">%s</div>
<h1>%s</h1>
<div class="subtitle">Request %s</div>
</div>`, bannerClass, icon, escapeHTML(bannerTitle), escapeHTML(req.ID)))

	// Response values.
	if len(displayValues) > 0 {
		sb.WriteString(`<div class="card">
<div class="card-header">
<h2>Your Response</h2>`)
		if formTitle != "" {
			sb.WriteString(fmt.Sprintf(`<div class="form-title">%s</div>`, escapeHTML(formTitle)))
		}
		sb.WriteString(`</div>
`)

		for k, v := range displayValues {
			label := labels[k]
			if label == "" {
				label = prettyLabel(k)
			}
			sb.WriteString(`<div class="field-row">
<span class="field-label">`)
			sb.WriteString(escapeHTML(label))
			sb.WriteString(`</span>
<span class="field-value">`)
			sb.WriteString(formatValue(k, v))
			sb.WriteString(`</span>
</div>`)
		}

		// Meta section.
		if req.Type == "form-builder" && req.Response != nil {
			if meta, ok := req.Response["meta"].(map[string]any); ok {
				sb.WriteString(`<div class="meta-section">`)
				if t, ok := meta["submittedAt"].(string); ok {
					sb.WriteString(fmt.Sprintf(`<div class="field-row">
<span class="field-label">Submitted</span>
<span class="field-value">%s</span>
</div>`, escapeHTML(t)))
				}
				sb.WriteString(`</div>`)
			}
		}

		sb.WriteString(`</div>`)
	}

	sb.WriteString(`
<div class="footer">
  Powered by <a href="https://github.com/philhug/hax-go">HAX Go SDK</a>
</div>
</div>
</body>
</html>`)
	return sb.String()
}

// formatValue renders a response value as HTML.
func formatValue(key string, v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return `<span class="badge-bool badge-true">Yes</span>`
		}
		return `<span class="badge-bool badge-false">No</span>`
	case string:
		if val == "" {
			return `<span class="field-empty">—</span>`
		}
		if key == "decision" {
			return fmt.Sprintf(`<span class="badge-decision-%s">%s</span>`, escapeHTML(val), escapeHTML(val))
		}
		return escapeHTML(val)
	case float64:
		if val == float64(int(val)) {
			return escapeHTML(fmt.Sprintf("%d", int(val)))
		}
		return escapeHTML(fmt.Sprintf("%g", val))
	case []any:
		if len(val) == 0 {
			return `<span class="field-empty">None selected</span>`
		}
		var parts []string
		for _, item := range val {
			parts = append(parts, fmt.Sprintf(`<span class="tag">%s</span>`, escapeHTML(fmt.Sprintf("%v", item))))
		}
		return fmt.Sprintf(`<span class="tag-list">%s</span>`, strings.Join(parts, ""))
	case map[string]any:
		b, _ := json.Marshal(val)
		return escapeHTML(string(b))
	default:
		return escapeHTML(fmt.Sprintf("%v", v))
	}
}

// prettyLabel converts a field ID to a human-readable label.
func prettyLabel(id string) string {
	// Split on underscores/camelCase and capitalize.
	var result []byte
	for i, c := range id {
		if c == '_' {
			result = append(result, ' ')
			continue
		}
		if i == 0 || (i > 0 && id[i-1] == '_') {
			result = append(result, byte(unicode.ToUpper(c)))
		} else if unicode.IsUpper(c) && i > 0 && unicode.IsLower(rune(id[i-1])) {
			result = append(result, ' ')
			result = append(result, byte(c))
		} else {
			result = append(result, byte(c))
		}
	}
	return string(result)
}

func notFoundHTML(id string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Not Found</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, sans-serif; background: #0f1117; color: #e4e6ed; padding: 20px; }
.container { max-width: 480px; margin: 80px auto; text-align: center; }
.card { background: #1a1d28; border: 1px solid #2d3245; border-radius: 10px; padding: 40px; }
.icon { font-size: 48px; margin-bottom: 20px; }
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="icon">🔍</div>
<h1>Request Not Found</h1>
<p style="color:#8b8fa3;margin-top:12px">No request exists with ID <code>%s</code></p>
</div>
</div>
</body>
</html>`, escapeHTML(id))
}

func errorHTML(title, detail string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Error</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, sans-serif; background: #0f1117; color: #e4e6ed; padding: 20px; }
.container { max-width: 480px; margin: 80px auto; text-align: center; }
.card { background: #1a1d28; border: 1px solid #2d3245; border-radius: 10px; padding: 40px; }
.icon { font-size: 48px; margin-bottom: 20px; }
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="icon">⚠</div>
<h1>%s</h1>
<p style="color:#8b8fa3;margin-top:12px">%s</p>
</div>
</div>
</body>
</html>`, escapeHTML(title), escapeHTML(detail))
}

// --- Helpers ---

func requiredAttr(required bool) string {
	if required {
		return " required"
	}
	return ""
}

func escapeHTML(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}


