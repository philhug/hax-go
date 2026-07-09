package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	hax "github.com/philhug/hax-go"
)

// --- Health ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"service":    "hax-server",
		"version":    "0.2.8",
		"requests":   len(s.store.list()),
		"timestamp":  timestamp(),
	})
}

// --- Handlers ---

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	reqType, _ := body["type"].(string)
	if reqType == "" {
		writeErrorWithDetails(w, http.StatusUnprocessableEntity, "type is required", nil)
		return
	}
	payload, _ := body["payload"].(map[string]any)
	if payload == nil {
		payload = map[string]any{}
	}

	now := timestamp()

	req := &storedRequest{
		ID:        generateID(),
		Type:      reqType,
		Payload:   payload,
		Status:    "pending",
		CreatedAt: now,
		UpdatedAt: now,
	}

	if v, ok := body["title"].(string); ok {
		req.Title = &v
	}
	if v, ok := body["description"].(string); ok {
		req.Description = &v
	}
	if v, ok := body["metadata"].(map[string]any); ok {
		req.Metadata = v
	}
	if v, ok := body["webhookUrl"].(string); ok {
		req.WebhookURL = v
	}
	if v, ok := body["userId"].(string); ok {
		req.UserID = &v
	}
	if v, ok := body["workspace"].(string); ok {
		req.Workspace = v
		req.WorkspaceID = v
	}
	if v, ok := body["senderInvite"].(string); ok {
		req.SenderInvite = v
	}
	if v, ok := body["threadKey"].(string); ok {
		req.ThreadKey = v
	}
	if v, ok := body["refs"].(map[string]any); ok {
		req.Refs = v
	}
	if v, ok := body["publicKey"].(map[string]any); ok {
		req.PublicKey = v
	}
	if v, ok := body["delivery"].(map[string]any); ok {
		req.Delivery = v
	}
	if v, ok := body["sender"].(map[string]any); ok {
		req.Sender = v
		if key, ok := v["key"].(string); ok {
			req.SenderID = &key
		}
	}
	if req.ThreadKey != "" {
		tid := req.ThreadKey
		req.ThreadID = &tid
	}

	// Expiration.
	if secs, ok := body["expiresInSeconds"]; ok {
		if n := toInt64(secs); n > 0 {
			exp := time.Now().UTC().Add(time.Duration(n) * time.Second).Format("2006-01-02T15:04:05.000Z")
			req.ExpiresAt = &exp
		}
	}

	// DID-based auth: check knock status.
	auth := s.getAuthFromContext(r)
	if auth != nil && auth.Method == "did" && auth.DID != "" {
		req.CreatedByDID = auth.DID
		ws := req.Workspace
		if ws == "" {
			ws = "default"
		}
		status, exists := s.store.getKnockStatus(ws, auth.DID)
		if !exists {
			s.store.setKnockStatus(ws, auth.DID, "pending")
			status = "pending"
		}
		if status != "active" {
			if *s.config.AutoAcceptKnocks {
				s.store.setKnockStatus(ws, auth.DID, "active")
			} else {
				req.Status = "held"
			}
		}
	}

	s.store.put(req)

	// Build the response (CreatedRequest format — flat, not wrapped).
	resp := s.requestToMap(req)
	resp["url"] = s.requestURL(req.ID)

	// Delivery result.
	if req.Delivery != nil {
		channel, _ := req.Delivery["channel"].(string)
		resp["delivery"] = map[string]any{
			"success": true,
			"channel": channel,
		}
		s.dispatchWebhook("sent", req)
	}

	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.store.getAndExpire(id)
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	resp := map[string]any{"request": s.requestToMap(req)}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	all := s.store.list()

	// Pagination: default 25, max 100, supports ?limit= and ?before= (cursor = last ID).
	limit := 25
	if l := r.URL.Query().Get("limit"); l != "" {
		if n := int(toInt64(l)); n > 0 && n <= 100 {
			limit = n
		}
	}

	// Cursor: return items before this ID (exclusive).
	cursor := r.URL.Query().Get("before")

	start := 0
	if cursor != "" {
		for i, req := range all {
			if req.ID == cursor {
				start = i
				break
			}
		}
	}

	// Return latest first: take from the end.
	end := len(all)
	if end-start > limit {
		end = start + limit
	}

	items := make([]map[string]any, 0, end-start)
	for i := start; i < end; i++ {
		items = append(items, s.requestToMap(all[i]))
	}

	resp := map[string]any{
		"requests": items,
		"count":    len(items),
		"hasMore":  end < len(all),
	}
	if end < len(all) && len(items) > 0 {
		lastID := items[len(items)-1]["id"].(string)
		resp["nextCursor"] = lastID
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.store.getAndExpire(id)
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}

	body, err := readJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if status, ok := body["status"].(string); ok {
		req.Status = status
		req.UpdatedAt = timestamp()
		if status == "cancelled" {
			s.dispatchWebhook("cancelled", req)
		}
	}

	resp := map[string]any{"request": s.requestToMap(req)}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSubmitResponse(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.store.getAndExpire(id)
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}

	body, err := readJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	response, _ := body["response"].(map[string]any)
	if response == nil {
		writeErrorWithDetails(w, http.StatusUnprocessableEntity, "response is required", nil)
		return
	}

	now := timestamp()
	req.Response = response
	req.Status = "completed"
	req.UpdatedAt = now

	respondedBy := "anonymous"
	req.RespondedBy = &respondedBy
	req.RespondedAt = &now

	// Encrypt the response if a public key was provided.
	if req.PublicKey != nil {
		encrypted, err := hax.EncryptWithPublicKey(response, req.PublicKey)
		if err == nil {
			req.Response = map[string]any{"_encrypted": encrypted}
		}
	}

	// Fire webhook.
	s.dispatchWebhook("completed", req)

	resp := map[string]any{"request": s.requestToMap(req)}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListTypes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	pack := r.URL.Query().Get("pack")
	tagsParam := r.URL.Query().Get("tags")
	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		limit = toInt(toInt64(l))
	}

	var tags []string
	if tagsParam != "" {
		tags = strings.Split(tagsParam, ",")
	}

	if q == "" && pack == "" && tagsParam == "" && limit == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"types": builtinTypes})
		return
	}

	result := filterTypes(q, tags, pack, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"types":  result,
		"count":  len(result),
		"query":  q,
		"pack":   pack,
	})
}

func (s *Server) handleKnockStatus(w http.ResponseWriter, r *http.Request) {
	workspace := r.URL.Query().Get("workspace")
	if workspace == "" {
		workspace = "default"
	}

	auth := s.getAuthFromContext(r)
	did := ""
	if auth != nil {
		did = auth.DID
	}

	senderInvite := r.URL.Query().Get("senderInvite")

	status, exists := s.store.getKnockStatus(workspace, did)
	if !exists {
		if *s.config.AutoAcceptKnocks {
			s.store.setKnockStatus(workspace, did, "active")
			status = "active"
		} else {
			s.store.setKnockStatus(workspace, did, "pending")
			status = "pending"
		}
	} else if status == "pending" && *s.config.AutoAcceptKnocks {
		s.store.setKnockStatus(workspace, did, "active")
		status = "active"
		s.store.releaseHeldRequests(workspace, did)
	}

	resp := map[string]any{
		"status":       status,
		"workspace":    workspace,
		"did":           did,
		"senderInvite": senderInvite,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleWorkspaceSettings(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	messaging, _ := body["messaging"].(map[string]any)
	if messaging == nil {
		writeErrorWithDetails(w, http.StatusUnprocessableEntity, "messaging is required", nil)
		return
	}

	workspace := "default"
	s.store.setWorkspaceSettings(workspace, map[string]any{"messaging": messaging})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "updated",
		"workspace": workspace,
	})
}

func (s *Server) handleGetWorkspaceSettings(w http.ResponseWriter, r *http.Request) {
	workspace := "default"
	settings := s.store.getWorkspaceSettings(workspace)
	if settings == nil {
		settings = map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"workspace": workspace,
		"settings":  settings,
	})
}

// --- Admin endpoints (for testing, not part of the client SDK) ---

func (s *Server) handleAdminKnock(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	workspace, _ := body["workspace"].(string)
	did, _ := body["did"].(string)
	status, _ := body["status"].(string)
	if workspace == "" {
		workspace = "default"
	}
	if status != "active" && status != "blocked" && status != "pending" {
		writeErrorWithDetails(w, http.StatusUnprocessableEntity, "status must be active, blocked, or pending", nil)
		return
	}
	s.store.setKnockStatus(workspace, did, status)
	if status == "active" {
		s.store.releaseHeldRequests(workspace, did)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "workspace": workspace, "did": did, "knockStatus": status})
}

func (s *Server) handleAdminRespond(w http.ResponseWriter, r *http.Request) {
	body, err := readJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	requestID, _ := body["requestId"].(string)
	response, _ := body["response"].(map[string]any)

	req, ok := s.store.getAndExpire(requestID)
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}

	now := timestamp()
	req.Response = response
	req.Status = "completed"
	req.UpdatedAt = now
	respondedBy := "admin"
	req.RespondedBy = &respondedBy
	req.RespondedAt = &now

	// Encrypt if public key present.
	if req.PublicKey != nil {
		encrypted, err := hax.EncryptWithPublicKey(response, req.PublicKey)
		if err == nil {
			req.Response = map[string]any{"_encrypted": encrypted}
		}
	}

	s.dispatchWebhook("completed", req)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request": s.requestToMap(req)})
}

// --- Helpers ---

// requestToMap converts a storedRequest to a JSON-ready map.
func (s *Server) requestToMap(req *storedRequest) map[string]any {
	m := map[string]any{
		"id":          req.ID,
		"workspaceId": req.WorkspaceID,
		"type":        req.Type,
		"status":      req.Status,
		"createdAt":   req.CreatedAt,
		"updatedAt":   req.UpdatedAt,
	}
	if req.Title != nil {
		m["title"] = *req.Title
	}
	if req.Description != nil {
		m["description"] = *req.Description
	}
	if req.Payload != nil {
		m["payload"] = req.Payload
	}
	if req.Metadata != nil {
		m["metadata"] = req.Metadata
	}
	if req.ExpiresAt != nil {
		m["expiresAt"] = *req.ExpiresAt
	}
	if req.Response != nil {
		m["response"] = req.Response
	}
	if req.RespondedBy != nil {
		m["respondedBy"] = *req.RespondedBy
	}
	if req.RespondedAt != nil {
		m["respondedAt"] = *req.RespondedAt
	}
	if req.WebhookURL != "" {
		m["webhookUrl"] = req.WebhookURL
	}
	if req.OpenedAt != nil {
		m["openedAt"] = *req.OpenedAt
	}
	if req.UserID != nil {
		m["userId"] = *req.UserID
	}
	if req.SenderID != nil {
		m["senderId"] = *req.SenderID
	}
	if req.ThreadID != nil {
		m["threadId"] = *req.ThreadID
	}
	if req.Refs != nil {
		m["refs"] = req.Refs
	}
	return m
}

// getAuthFromContext retrieves auth info stored by the auth middleware.
func (s *Server) getAuthFromContext(r *http.Request) *authInfo {
	v := r.Context().Value(authContextKey{})
	if v == nil {
		return nil
	}
	return v.(*authInfo)
}

type authContextKey struct{}

func generateID() string {
	b := make([]byte, 16)
	if _, err := readRandom(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		var i int64
		fmt.Sscanf(n, "%d", &i)
		return i
	}
	return 0
}

func toInt(v int64) int {
	return int(v)
}
