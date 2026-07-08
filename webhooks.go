package hax

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// WebhookEvent is a parsed webhook event from HAX.
type WebhookEvent struct {
	Type      string         `json:"type"`
	Timestamp string         `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// EventType returns the event type without the "request." prefix.
func (e *WebhookEvent) EventType() string {
	if strings.HasPrefix(e.Type, "request.") {
		return e.Type[8:]
	}
	return e.Type
}

// RequestID returns the request ID from the event data.
func (e *WebhookEvent) RequestID() string {
	if id, ok := e.Data["id"].(string); ok {
		return id
	}
	return ""
}

// Metadata returns the request metadata from the event data.
func (e *WebhookEvent) Metadata() map[string]any {
	if m, ok := e.Data["metadata"].(map[string]any); ok {
		return m
	}
	return nil
}

// Response returns the response data if the request was completed.
func (e *WebhookEvent) Response() map[string]any {
	if r, ok := e.Data["response"].(map[string]any); ok {
		return r
	}
	return nil
}

// Request parses the event data as a Request object.
func (e *WebhookEvent) Request() *Request {
	return &Request{
		ID:          getStringVal(e.Data, "id"),
		WorkspaceID: getStringVal(e.Data, "workspaceId"),
		Type:        getStringVal(e.Data, "type"),
		Status:      RequestStatus(getStringVal(e.Data, "status")),
		Metadata:    getMapVal(e.Data, "metadata"),
		Response:    getMapVal(e.Data, "response"),
		Payload:     getMapVal(e.Data, "payload"),
		CreatedAt:   getStringOr(e.Data, "createdAt", e.Timestamp),
		UpdatedAt:   getStringOr(e.Data, "updatedAt", e.Timestamp),
	}
}

func getStringVal(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getMapVal(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func getStringOr(m map[string]any, key, fallback string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return fallback
}

// VerifySignature verifies a webhook signature.
//
// payload is the raw request body bytes.
// signature is the X-Hax-Signature header value (e.g., "sha256=abc123...").
// secret is the webhook secret (e.g., "whsec_...").
func VerifySignature(payload []byte, signature, secret string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	expected := signature[7:]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	computed := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(computed), []byte(expected))
}

// ParseEvent parses a webhook payload into a typed event.
//
// If privateKey is provided, the response field is decrypted if encrypted.
func ParseEvent(payload []byte, privateKey map[string]any) (*WebhookEvent, error) {
	var data map[string]any
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("failed to parse webhook payload: %w", err)
	}

	// Decrypt response field if private key provided.
	if privateKey != nil {
		if eventData, ok := data["data"].(map[string]any); ok {
			if resp, ok := eventData["response"].(map[string]any); ok {
				if IsEncryptedResponse(resp) {
					if encStr, ok := resp["_encrypted"].(string); ok {
						decrypted, err := DecryptResponse(encStr, privateKey)
						if err == nil {
							if dm, ok := decrypted.(map[string]any); ok {
								eventData["response"] = dm
							}
						}
					}
				}
			}
		}
	}

	event := &WebhookEvent{}
	if t, ok := data["type"].(string); ok {
		event.Type = t
	}
	if ts, ok := data["timestamp"].(string); ok {
		event.Timestamp = ts
	}
	if d, ok := data["data"].(map[string]any); ok {
		event.Data = d
	}
	return event, nil
}

// SignPayload signs a webhook payload (for testing purposes).
func SignPayload(payload map[string]any, secret string) (string, error) {
	body, err := compactJSON(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil)), nil
}
