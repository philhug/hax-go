package server

import (
	"bytes"
	"net/http"
	"time"

	hax "github.com/philhug/hax-go"
)

// dispatchWebhook fires a webhook event for a request lifecycle event.
// It runs in a goroutine to avoid blocking the response.
func (s *Server) dispatchWebhook(eventType string, req *storedRequest) {
	if req.WebhookURL == "" {
		return
	}
	go s.sendWebhook(eventType, req)
}

func (s *Server) sendWebhook(eventType string, req *storedRequest) {
	event := map[string]any{
		"type":      "request." + eventType,
		"timestamp": req.UpdatedAt,
		"data":      s.requestToMap(req),
	}

	rawBody, err := hax.CompactJSON(event)
	if err != nil {
		return
	}

	sig, err := hax.SignPayload(event, s.config.WebhookSecret)
	if err != nil {
		return
	}

	httpReq, err := http.NewRequest("POST", req.WebhookURL, bytes.NewReader(rawBody))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Hax-Signature", sig)
	httpReq.Header.Set("X-Hax-Event", "request."+eventType)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return
	}
	resp.Body.Close()
}
