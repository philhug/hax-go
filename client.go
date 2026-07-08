package hax

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const DefaultBaseURL = "https://hax-sdk-production.up.railway.app/api/v1"

// ClientOptions configures a HaxClient.
type ClientOptions struct {
	APIKey        string
	BaseURL       string
	WebhookURL    string
	Timeout       float64
	EncryptionKey string
	PublicKey     map[string]any
	DID           string
	PrivateKeyJWK map[string]any
	IdentityFile  string
}

// HaxClient is the client for interacting with the HAX API.
type HaxClient struct {
	apiKey           string
	baseURL          string
	defaultWebhook   string
	identity         *Identity
	http             *HttpClient
	keyPairPublic    map[string]any
	keyPairPrivate   map[string]any
	publicKeyOnly    map[string]any
}

// NewClient creates a new HaxClient.
func NewClient(opts ClientOptions) (*HaxClient, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = DefaultBaseURL
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}

	// Resolve DID identity. Mint only when there is no API key.
	identity, err := LoadIdentity(LoadIdentityOptions{
		DID:           opts.DID,
		PrivateKeyJWK: opts.PrivateKeyJWK,
		IdentityFile:  opts.IdentityFile,
		AllowMint:     opts.APIKey == "",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity: %w", err)
	}

	if opts.APIKey == "" && identity == nil {
		return nil, fmt.Errorf(
			"HaxClient needs authentication: pass APIKey, or a DID identity " +
				"(DID + PrivateKeyJWK, IdentityFile, or let one be minted at ~/.hax/identity.json)",
		)
	}

	c := &HaxClient{
		apiKey:         opts.APIKey,
		baseURL:        opts.BaseURL,
		defaultWebhook: opts.WebhookURL,
		identity:       identity,
	}

	var signer Signer
	if identity != nil {
		signer = c.buildSigner()
	}
	c.http = NewHttpClient(opts.BaseURL, opts.APIKey, opts.Timeout, signer)

	// Set up encryption.
	if opts.EncryptionKey != "" {
		pub, priv, err := GenerateKeyPair(opts.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key pair: %w", err)
		}
		c.keyPairPublic = pub
		c.keyPairPrivate = priv
	} else if opts.PublicKey != nil {
		c.publicKeyOnly = opts.PublicKey
	}

	return c, nil
}

// PublicKey returns the public key for this client (if encryption is enabled).
func (c *HaxClient) PublicKey() map[string]any {
	if c.keyPairPublic != nil {
		return c.keyPairPublic
	}
	return c.publicKeyOnly
}

// PrivateKey returns the private key for this client (if derived from passphrase).
func (c *HaxClient) PrivateKey() map[string]any {
	return c.keyPairPrivate
}

// GetIdentity returns the active DID identity, or nil if key-only.
func (c *HaxClient) GetIdentity() map[string]any {
	if c.identity == nil {
		return nil
	}
	return map[string]any{"did": c.identity.DID}
}

func (c *HaxClient) buildSigner() Signer {
	identity := c.identity
	return func(method, htu string, rawBody []byte) (map[string]string, error) {
		jws, err := SignKnockJWS(SignKnockJWSOptions{
			DID:           identity.DID,
			PrivateKeyJWK: identity.PrivateKeyJWK,
			HTM:           method,
			HTU:           htu,
			RawBody:       rawBody,
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"X-HAX-DID":       identity.DID,
			"X-HAX-Signature": jws,
		}, nil
	}
}

// CreateRequestParams configures a new human input request.
type CreateRequestParams struct {
	Type             string
	Payload          map[string]any
	Title            *string
	Description      *string
	WebhookURL       *string
	ExpiresInSeconds *int
	Metadata         map[string]any
	Delivery         *DeliveryConfig
	UserID           *string
	Sender           any // *SenderManifest or map[string]any
	Refs             map[string]any
	ThreadKey        *string
	Workspace        *string
	SenderInvite     *string
}

// CreateRequest creates a new human input request.
func (c *HaxClient) CreateRequest(params CreateRequestParams) (*CreatedRequest, error) {
	body := map[string]any{
		"type":    params.Type,
		"payload": params.Payload,
	}

	if params.Title != nil {
		body["title"] = *params.Title
	}
	if params.Description != nil {
		body["description"] = *params.Description
	}

	// Use request-level webhook URL, fall back to client default.
	webhookURL := ""
	if params.WebhookURL != nil {
		webhookURL = *params.WebhookURL
	} else {
		webhookURL = c.defaultWebhook
	}
	if webhookURL != "" {
		body["webhookUrl"] = webhookURL
	}

	if params.ExpiresInSeconds != nil {
		body["expiresInSeconds"] = *params.ExpiresInSeconds
	}
	if params.Metadata != nil {
		body["metadata"] = params.Metadata
	}
	if params.Delivery != nil {
		body["delivery"] = deliveryToMap(params.Delivery)
	}
	if params.UserID != nil {
		body["userId"] = *params.UserID
	}
	if params.Sender != nil {
		senderMap, err := normalizeSender(params.Sender)
		if err != nil {
			return nil, err
		}
		body["sender"] = senderMap
	}
	if params.Refs != nil {
		body["refs"] = params.Refs
	}
	if params.ThreadKey != nil {
		body["threadKey"] = *params.ThreadKey
	}
	if params.Workspace != nil {
		body["workspace"] = *params.Workspace
	}
	if params.SenderInvite != nil {
		body["senderInvite"] = *params.SenderInvite
	}

	// Include public key for response encryption.
	pubKey := c.PublicKey()
	if pubKey != nil {
		body["publicKey"] = pubKey
	}

	data, err := c.http.Post("/requests", body)
	if err != nil {
		return nil, err
	}

	return parseCreatedRequest(data)
}

// RequestViaEmail creates a request and sends it via email.
func (c *HaxClient) RequestViaEmail(params CreateRequestParams, toEmail string, subject, message *string) (*CreatedRequest, error) {
	params.Delivery = &DeliveryConfig{
		Channel:   "email",
		Recipient: toEmail,
		Subject:   subject,
		Message:   message,
	}
	return c.CreateRequest(params)
}

// RequestViaSMS creates a request and sends it via SMS.
func (c *HaxClient) RequestViaSMS(params CreateRequestParams, toPhone string, message *string) (*CreatedRequest, error) {
	params.Delivery = &DeliveryConfig{
		Channel:   "sms",
		Recipient: toPhone,
		Message:   message,
	}
	return c.CreateRequest(params)
}

// ConfigureMessaging configures messaging providers for the workspace.
func (c *HaxClient) ConfigureMessaging(email, sms map[string]any) error {
	messaging := map[string]any{}
	if email != nil {
		messaging["email"] = email
	}
	if sms != nil {
		messaging["sms"] = sms
	}
	_, err := c.http.Patch("/workspaces/settings", map[string]any{"messaging": messaging})
	return err
}

// GetRequest gets a request by ID.
// If encryption was enabled, encrypted response fields are automatically decrypted.
func (c *HaxClient) GetRequest(requestID string) (*Request, error) {
	data, err := c.http.Get("/requests/"+requestID, nil)
	if err != nil {
		return nil, err
	}

	requestData := unwrap(data, "request")

	// Auto-decrypt response if we have a private key.
	if c.PrivateKey() != nil {
		requestData = c.decryptResponseField(requestData)
	}

	req, err := parseRequest(requestData)
	if err != nil {
		return nil, err
	}
	req.SetBaseURL(c.baseURL)
	return req, nil
}

// ListRequests lists recent requests for the workspace (latest 25).
func (c *HaxClient) ListRequests() ([]*RequestSummary, error) {
	data, err := c.http.Get("/requests", nil)
	if err != nil {
		return nil, err
	}

	var requestsData []any
	if r, ok := data["requests"].([]any); ok {
		requestsData = r
	}

	// Auto-decrypt each request's response if we have a private key.
	if c.PrivateKey() != nil {
		for i, r := range requestsData {
			if m, ok := r.(map[string]any); ok {
				requestsData[i] = c.decryptResponseField(m)
			}
		}
	}

	result := make([]*RequestSummary, 0, len(requestsData))
	for _, r := range requestsData {
		if m, ok := r.(map[string]any); ok {
			b, err := compactJSON(m)
			if err != nil {
				return nil, err
			}
			var rs RequestSummary
			if err := json.Unmarshal(b, &rs); err != nil {
				return nil, err
			}
			result = append(result, &rs)
		}
	}
	return result, nil
}

// CancelRequest cancels a pending request.
func (c *HaxClient) CancelRequest(requestID string) (*Request, error) {
	data, err := c.http.Patch("/requests/"+requestID, map[string]any{"status": "cancelled"})
	if err != nil {
		return nil, err
	}

	requestData := unwrap(data, "request")
	req, err := parseRequest(requestData)
	if err != nil {
		return nil, err
	}
	req.SetBaseURL(c.baseURL)
	return req, nil
}

// SubmitResponse submits a response to a request (for testing/internal use).
func (c *HaxClient) SubmitResponse(requestID string, response map[string]any) (*Request, error) {
	data, err := c.http.Post("/requests/"+requestID+"/response", map[string]any{"response": response})
	if err != nil {
		return nil, err
	}

	requestData := unwrap(data, "request")
	req, err := parseRequest(requestData)
	if err != nil {
		return nil, err
	}
	req.SetBaseURL(c.baseURL)
	return req, nil
}

// ListTypes lists available template types.
func (c *HaxClient) ListTypes() ([]map[string]string, error) {
	data, err := c.http.Get("/types", nil)
	if err != nil {
		return nil, err
	}

	var result []map[string]string
	if types, ok := data["types"].([]any); ok {
		for _, t := range types {
			if m, ok := t.(map[string]any); ok {
				entry := map[string]string{}
				for k, v := range m {
					if s, ok := v.(string); ok {
						entry[k] = s
					}
				}
				result = append(result, entry)
			}
		}
	}
	return result, nil
}

// SearchTypes searches shipped templates with compact metadata.
func (c *HaxClient) SearchTypes(q string, tags any, pack string, limit *int) (map[string]any, error) {
	params := map[string]any{}
	if q != "" {
		params["q"] = q
	}
	if pack != "" {
		params["pack"] = pack
	}
	if limit != nil {
		params["limit"] = *limit
	}
	if tags != nil {
		switch t := tags.(type) {
		case string:
			params["tags"] = t
		case []string:
			params["tags"] = strings.Join(t, ",")
		case []any:
			parts := make([]string, 0, len(t))
			for _, v := range t {
				if s, ok := v.(string); ok {
					parts = append(parts, s)
				}
			}
			params["tags"] = strings.Join(parts, ",")
		}
	}
	return c.http.Get("/types", params)
}

// WaitForResponse polls until a request is completed, expired, or cancelled.
func (c *HaxClient) WaitForResponse(requestID string, pollInterval, timeout float64) (*Request, error) {
	if pollInterval <= 0 {
		pollInterval = 2.0
	}
	start := time.Now()

	for {
		req, err := c.GetRequest(requestID)
		if err != nil {
			return nil, err
		}

		if req.IsCompleted() || req.IsExpired() || req.IsCancelled() {
			return req, nil
		}

		if timeout > 0 {
			elapsed := time.Since(start).Seconds()
			if elapsed >= timeout {
				return nil, fmt.Errorf("request %s did not complete within %v seconds", requestID, timeout)
			}
		}

		time.Sleep(time.Duration(pollInterval * float64(time.Second)))
	}
}

// CreateFormRequest creates a form request with typed responses.
func (c *HaxClient) CreateFormRequest(form *FormBuilder, params CreateRequestParams) (*FormRequestHandle, error) {
	params.Type = "form-builder"
	params.Payload = form.ToPayload()

	created, err := c.CreateRequest(params)
	if err != nil {
		return nil, err
	}
	return &FormRequestHandle{
		client:    c,
		id:        created.ID,
		url:       created.URL,
		form:      form,
	}, nil
}

// GetKnockStatus checks this DID's review status for a workspace.
func (c *HaxClient) GetKnockStatus(workspace, senderInvite string) (map[string]any, error) {
	params := map[string]any{}
	if workspace != "" {
		params["workspace"] = workspace
	}
	if senderInvite != "" {
		params["senderInvite"] = senderInvite
	}
	return c.http.Get("/knock/status", params)
}

// WaitForAcceptance polls get_knock_status until the DID is accepted, blocked, or times out.
// Returns "active", "blocked", or "timeout".
func (c *HaxClient) WaitForAcceptance(workspace, senderInvite string, timeout, poll float64) (string, error) {
	if poll <= 0 {
		poll = 3.0
	}
	if timeout <= 0 {
		timeout = 300.0
	}
	start := time.Now()

	for {
		status, err := c.GetKnockStatus(workspace, senderInvite)
		if err != nil {
			return "", err
		}

		s, _ := status["status"].(string)
		if s == "active" {
			return "active", nil
		}
		if s == "blocked" {
			return "blocked", nil
		}

		if time.Since(start).Seconds() >= timeout {
			return "timeout", nil
		}

		time.Sleep(time.Duration(poll * float64(time.Second)))
	}
}

// Close closes the client and releases resources.
func (c *HaxClient) Close() {
	c.http.Close()
}

// --- Internal helpers ---

func (c *HaxClient) decryptResponseField(data map[string]any) map[string]any {
	if c.PrivateKey() == nil {
		return data
	}

	response, ok := data["response"]
	if response == nil || !ok {
		return data
	}

	// Format 1: Entire response is encrypted { _encrypted: "..." }
	if IsEncryptedResponse(response) {
		decrypted, err := DecryptResponse(
			response.(map[string]any)["_encrypted"].(string),
			c.PrivateKey(),
		)
		if err != nil {
			return data
		}
		if m, ok := decrypted.(map[string]any); ok {
			data["response"] = m
		} else {
			data["response"] = decrypted
		}
		return data
	}

	// Format 2: Only values are encrypted { values: { _encrypted: "..." }, ... }
	if respMap, ok := response.(map[string]any); ok {
		if IsEncryptedResponse(respMap["values"]) {
			decrypted, err := DecryptResponse(
				respMap["values"].(map[string]any)["_encrypted"].(string),
				c.PrivateKey(),
			)
			if err != nil {
				return data
			}
			newResp := map[string]any{}
			for k, v := range respMap {
				newResp[k] = v
			}
			if m, ok := decrypted.(map[string]any); ok {
				newResp["values"] = m
			} else {
				newResp["values"] = decrypted
			}
			data["response"] = newResp
		}
	}

	return data
}

func deliveryToMap(d *DeliveryConfig) map[string]any {
	m := map[string]any{
		"channel":   d.Channel,
		"recipient": d.Recipient,
	}
	if d.Subject != nil {
		m["subject"] = *d.Subject
	}
	if d.Message != nil {
		m["message"] = *d.Message
	}
	return m
}

func normalizeSender(sender any) (map[string]any, error) {
	switch s := sender.(type) {
	case *SenderManifest:
		return senderManifestToMap(s), nil
	case SenderManifest:
		return senderManifestToMap(&s), nil
	case map[string]any:
		result := map[string]any{}
		for k, v := range s {
			result[snakeToCamel(k)] = v
		}
		return result, nil
	}
	return nil, fmt.Errorf("sender must be *SenderManifest or map[string]any")
}

func senderManifestToMap(s *SenderManifest) map[string]any {
	m := map[string]any{"key": s.Key}
	if s.DisplayName != nil {
		m["displayName"] = *s.DisplayName
	}
	if s.Description != nil {
		m["description"] = *s.Description
	}
	if s.Icon != nil {
		m["icon"] = *s.Icon
	}
	if s.ThreadBy != nil {
		m["threadBy"] = *s.ThreadBy
	}
	if s.DiscussURL != nil {
		m["discussUrl"] = *s.DiscussURL
	}
	if s.Project != nil {
		m["project"] = *s.Project
	}
	return m
}

// unwrap tries to get a nested key, falling back to the original data.
func unwrap(data map[string]any, key string) map[string]any {
	if v, ok := data[key].(map[string]any); ok {
		return v
	}
	return data
}

func parseCreatedRequest(data map[string]any) (*CreatedRequest, error) {
	b, err := compactJSON(data)
	if err != nil {
		return nil, err
	}
	var req CreatedRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("failed to parse created request: %w", err)
	}
	return &req, nil
}

func parseRequest(data map[string]any) (*Request, error) {
	b, err := compactJSON(data)
	if err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}
	return &req, nil
}

// StringPtr returns a pointer to s.
func StringPtr(s string) *string { return &s }

// IntPtr returns a pointer to i.
func IntPtr(i int) *int { return &i }
