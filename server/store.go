package server

import (
	"sync"
	"time"
)

// storedRequest is the internal representation of a HAX request.
type storedRequest struct {
	ID           string             `json:"id"`
	WorkspaceID  string             `json:"workspaceId"`
	Type         string             `json:"type"`
	Title        *string            `json:"title,omitempty"`
	Description  *string            `json:"description,omitempty"`
	Payload      map[string]any     `json:"payload"`
	Metadata     map[string]any     `json:"metadata,omitempty"`
	Status       string             `json:"status"`
	ExpiresAt    *string            `json:"expiresAt,omitempty"`
	Response     map[string]any     `json:"response,omitempty"`
	RespondedBy  *string            `json:"respondedBy,omitempty"`
	RespondedAt  *string            `json:"respondedAt,omitempty"`
	WebhookURL   string             `json:"-"`
	OpenedAt     *string            `json:"openedAt,omitempty"`
	UserID       *string            `json:"userId,omitempty"`
	SenderID     *string            `json:"senderId,omitempty"`
	ThreadID     *string            `json:"threadId,omitempty"`
	CreatedAt    string             `json:"createdAt"`
	UpdatedAt    string             `json:"updatedAt"`
	PublicKey    map[string]any     `json:"-"`
	Sender       map[string]any     `json:"-"`
	Workspace    string             `json:"-"`
	SenderInvite string             `json:"-"`
	ThreadKey    string             `json:"-"`
	Delivery     map[string]any     `json:"-"`
	CreatedByDID string             `json:"-"`
	Refs         map[string]any     `json:"-"`
}

// knockKey indexes a knock by workspace and DID.
func knockKey(workspace, did string) string {
	return workspace + "\x00" + did
}

// store is a thread-safe in-memory store for the reference server.
type store struct {
	mu           sync.RWMutex
	requests     map[string]*storedRequest
	knockStatus  map[string]string // workspace\x00did -> "pending"|"active"|"blocked"
	wsSettings   map[string]map[string]any
	order        []string // request IDs in creation order
}

func newStore() *store {
	return &store{
		requests:    make(map[string]*storedRequest),
		knockStatus: make(map[string]string),
		wsSettings:  make(map[string]map[string]any),
	}
}

func (s *store) put(req *storedRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.ID] = req
	s.order = append(s.order, req.ID)
}

func (s *store) get(id string) (*storedRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.requests[id]
	return r, ok
}

// getAndExpire returns a request, auto-expiring it if past its expiresAt.
func (s *store) getAndExpire(id string) (*storedRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	if !ok {
		return nil, false
	}
	s.expireLocked(r)
	return r, true
}

// expireLocked auto-expires a request if past its deadline. Caller must hold the lock.
func (s *store) expireLocked(r *storedRequest) {
	if r.Status != "pending" && r.Status != "opened" {
		return
	}
	if r.ExpiresAt == nil {
		return
	}
	exp, err := time.Parse("2006-01-02T15:04:05.000Z", *r.ExpiresAt)
	if err != nil {
		return
	}
	if time.Now().UTC().After(exp) {
		r.Status = "expired"
		r.UpdatedAt = timestamp()
	}
}

// markOpened transitions a pending request to "opened" (human viewed it).
// Returns true if the status changed.
func (s *store) markOpened(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	if !ok {
		return false
	}
	if r.Status == "pending" {
		r.Status = "opened"
		now := timestamp()
		r.OpenedAt = &now
		r.UpdatedAt = now
		return true
	}
	return false
}

// expireExpired returns IDs of requests that were auto-expired.
func (s *store) expireExpired() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []string
	now := time.Now().UTC()
	for _, r := range s.requests {
		if (r.Status == "pending" || r.Status == "opened") && r.ExpiresAt != nil {
			if exp, err := time.Parse("2006-01-02T15:04:05.000Z", *r.ExpiresAt); err == nil && now.After(exp) {
				r.Status = "expired"
				r.UpdatedAt = timestamp()
				expired = append(expired, r.ID)
			}
		}
	}
	return expired
}

func (s *store) list() []*storedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, r := range s.requests {
		if (r.Status == "pending" || r.Status == "opened") && r.ExpiresAt != nil {
			if exp, err := time.Parse("2006-01-02T15:04:05.000Z", *r.ExpiresAt); err == nil && now.After(exp) {
				r.Status = "expired"
				r.UpdatedAt = timestamp()
			}
		}
	}
	result := make([]*storedRequest, 0, len(s.order))
	for _, id := range s.order {
		if r, ok := s.requests[id]; ok {
			result = append(result, r)
		}
	}
	return result
}

// knockStatus get/set
func (s *store) getKnockStatus(workspace, did string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.knockStatus[knockKey(workspace, did)]
	return st, ok
}

func (s *store) setKnockStatus(workspace, did, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.knockStatus[knockKey(workspace, did)] = status
}

func (s *store) getWorkspaceSettings(workspace string) map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if settings, ok := s.wsSettings[workspace]; ok {
		out := make(map[string]any, len(settings))
		for k, v := range settings {
			out[k] = v
		}
		return out
	}
	return nil
}

func (s *store) setWorkspaceSettings(workspace string, settings map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wsSettings[workspace] = settings
}

// releaseHeldRequests moves all held requests for a workspace+did to pending.
func (s *store) releaseHeldRequests(workspace, did string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := timestamp()
	for _, req := range s.requests {
		if req.Status == "held" && req.Workspace == workspace && req.CreatedByDID == did {
			req.Status = "pending"
			req.UpdatedAt = now
		}
	}
}

func timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}
