package handler

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrSessionExpired       = errors.New("authentication session expired")
	ErrSessionConsumed      = errors.New("authentication session already consumed (single-use enforced)")
	ErrSessionNotFound      = errors.New("authentication session not found")
	ErrCorrelationStoreFull = errors.New("too many active authentication sessions; please retry shortly")
)

// AuthSessionState correlates downstream ITA and upstream IdP transactions
type AuthSessionState struct {
	SessionID           string
	ITAAuthnRequestID   string
	ITARelayState       string
	ITAACSURL           string
	OutboundRequestID   string
	SelectedIdP         string
	UpstreamEntityID    string
	UpstreamCertFile    string
	SubjectNameID       string
	SubjectNameIDFormat string
	UserIdentityKey     string
	UserEmail           string
	UserPhone           string
	UserDisplayName     string
	UserGroups          []string
	AssertionConsumed   bool
	MFAVerified         bool
	ReEnrollAuthorized  bool
	CSRFToken           string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Consumed            bool
}

type CorrelationStore struct {
	mu          sync.RWMutex
	sessions    map[string]*AuthSessionState
	ttl         time.Duration
	maxSessions int
}

func NewCorrelationStore(ttl time.Duration) *CorrelationStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	store := &CorrelationStore{
		sessions:    make(map[string]*AuthSessionState),
		ttl:         ttl,
		maxSessions: 10000,
	}
	go store.cleanupExpired()
	return store
}

func (s *CorrelationStore) Create(state *AuthSessionState) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	maxCap := s.maxSessions
	if maxCap <= 0 {
		maxCap = 10000
	}
	now := time.Now().UTC()
	if len(s.sessions) >= maxCap {
		for id, st := range s.sessions {
			if now.After(st.ExpiresAt) || st.Consumed {
				delete(s.sessions, id)
			}
		}
		if len(s.sessions) >= maxCap {
			return "", ErrCorrelationStoreFull
		}
	}

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	sessionID := hex.EncodeToString(tokenBytes)

	csrfBytes := make([]byte, 24)
	if _, err := rand.Read(csrfBytes); err != nil {
		return "", err
	}
	state.CSRFToken = hex.EncodeToString(csrfBytes)

	state.SessionID = sessionID
	state.CreatedAt = now
	state.ExpiresAt = now.Add(s.ttl)
	state.Consumed = false

	s.sessions[sessionID] = state
	return sessionID, nil
}

func (s *CorrelationStore) Get(sessionID string) (*AuthSessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().UTC().After(state.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	if state.Consumed {
		return nil, ErrSessionConsumed
	}

	return state, nil
}

func (s *CorrelationStore) Update(sessionID string, state *AuthSessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if existing.Consumed {
		return ErrSessionConsumed
	}

	state.SessionID = sessionID
	s.sessions[sessionID] = state
	return nil
}

func (s *CorrelationStore) Consume(sessionID string) (*AuthSessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().UTC().After(state.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, ErrSessionExpired
	}

	if state.Consumed {
		return nil, ErrSessionConsumed
	}

	state.Consumed = true
	return state, nil
}

func (s *CorrelationStore) cleanupExpired() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now().UTC()
		for id, st := range s.sessions {
			if now.After(st.ExpiresAt) || st.Consumed {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

