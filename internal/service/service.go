package service

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"scanvault/internal/audit"
	"scanvault/internal/crypto"
	"scanvault/internal/store"
)

var ErrSessionLimit = errors.New("record resource limit reached")

type SessionPool struct {
	mu     sync.Mutex
	active int
	limit  int
}

func NewSessionPool(limit int) *SessionPool {
	if limit < 1 {
		limit = 1
	}
	return &SessionPool{limit: limit}
}

func (p *SessionPool) Acquire() (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active >= p.limit {
		return nil, ErrSessionLimit
	}
	p.active++
	released := false
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if released {
			return
		}
		released = true
		if p.active > 0 {
			p.active--
		}
	}, nil
}

func (p *SessionPool) Active() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

type Service struct {
	Store   *store.Store
	Sealer  *crypto.Sealer
	Audit   *audit.Recorder
	Pool    *SessionPool
	Stamp   string
	Counter int
	mu      sync.Mutex
}

func New(database *store.Store, namespace, stamp string) *Service {
	if strings.TrimSpace(stamp) == "" {
		stamp = "2026-01-01T00:00:00Z"
	}
	return &Service{
		Store:  database,
		Sealer: crypto.NewSealer(namespace),
		Audit:  audit.NewRecorder(database, stamp),
		Pool:   NewSessionPool(1),
		Stamp:  stamp,
	}
}

func (s *Service) nextID(kind string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Counter++
	return fmt.Sprintf("%s-%04d", kind, s.Counter)
}

func (s *Service) OpenRecord() (func(), error) {
	return s.Pool.Acquire()
}

func (s *Service) StorePath() string {
	if s.Store == nil {
		return ""
	}
	return s.Store.Path()
}

func (s *Service) ActiveSessions() int {
	if s.Pool == nil {
		return 0
	}
	return s.Pool.Active()
}

func (s *Service) ValidateOperator(operator string) error {
	if strings.TrimSpace(operator) == "" {
		return errors.New("operator is required")
	}
	if len(operator) > 80 {
		return errors.New("operator is too long")
	}
	return nil
}
