package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

var ErrNotFound = errors.New("record not found")

type Store struct {
	db     *bbolt.DB
	path   string
	closed bool
	mu     sync.RWMutex
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if directory := filepath.Dir(path); directory != "." {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt store: %w", err)
	}
	store := &Store{db: db, path: path}
	if err := store.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) initialize() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, name := range bucketNames() {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	})
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

func (s *Store) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

func (s *Store) View(fn func(*bbolt.Tx) error) error {
	if fn == nil {
		return errors.New("view callback is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("store is closed")
	}
	return s.db.View(fn)
}

func (s *Store) Update(fn func(*bbolt.Tx) error) error {
	if fn == nil {
		return errors.New("update callback is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("store is closed")
	}
	return s.db.Update(fn)
}

func (s *Store) Put(bucket, key string, value []byte) error {
	if bucket == "" || key == "" {
		return errors.New("bucket and key are required")
	}
	return s.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %s does not exist", bucket)
		}
		return b.Put([]byte(key), value)
	})
}

func (s *Store) Get(bucket, key string) ([]byte, error) {
	if bucket == "" || key == "" {
		return nil, errors.New("bucket and key are required")
	}
	var result []byte
	err := s.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %s does not exist", bucket)
		}
		value := b.Get([]byte(key))
		if value == nil {
			return ErrNotFound
		}
		result = append([]byte(nil), value...)
		return nil
	})
	return result, err
}

func (s *Store) Delete(bucket, key string) error {
	return s.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %s does not exist", bucket)
		}
		return b.Delete([]byte(key))
	})
}
