// Package cache provides file-based caching with TTL support.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Entry represents a cached item with metadata.
type Entry struct {
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	DataFile  string    `json:"data_file"` // relative path within cache dir
}

// FileCache provides file-based caching with TTL.
type FileCache struct {
	dir string
}

// NewFileCache creates a new file cache in the given directory.
func NewFileCache(dir string) (*FileCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &FileCache{dir: dir}, nil
}

// Get retrieves a cached value by key. Returns nil if not found or expired.
func (c *FileCache) Get(key string) ([]byte, bool) {
	entry, err := c.getEntry(key)
	if err != nil || entry == nil {
		return nil, false
	}

	// Check expiry
	if time.Now().After(entry.ExpiresAt) {
		c.Delete(key) // cleanup expired
		return nil, false
	}

	dataPath := filepath.Join(c.dir, entry.DataFile)
	data, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, false
	}

	return data, true
}

// Set stores a value with the given TTL.
func (c *FileCache) Set(key string, data []byte, ttl time.Duration) error {
	hash := keyHash(key)
	dataFile := hash + ".data"

	entry := &Entry{
		Key:       key,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
		DataFile:  dataFile,
	}

	// Write data file
	dataPath := filepath.Join(c.dir, dataFile)
	if err := os.WriteFile(dataPath, data, 0o644); err != nil {
		return fmt.Errorf("write cache data: %w", err)
	}

	// Write metadata
	metaPath := filepath.Join(c.dir, hash+".meta.json")
	metaData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal cache meta: %w", err)
	}

	return os.WriteFile(metaPath, metaData, 0o644)
}

// Has checks if a non-expired key exists in the cache.
func (c *FileCache) Has(key string) bool {
	_, found := c.Get(key)
	return found
}

// Delete removes a cached entry.
func (c *FileCache) Delete(key string) error {
	hash := keyHash(key)

	dataPath := filepath.Join(c.dir, hash+".data")
	metaPath := filepath.Join(c.dir, hash+".meta.json")

	os.Remove(dataPath)
	os.Remove(metaPath)

	return nil
}

// Age returns how old a cached entry is. Returns 0 if not found.
func (c *FileCache) Age(key string) time.Duration {
	entry, err := c.getEntry(key)
	if err != nil || entry == nil {
		return 0
	}
	return time.Since(entry.CreatedAt)
}

// Cleanup removes all expired entries.
func (c *FileCache) Cleanup() (int, error) {
	entries, err := filepath.Glob(filepath.Join(c.dir, "*.meta.json"))
	if err != nil {
		return 0, fmt.Errorf("glob cache dir: %w", err)
	}

	removed := 0
	for _, metaPath := range entries {
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}

		if time.Now().After(entry.ExpiresAt) {
			hash := filepath.Base(metaPath)
			hash = hash[:len(hash)-len(".meta.json")]

			os.Remove(filepath.Join(c.dir, hash+".data"))
			os.Remove(metaPath)
			removed++
		}
	}

	return removed, nil
}

// Size returns the total number of entries (including expired).
func (c *FileCache) Size() int {
	entries, err := filepath.Glob(filepath.Join(c.dir, "*.meta.json"))
	if err != nil {
		return 0
	}
	return len(entries)
}

func (c *FileCache) getEntry(key string) (*Entry, error) {
	hash := keyHash(key)
	metaPath := filepath.Join(c.dir, hash+".meta.json")

	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

func keyHash(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:16]) // 32 chars
}
