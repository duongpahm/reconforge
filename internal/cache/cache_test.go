package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCache(t *testing.T) *FileCache {
	t.Helper()
	c, err := NewFileCache(t.TempDir())
	require.NoError(t, err)
	return c
}

func TestFileCache_SetGet(t *testing.T) {
	c := newTestCache(t)

	err := c.Set("resolvers", []byte("1.1.1.1\n8.8.8.8"), 1*time.Hour)
	require.NoError(t, err)

	data, found := c.Get("resolvers")
	assert.True(t, found)
	assert.Equal(t, "1.1.1.1\n8.8.8.8", string(data))
}

func TestFileCache_Expired(t *testing.T) {
	c := newTestCache(t)

	err := c.Set("temp", []byte("data"), 1*time.Millisecond)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	_, found := c.Get("temp")
	assert.False(t, found, "expired entry should not be returned")
}

func TestFileCache_Has(t *testing.T) {
	c := newTestCache(t)

	assert.False(t, c.Has("nonexistent"))

	c.Set("exists", []byte("yes"), 1*time.Hour)
	assert.True(t, c.Has("exists"))
}

func TestFileCache_Delete(t *testing.T) {
	c := newTestCache(t)

	c.Set("key", []byte("value"), 1*time.Hour)
	assert.True(t, c.Has("key"))

	c.Delete("key")
	assert.False(t, c.Has("key"))
}

func TestFileCache_Age(t *testing.T) {
	c := newTestCache(t)

	c.Set("key", []byte("value"), 1*time.Hour)
	time.Sleep(10 * time.Millisecond)

	age := c.Age("key")
	assert.Greater(t, age, time.Duration(0))
	assert.Less(t, age, 1*time.Second)
}

func TestFileCache_Size(t *testing.T) {
	c := newTestCache(t)

	assert.Equal(t, 0, c.Size())

	c.Set("a", []byte("1"), 1*time.Hour)
	c.Set("b", []byte("2"), 1*time.Hour)
	assert.Equal(t, 2, c.Size())
}

func TestFileCache_Cleanup(t *testing.T) {
	c := newTestCache(t)

	c.Set("expired1", []byte("old"), 1*time.Millisecond)
	c.Set("expired2", []byte("old"), 1*time.Millisecond)
	c.Set("valid", []byte("fresh"), 1*time.Hour)

	time.Sleep(10 * time.Millisecond)

	removed, err := c.Cleanup()
	require.NoError(t, err)
	assert.Equal(t, 2, removed)
	assert.Equal(t, 1, c.Size())
	assert.True(t, c.Has("valid"))
}

func TestFileCache_NotFound(t *testing.T) {
	c := newTestCache(t)

	data, found := c.Get("nonexistent")
	assert.False(t, found)
	assert.Nil(t, data)

	age := c.Age("nonexistent")
	assert.Equal(t, time.Duration(0), age)
}

func TestFileCache_OverwriteKey(t *testing.T) {
	c := newTestCache(t)

	c.Set("key", []byte("v1"), 1*time.Hour)
	c.Set("key", []byte("v2"), 1*time.Hour)

	data, found := c.Get("key")
	assert.True(t, found)
	assert.Equal(t, "v2", string(data))
}
