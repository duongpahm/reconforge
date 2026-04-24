package scope

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilter_ShouldInclude_Basic(t *testing.T) {
	f := NewFilter(nil, false)
	assert.True(t, f.ShouldInclude("example.com"))
	assert.True(t, f.ShouldInclude("other.com"))
}

func TestFilter_ShouldInclude_EmptyDomain(t *testing.T) {
	f := NewFilter(nil, false)
	assert.False(t, f.ShouldInclude(""))
	assert.False(t, f.ShouldInclude("   "))
}

func TestFilter_ShouldInclude_Deduplication(t *testing.T) {
	f := NewFilter(nil, false)
	assert.True(t, f.ShouldInclude("example.com"))
	assert.False(t, f.ShouldInclude("example.com"), "second occurrence should be excluded")
	assert.False(t, f.ShouldInclude("EXAMPLE.COM"), "case-insensitive dedup")
}

func TestFilter_ShouldInclude_ScopeFiltering(t *testing.T) {
	s := &Scope{InScope: []string{"example.com"}}
	f := NewFilter(s, false)

	assert.True(t, f.ShouldInclude("sub.example.com"))
	assert.False(t, f.ShouldInclude("other.com"))
}

func TestFilter_ShouldInclude_SensitiveExcluded(t *testing.T) {
	f := NewFilter(nil, true)

	// Sensitive TLDs should be excluded
	assert.False(t, f.ShouldInclude("agency.gov"))
	assert.False(t, f.ShouldInclude("base.mil"))
	assert.True(t, f.ShouldInclude("example.com"))
}

func TestFilter_FilterDomains(t *testing.T) {
	f := NewFilter(nil, false)
	domains := []string{
		"example.com",
		"sub.example.com",
		"example.com", // duplicate
		"other.com",
		"",
	}

	result := f.FilterDomains(domains)
	assert.Len(t, result, 3)
	assert.Contains(t, result, "example.com")
	assert.Contains(t, result, "sub.example.com")
	assert.Contains(t, result, "other.com")
	assert.NotContains(t, result, "")
}

func TestFilter_FilterDomains_Empty(t *testing.T) {
	f := NewFilter(nil, false)
	result := f.FilterDomains(nil)
	assert.Nil(t, result)
}

func TestFilter_Reset(t *testing.T) {
	f := NewFilter(nil, false)

	assert.True(t, f.ShouldInclude("example.com"))
	assert.False(t, f.ShouldInclude("example.com"), "should be deduped")

	f.Reset()

	assert.True(t, f.ShouldInclude("example.com"), "should be included again after reset")
}
