package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		s    Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.s.String())
	}
}

func TestParseSeverity(t *testing.T) {
	assert.Equal(t, SeverityInfo, ParseSeverity("info"))
	assert.Equal(t, SeverityLow, ParseSeverity("low"))
	assert.Equal(t, SeverityMedium, ParseSeverity("medium"))
	assert.Equal(t, SeverityHigh, ParseSeverity("high"))
	assert.Equal(t, SeverityCritical, ParseSeverity("critical"))
	assert.Equal(t, SeverityInfo, ParseSeverity("unknown-val")) // default
	assert.Equal(t, SeverityInfo, ParseSeverity(""))
}

func TestFinding_IsNew(t *testing.T) {
	now := time.Now()
	f := Finding{FoundAt: now}

	assert.True(t, f.IsNew(now.Add(-1*time.Second)))
	assert.False(t, f.IsNew(now.Add(1*time.Second)))
	assert.False(t, f.IsNew(now))
}

func TestFinding_HasTag(t *testing.T) {
	f := Finding{Tags: []string{"xss", "reflected", "high"}}

	assert.True(t, f.HasTag("xss"))
	assert.True(t, f.HasTag("reflected"))
	assert.False(t, f.HasTag("sqli"))
	assert.False(t, f.HasTag(""))
}

func TestFinding_HasTag_Empty(t *testing.T) {
	f := Finding{}
	assert.False(t, f.HasTag("anything"))
}

func TestFinding_SeverityAtLeast(t *testing.T) {
	f := Finding{Severity: SeverityHigh}

	assert.True(t, f.SeverityAtLeast(SeverityInfo))
	assert.True(t, f.SeverityAtLeast(SeverityLow))
	assert.True(t, f.SeverityAtLeast(SeverityMedium))
	assert.True(t, f.SeverityAtLeast(SeverityHigh))
	assert.False(t, f.SeverityAtLeast(SeverityCritical))
}
