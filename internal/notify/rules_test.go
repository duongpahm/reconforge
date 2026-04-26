package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/duongpahm/ReconForge/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleMatches(t *testing.T) {
	finding := models.Finding{
		Title:       "Critical RCE",
		Module:      "nuclei",
		Severity:    "critical",
		Fingerprint: "abcdef123456",
	}

	rule := Rule{
		Target:      `acme\.test`,
		MinSeverity: "high",
		Keywords:    []string{"rce", "ssrf"},
	}
	assert.True(t, rule.Matches("acme.test", finding))

	assert.False(t, (&Rule{Target: "["}).Matches("acme.test", finding))
	assert.False(t, (&Rule{Target: `other\.test`}).Matches("acme.test", finding))
	assert.False(t, (&Rule{MinSeverity: "critical"}).Matches("acme.test", models.Finding{Severity: "medium"}))
	assert.False(t, (&Rule{Keywords: []string{"xss"}}).Matches("acme.test", finding))
}

func TestRuleEngineLoadSaveAndGetTriggeredRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify_rules.json")

	engine := &RuleEngine{
		Rules: []Rule{
			{ID: "r1", Name: "critical", MinSeverity: "critical"},
			{ID: "r2", Name: "web", Keywords: []string{"nuclei"}},
		},
	}
	require.NoError(t, engine.SaveRules(path))

	loaded, err := LoadRules(path)
	require.NoError(t, err)
	require.Len(t, loaded.Rules, 2)

	triggered := loaded.GetTriggeredRules("acme.test", models.Finding{
		Severity: "critical",
		Module:   "nuclei",
		Title:    "Critical issue",
	})
	require.Len(t, triggered, 2)

	empty, err := LoadRules(filepath.Join(t.TempDir(), "missing.json"))
	require.NoError(t, err)
	assert.Empty(t, empty.Rules)
}

func TestProcessDeltaAndSendRuleWebhook(t *testing.T) {
	var calls int
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := &RuleEngine{
		Rules: []Rule{
			{
				ID:          "r1",
				Name:        "critical-web",
				Target:      `acme\.test`,
				MinSeverity: "high",
				Keywords:    []string{"rce"},
				WebhookURL:  server.URL,
			},
		},
	}

	engine.ProcessDelta("acme.test", []models.Finding{
		{
			Title:       "Critical RCE",
			Severity:    "critical",
			Module:      "nuclei",
			URL:         "https://app.acme.test",
			Fingerprint: "abcdef123456",
		},
		{
			Title:       "Low info",
			Severity:    "low",
			Module:      "httpx",
			URL:         "https://app.acme.test",
			Fingerprint: "fedcba654321",
		},
	})

	assert.Equal(t, 1, calls)
	assert.Contains(t, payload["text"], "critical-web")
	assert.Contains(t, payload["text"], "Critical RCE")
}
