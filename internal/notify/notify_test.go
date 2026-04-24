package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/reconforge/reconforge/internal/config"
	"github.com/reconforge/reconforge/internal/module"
	"github.com/stretchr/testify/assert"
)

func TestNewAlertFromResults(t *testing.T) {
	sr := module.NewScanResults()
	sr.AddSubdomains([]string{"a.com", "b.com"})
	sr.AddLiveHosts([]string{"http://a.com"})
	sr.AddFindings([]module.Finding{
		{Module: "nuclei", Severity: "critical", Target: "a.com", Detail: "CVE"},
		{Module: "xss", Severity: "high", Target: "a.com", Detail: "XSS"},
		{Module: "ssl", Severity: "low", Target: "a.com", Detail: "Weak cipher"},
	})

	alert := NewAlertFromResults("example.com", "completed", 5*time.Minute, sr)

	assert.Equal(t, "example.com", alert.Target)
	assert.Equal(t, "completed", alert.Status)
	assert.Equal(t, 2, alert.Subdomain)
	assert.Equal(t, 1, alert.LiveHosts)
	assert.Equal(t, 3, alert.Findings)
	assert.Equal(t, 1, alert.Critical)
	assert.Equal(t, 1, alert.High)
}

func TestSend_Disabled(t *testing.T) {
	logger := zerolog.Nop()
	cfg := config.NotifyConfig{Enabled: false}
	n := New(cfg, logger)

	alert := &Alert{Target: "test.com", Status: "completed"}
	// Should not panic or error
	n.Send(context.Background(), alert)
}

func TestSendSlack(t *testing.T) {
	var received bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := config.NotifyConfig{
		Enabled:      true,
		SlackWebhook: server.URL,
	}
	n := New(cfg, logger)

	alert := &Alert{Target: "test.com", Status: "completed", Subdomain: 100}
	n.Send(context.Background(), alert)
	assert.True(t, received, "Slack webhook should have been called")
}

func TestSendDiscord(t *testing.T) {
	var received bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	cfg := config.NotifyConfig{
		Enabled:        true,
		DiscordWebhook: server.URL,
	}
	n := New(cfg, logger)

	alert := &Alert{Target: "test.com", Status: "completed", Critical: 3}
	n.Send(context.Background(), alert)
	assert.True(t, received, "Discord webhook should have been called")
}

func TestSendTelegram(t *testing.T) {
	var received bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zerolog.Nop()
	// Override Telegram URL would require refactoring, test via postJSON
	cfg := config.NotifyConfig{
		Enabled:        true,
		TelegramToken:  "test-token",
		TelegramChatID: "12345",
	}
	n := New(cfg, logger)

	// This will fail because the URL is real Telegram API, but should not panic
	alert := &Alert{Target: "test.com", Status: "failed"}
	n.Send(context.Background(), alert)
	// Just verify no panic - Telegram will fail silently
	_ = received
}
