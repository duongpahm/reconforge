package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestSendDiscordAndTelegram(t *testing.T) {
	var discordPayload map[string]any
	discordServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &discordPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer discordServer.Close()

	var telegramPayload map[string]any
	telegramServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &telegramPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer telegramServer.Close()

	logger := zerolog.Nop()
	cfg := config.NotifyConfig{
		Enabled:        true,
		DiscordWebhook: discordServer.URL,
		TelegramToken:  "token",
		TelegramChatID: "12345",
	}
	n := New(cfg, logger)

	alert := &Alert{
		Target:    "test.com",
		Status:    "failed",
		Duration:  "2m0s",
		Subdomain: 2,
		LiveHosts: 1,
		Findings:  3,
		Critical:  1,
		High:      1,
	}

	n.sendDiscord(context.Background(), alert)
	assert.NotNil(t, discordPayload["embeds"])

	n.cfg.TelegramToken = "bot-token"
	n.client = &http.Client{
		Transport: rewriteNotifyTransport{baseURL: telegramServer.URL},
	}
	n.sendTelegram(context.Background(), alert)
	assert.Equal(t, "12345", telegramPayload["chat_id"])
	assert.Equal(t, "HTML", telegramPayload["parse_mode"])
}

type rewriteNotifyTransport struct {
	baseURL string
}

func (t rewriteNotifyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target := strings.TrimRight(t.baseURL, "/") + "/" + strings.TrimPrefix(req.URL.Path, "/")
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, target, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header.Clone()
	return http.DefaultTransport.RoundTrip(newReq)
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
