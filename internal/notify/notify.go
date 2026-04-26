// Package notify sends scan notifications via webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/duongpahm/ReconForge/internal/config"
	"github.com/duongpahm/ReconForge/internal/module"
)

// Notifier sends scan results to configured channels.
type Notifier struct {
	cfg    config.NotifyConfig
	logger zerolog.Logger
	client *http.Client
}

// New creates a new Notifier.
func New(cfg config.NotifyConfig, logger zerolog.Logger) *Notifier {
	return &Notifier{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Alert holds the notification payload.
type Alert struct {
	Target    string `json:"target"`
	Status    string `json:"status"` // completed, failed
	Duration  string `json:"duration"`
	Subdomain int    `json:"subdomains"`
	LiveHosts int    `json:"live_hosts"`
	Findings  int    `json:"findings"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
}

// NewAlertFromResults creates an Alert from scan results.
func NewAlertFromResults(target, status string, duration time.Duration, results *module.ScanResults) *Alert {
	findings := results.GetFindings()
	critical, high := 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		}
	}

	return &Alert{
		Target:    target,
		Status:    status,
		Duration:  duration.Round(time.Second).String(),
		Subdomain: results.SubdomainCount(),
		LiveHosts: len(results.GetLiveHosts()),
		Findings:  len(findings),
		Critical:  critical,
		High:      high,
	}
}

// Send sends the alert to all configured channels.
func (n *Notifier) Send(ctx context.Context, alert *Alert) {
	if !n.cfg.Enabled {
		return
	}

	if n.cfg.SlackWebhook != "" {
		n.sendSlack(ctx, alert)
	}
	if n.cfg.DiscordWebhook != "" {
		n.sendDiscord(ctx, alert)
	}
	if n.cfg.TelegramToken != "" && n.cfg.TelegramChatID != "" {
		n.sendTelegram(ctx, alert)
	}
}

func (n *Notifier) sendSlack(ctx context.Context, alert *Alert) {
	emoji := "[+]"
	if alert.Status == "failed" {
		emoji = "[-]"
	}

	text := fmt.Sprintf(
		"%s *ReconForge Scan %s*\n"+
			"*Target:* `%s`\n"+
			"*Duration:* %s\n"+
			"*Subdomains:* %d | *Live:* %d | *Findings:* %d\n"+
			"*Critical:* %d | *High:* %d",
		emoji, alert.Status, alert.Target, alert.Duration,
		alert.Subdomain, alert.LiveHosts, alert.Findings,
		alert.Critical, alert.High,
	)

	payload := map[string]string{"text": text}
	n.postJSON(ctx, n.cfg.SlackWebhook, payload, "Slack")
}

func (n *Notifier) sendDiscord(ctx context.Context, alert *Alert) {
	color := 0x00ff00 // green
	if alert.Status == "failed" {
		color = 0xff0000
	} else if alert.Critical > 0 {
		color = 0xff4500
	}

	embed := map[string]interface{}{
		"title":       fmt.Sprintf("ReconForge — %s", alert.Target),
		"description": fmt.Sprintf("Scan %s in %s", alert.Status, alert.Duration),
		"color":       color,
		"fields": []map[string]interface{}{
			{"name": "Subdomains", "value": fmt.Sprintf("%d", alert.Subdomain), "inline": true},
			{"name": "Live Hosts", "value": fmt.Sprintf("%d", alert.LiveHosts), "inline": true},
			{"name": "Findings", "value": fmt.Sprintf("%d", alert.Findings), "inline": true},
			{"name": "Critical", "value": fmt.Sprintf("%d", alert.Critical), "inline": true},
			{"name": "High", "value": fmt.Sprintf("%d", alert.High), "inline": true},
		},
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}
	n.postJSON(ctx, n.cfg.DiscordWebhook, payload, "Discord")
}

func (n *Notifier) sendTelegram(ctx context.Context, alert *Alert) {
	emoji := "[+]"
	if alert.Status == "failed" {
		emoji = "[-]"
	}

	text := fmt.Sprintf(
		"%s <b>ReconForge Scan %s</b>\n"+
			"<b>Target:</b> <code>%s</code>\n"+
			"<b>Duration:</b> %s\n"+
			"Subdomains: %d | Live: %d | Findings: %d\n"+
			"🔴 Critical: %d | 🟠 High: %d",
		emoji, alert.Status, alert.Target, alert.Duration,
		alert.Subdomain, alert.LiveHosts, alert.Findings,
		alert.Critical, alert.High,
	)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.TelegramToken)
	payload := map[string]string{
		"chat_id":    n.cfg.TelegramChatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	n.postJSON(ctx, url, payload, "Telegram")
}

func (n *Notifier) postJSON(ctx context.Context, url string, payload interface{}, channel string) {
	data, err := json.Marshal(payload)
	if err != nil {
		n.logger.Error().Err(err).Str("channel", channel).Msg("Failed to marshal notification")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		n.logger.Error().Err(err).Str("channel", channel).Msg("Failed to create notification request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		n.logger.Warn().Err(err).Str("channel", channel).Msg("Failed to send notification")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		n.logger.Warn().
			Str("channel", channel).
			Int("status", resp.StatusCode).
			Msg("Notification webhook returned error")
		return
	}

	n.logger.Info().Str("channel", channel).Msg("Notification sent")
}
