// Package notify sends alerts to Telegram and Discord.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Pizareis/netpulse/internal/model"
)

var client = &http.Client{Timeout: 10 * time.Second}

func format(a model.Alert) string {
	icon := map[model.Severity]string{model.Critical: "🚨", model.Warning: "⚠️", model.Info: "ℹ️"}[a.Severity]
	return fmt.Sprintf("%s NetPulse: %s\n%s\n%s", icon, a.Title, a.Detail, a.Time.Format("2006-01-02 15:04:05"))
}

func postJSON(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

type Telegram struct {
	Token  string
	ChatID string
}

func (Telegram) Name() string { return "telegram" }

func (t Telegram) Notify(ctx context.Context, a model.Alert) error {
	url := "https://api.telegram.org/bot" + t.Token + "/sendMessage"
	return postJSON(ctx, url, map[string]string{"chat_id": t.ChatID, "text": format(a)})
}

type Discord struct {
	Webhook string
}

func (Discord) Name() string { return "discord" }

func (d Discord) Notify(ctx context.Context, a model.Alert) error {
	return postJSON(ctx, d.Webhook, map[string]string{"content": format(a)})
}
