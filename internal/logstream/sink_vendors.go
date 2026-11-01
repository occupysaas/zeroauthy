package logstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}
func (s *httpSink) sendVendor(ctx context.Context, stream *store.LogStream, private map[string]any, items []Item) error {
	headers := http.Header{"Content-Type": []string{"application/json"}}
	var endpoint string
	var payload any
	switch stream.Type {
	case "datadog":
		domain := map[string]string{"us": "datadoghq.com", "eu": "datadoghq.eu", "us3": "us3.datadoghq.com", "us5": "us5.datadoghq.com"}[value(stream.Sink, "datadogRegion")]
		if domain == "" {
			return deliveryError("refused")
		}
		endpoint = "https://http-intake.logs." + domain + "/api/v2/logs"
		headers.Set("DD-API-KEY", value(private, "datadogApiKey"))
		rows := make([]map[string]any, 0, len(items))
		for _, item := range items {
			b, _ := json.Marshal(item)
			rows = append(rows, map[string]any{"message": string(b), "ddsource": "auth0", "service": "zeroauthy"})
		}
		payload = rows
	case "splunk":
		// splunkSecure does not disable certificate verification. Plain HTTP needs
		// the separate deployment opt-in, just like the generic HTTP adapter.
		scheme := "https"
		if secure, ok := stream.Sink["splunkSecure"].(bool); ok && !secure && s.cfg.AllowInsecureHTTP {
			scheme = "http"
		}
		endpoint = scheme + "://" + net.JoinHostPort(strings.Trim(value(stream.Sink, "splunkDomain"), "[]"), value(stream.Sink, "splunkPort")) + "/services/collector/event"
		headers.Set("Authorization", "Splunk "+value(private, "splunkToken"))
		rows := make([]map[string]any, 0, len(items))
		for _, item := range items {
			_, _, at := itemFields(item)
			rows = append(rows, map[string]any{"event": item, "time": at.Unix()})
		}
		body, err := jsonLines(rows)
		if err != nil {
			return deliveryError("refused")
		}
		return s.post(ctx, endpoint, headers, body)
	case "sumo":
		endpoint = value(private, "sumoSourceAddress")
		body, err := jsonLines(items)
		if err != nil {
			return deliveryError("refused")
		}
		return s.post(ctx, endpoint, headers, body)
	case "segment":
		endpoint = "https://api.segment.io/v1/batch"
		headers.Set("Authorization", basic(value(private, "segmentWriteKey"), ""))
		batch := make([]map[string]any, 0, len(items))
		for _, item := range items {
			typ, user, _ := itemFields(item)
			var data map[string]any
			_ = json.Unmarshal(item.Data, &data)
			row := map[string]any{"type": "track", "event": typ, "timestamp": data["date"], "messageId": item.LogID, "properties": item}
			if user != "" {
				row["userId"] = user
			} else {
				row["anonymousId"] = item.LogID
			}
			batch = append(batch, row)
		}
		payload = map[string]any{"batch": batch}
	case "mixpanel":
		host := map[string]string{"us": "api.mixpanel.com", "eu": "api-eu.mixpanel.com"}[value(stream.Sink, "mixpanelRegion")]
		if host == "" {
			return deliveryError("refused")
		}
		endpoint = "https://" + host + "/import?" + url.Values{"strict": {"1"}, "project_id": {value(stream.Sink, "mixpanelProjectId")}}.Encode()
		headers.Set("Authorization", basic(value(stream.Sink, "mixpanelServiceAccountUsername"), value(private, "mixpanelServiceAccountPassword")))
		rows := make([]map[string]any, 0, len(items))
		for _, item := range items {
			typ, user, at := itemFields(item)
			if user == "" {
				user = item.LogID
			}
			rows = append(rows, map[string]any{"event": typ, "properties": map[string]any{"log_id": item.LogID, "data": item.Data, "time": at.Unix(), "distinct_id": user, "$insert_id": item.LogID}})
		}
		payload = rows
	default:
		return deliveryError("refused")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return deliveryError("refused")
	}
	return s.post(ctx, endpoint, headers, body)
}
func itemFields(item Item) (typ, user string, at time.Time) {
	var d struct {
		Type   string `json:"type"`
		UserID string `json:"user_id"`
		Date   string `json:"date"`
	}
	_ = json.Unmarshal(item.Data, &d)
	at, _ = time.Parse(time.RFC3339Nano, d.Date)
	return d.Type, d.UserID, at
}
