package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// Webhook delivery headers. The signature covers the timestamp as well as the
// body, so a captured request cannot be replayed later.
const (
	WebhookSignatureHeader = "X-Auth-Signature"
	WebhookTimestampHeader = "X-Auth-Timestamp"
	WebhookEventIDHeader   = "X-Auth-Event-Id"
	WebhookEventTypeHeader = "X-Auth-Event-Type"
	// WebhookSignatureScheme prefixes the signature header value.
	WebhookSignatureScheme = "v1="
)

// DefaultWebhookTolerance is how far a delivery's signed timestamp may be from
// the receiving clock.
const DefaultWebhookTolerance = 5 * time.Minute

// PullEventsParams reads the application's change stream from a cursor. After
// is the previous page's Next; zero starts at the oldest retained event. Types
// filters the page by the closed event vocabulary and may name at most
// MaxEventTypeFilters types.
type PullEventsParams struct {
	After int64
	Limit int
	Types []EventType
}

// PullEvents reads this application's change stream (events:read). The pull is
// the record and a webhook is only notification, so an application that missed
// a delivery reads the same event back from its own cursor and deduplicates on
// the event ID.
//
// Only Next is a cursor: the event ID and the source's own sequence are not.
// A cursor older than the 30-day retention window answers snapshot_required
// (ErrorSnapshotRequired) and the caller must rebuild its snapshot instead of
// skipping the gap.
func (c *Client) PullEvents(ctx context.Context, machineToken string, params PullEventsParams) (*EventPageResponse, error) {
	query, err := pageQuery(params.After, params.Limit)
	if err != nil {
		return nil, err
	}
	if len(params.Types) > MaxEventTypeFilters {
		return nil, invalid("Types", "must contain at most 8 event types")
	}
	for _, eventType := range params.Types {
		if !eventType.valid() {
			return nil, invalid("Types", "contains an event type outside the vocabulary")
		}
		query.Add("type", string(eventType))
	}
	response, err := readResource[EventPage](ctx, c, request{
		method: http.MethodGet, path: "/events", query: query,
		cred: credentialMachineToken, token: machineToken,
	})
	if err != nil {
		return nil, err
	}
	if response.Data.Events == nil {
		return nil, invalidResponse("missing event list")
	}
	if response.Data.Next < 0 {
		return nil, invalidResponse("negative event cursor")
	}
	return response, nil
}

// SignWebhookSignature returns the signature one delivery carries: the
// HMAC-SHA256 of "<timestamp>.<body>" under the subscription's signing key.
func SignWebhookSignature(secret []byte, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return WebhookSignatureScheme + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature authenticates one delivery. The body must be the raw
// request body, read before any parsing, and the timestamp must be inside the
// tolerance window; the comparison is constant time. An empty secret rejects
// every delivery rather than accepting one.
//
// Delivery is at least once, so a receiver deduplicates on WebhookEventIDHeader
// and tolerates the same event arriving twice.
func VerifyWebhookSignature(secret, body []byte, timestamp int64, signature string, now time.Time, tolerance time.Duration) bool {
	if len(secret) == 0 || tolerance <= 0 {
		return false
	}
	drift := now.Unix() - timestamp
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > tolerance {
		return false
	}
	expected := SignWebhookSignature(secret, timestamp, body)
	return hmac.Equal([]byte(expected), []byte(signature))
}
