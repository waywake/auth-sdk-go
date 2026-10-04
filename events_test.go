package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPullEventsRequest(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"next":21,"events":[{"id":20,"sequence":20,"type":"user.updated","subject":"user","subject_id":7,"occurred_at":"2026-09-30T10:00:00Z","expires_at":"2026-10-30T10:00:00Z","data":{"user_id":7}}],"has_more":true},"request_id":"r"}`)
	page, err := c.PullEvents(context.Background(), testMachineToken, PullEventsParams{
		After: 12, Limit: 10, Types: []EventType{EventUserUpdated, EventSessionRevoked, EventExternalIdentityChanged},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := m.only(t)
	if request.method != http.MethodGet || request.path != apiPath+"/events" || request.token != bearer(testMachineToken) {
		t.Fatalf("request=%+v", request)
	}
	if got := request.query["type"]; len(got) != 3 || got[0] != "user.updated" || got[1] != "session.revoked" || got[2] != "external_identity.changed" {
		t.Fatalf("type=%v", got)
	}
	if request.query.Get("after") != "12" || request.query.Get("limit") != "10" {
		t.Fatalf("query=%v", request.query)
	}
	if page.Data.Next != 21 || !page.Data.HasMore || len(page.Data.Events) != 1 {
		t.Fatalf("page=%+v", page)
	}
	event := page.Data.Events[0]
	if event.ID != 20 || event.Sequence != 20 || event.Type != EventUserUpdated || event.Subject != EventSubjectUser ||
		event.SubjectID != 7 || event.OccurredAt.IsZero() || event.ExpiresAt.IsZero() || event.Data["user_id"] != float64(7) {
		t.Fatalf("event=%+v", event)
	}
}

func TestPullEventsWithoutFilters(t *testing.T) {
	c, m := jsonMock(t, `{"data":{"next":0,"events":[],"has_more":false},"request_id":"r"}`)
	if _, err := c.PullEvents(context.Background(), testMachineToken, PullEventsParams{}); err != nil {
		t.Fatal(err)
	}
	if query := m.only(t).query; len(query) != 0 {
		t.Fatalf("query=%v", query)
	}
}

func TestPullEventsSnapshotRequired(t *testing.T) {
	c, _ := errorMock(t, 410, ErrorSnapshotRequired)
	_, err := c.PullEvents(context.Background(), testMachineToken, PullEventsParams{After: 1})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 410 || apiErr.Code != ErrorSnapshotRequired {
		t.Fatalf("err=%v", err)
	}
}

func TestPullEventsValidation(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	if _, err := c.PullEvents(ctx, testMachineToken, PullEventsParams{Types: []EventType{"user.renamed"}}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("accepted an event type outside the vocabulary")
	}
	tooMany := make([]EventType, MaxEventTypeFilters+1)
	for i := range tooMany {
		tooMany[i] = EventUserUpdated
	}
	if _, err := c.PullEvents(ctx, testMachineToken, PullEventsParams{Types: tooMany}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("accepted more filters than the server allows")
	}
	if _, err := c.PullEvents(ctx, testMachineToken, PullEventsParams{Limit: 201}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("accepted an oversized page")
	}
	if len(EventTypes()) != 24 {
		t.Fatalf("event vocabulary has %d entries", len(EventTypes()))
	}
	for _, eventType := range EventTypes() {
		if !eventType.valid() {
			t.Fatalf("%s is not valid", eventType)
		}
	}
}

func TestInvalidEventPage(t *testing.T) {
	c, _ := jsonMock(t, `{"data":{"next":0,"has_more":false},"request_id":"r"}`)
	if _, err := c.PullEvents(context.Background(), testMachineToken, PullEventsParams{}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted a page without events")
	}
	c, _ = jsonMock(t, `{"data":{"next":-1,"events":[],"has_more":false},"request_id":"r"}`)
	if _, err := c.PullEvents(context.Background(), testMachineToken, PullEventsParams{}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("accepted a negative cursor")
	}
}

func TestWebhookSignature(t *testing.T) {
	secret := []byte("oaw_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
	body := []byte(`{"id":20,"type":"user.updated"}`)
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	signature := SignWebhookSignature(secret, now.Unix(), body)
	if !strings.HasPrefix(signature, WebhookSignatureScheme) {
		t.Fatalf("signature=%q", signature)
	}
	if !VerifyWebhookSignature(secret, body, now.Unix(), signature, now, DefaultWebhookTolerance) {
		t.Fatal("a fresh delivery was refused")
	}
	// The timestamp is inside the signed material, so neither half can be
	// changed without invalidating the signature.
	if VerifyWebhookSignature(secret, body, now.Add(time.Minute).Unix(), signature, now, DefaultWebhookTolerance) {
		t.Fatal("a replayed timestamp was accepted")
	}
	if VerifyWebhookSignature(secret, []byte(`{"id":21}`), now.Unix(), signature, now, DefaultWebhookTolerance) {
		t.Fatal("a modified body was accepted")
	}
	if VerifyWebhookSignature([]byte("other"), body, now.Unix(), signature, now, DefaultWebhookTolerance) {
		t.Fatal("a wrong secret was accepted")
	}
	if VerifyWebhookSignature(nil, body, now.Unix(), signature, now, DefaultWebhookTolerance) {
		t.Fatal("an empty secret was accepted")
	}
	if VerifyWebhookSignature(secret, body, now.Unix(), strings.TrimPrefix(signature, WebhookSignatureScheme), now, DefaultWebhookTolerance) {
		t.Fatal("a signature without its scheme was accepted")
	}
	if VerifyWebhookSignature(secret, body, now.Unix(), signature, now.Add(2*DefaultWebhookTolerance), DefaultWebhookTolerance) {
		t.Fatal("a delivery outside the tolerance window was accepted")
	}
	if VerifyWebhookSignature(secret, body, now.Add(-time.Minute).Unix(), signature, now, DefaultWebhookTolerance) {
		t.Fatal("a signature computed over another timestamp was accepted")
	}
	// A delivery signed slightly in the past or future stays acceptable inside
	// the window, and the clock skew is measured in both directions.
	for _, offset := range []time.Duration{-time.Minute, time.Minute} {
		stamp := now.Add(offset)
		if !VerifyWebhookSignature(secret, body, stamp.Unix(), SignWebhookSignature(secret, stamp.Unix(), body), now, DefaultWebhookTolerance) {
			t.Fatalf("a delivery %s from now was refused", offset)
		}
	}
	if VerifyWebhookSignature(secret, body, now.Unix(), signature, now, 0) {
		t.Fatal("a zero tolerance was accepted")
	}
}
