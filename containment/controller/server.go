package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"river3.local/containment/apiclient"
	"river3.local/containment/normalize"
	"river3.local/containment/sign"
	policy "river3.local/policy"
)

const (
	maxWebhookBody = 64 << 10
	maxEventBody   = 64 << 10
	webhookSkew    = 5 * time.Minute // api/river3_api/security.py: reject timestamps older than 5 minutes
	// maxSeenDeliveries bounds the replay set. Legitimate traffic is a handful of
	// operator actions per hour, so 10k ids within the ±5 min window only happens
	// under a flood; evicting the oldest then keeps memory bounded, and the timestamp
	// window still rejects anything older than the ids that were evicted.
	maxSeenDeliveries = 10_000
)

// WebhookBase is the exact string both sides sign (api/river3_api/security.py
// sign_webhook / verify_signature must build the same bytes):
//
//	"<X-River3-Timestamp>.<X-River3-Delivery>.<body>"
//
// Signature = "sha256=" + hex(HMAC-SHA256(secret, WebhookBase)). The delivery id is
// inside the MAC so a captured request cannot be replayed under a fresh id, and a
// request without one is rejected rather than exempted from the replay check.
// ts is the header text verbatim (the API writes the integer in plain decimal).
//
// The implementation lives in package sign so the gateway session adapter signs its
// outbound requests with the very same function (CONTRACTS.md §2.1).
func WebhookBase(ts, delivery string, body []byte) []byte { return sign.Base(ts, delivery, body) }

// Server exposes the controller's inbound HTTP surface. Bind it to loopback or a
// private interface; it carries a sensor token check and an HMAC check but no TLS
// of its own — put it behind the node's TLS terminator if it leaves the host.
type Server struct {
	C             *Controller
	WebhookSecret []byte // RIVER3_WEBHOOK_SECRET shared with the API; empty disables the webhook route
	Async         bool   // webhook: respond 202 and execute in the background (production); false = inline (tests)

	seenMu sync.Mutex
	seen   map[string]time.Time // X-River3-Delivery ids within the skew window
	order  []seenDelivery       // the same ids oldest first, so eviction is O(1) at the front
}

type seenDelivery struct {
	id string
	at time.Time
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/events", s.events)
	mux.HandleFunc("POST /river3/actions", s.webhook)
	mux.HandleFunc("GET /healthz", s.health)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"ok": true, "journal": s.C.Journal().Stats(), "adapter": s.C.cfg.Adapter.Name(), "sessions": s.C.SessionCounts()}
	// registry_error is always present: "" means the enrollment file on disk is the one
	// in force; anything else is why the last reload was refused (the previous snapshot
	// is still enforced, so ok stays true).
	out["registry"], out["registry_error"] = s.C.RegistryStatus()
	if s.C.cfg.Sessions != nil {
		out["session_adapter"] = s.C.cfg.Sessions.Name()
	}
	if eg := s.C.EgressStatus(); eg != nil {
		out["egress"] = eg
	}
	writeJSON(w, http.StatusOK, out)
}

// events accepts one river3d event from an authenticated sensor and runs the loop.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	sensor, ok := s.C.Registry().Get().Authenticate(token)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": "valid sensor token required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxEventBody+1))
	if err != nil || len(body) > maxEventBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"detail": "event too large"})
		return
	}
	var raw normalize.Raw
	if err := policy.DecodeStrict(body, &raw); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"detail": err.Error()})
		return
	}
	env := normalize.Envelope{Raw: raw, Sensor: sensor, Authentic: true, ReceivedAt: s.C.cfg.Clock(), Provenance: policy.Live}
	out, err := s.C.HandleEvent(r.Context(), env)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"detail": err.Error(), "event_id": raw.Facts.ID})
		return
	}
	writeJSON(w, http.StatusAccepted, out)
}

// webhook receives operator actions pushed by the API (RIVER3_ACTION_WEBHOOK).
func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	if len(s.WebhookSecret) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"detail": "webhook not configured"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil || len(body) > maxWebhookBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"detail": "body too large"})
		return
	}
	if err := s.verify(r.Header, body, s.C.cfg.Clock()); err != nil {
		s.C.cfg.Log.Warn("webhook.rejected", "err", err.Error(), "remote", r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": err.Error()})
		return
	}
	var a apiclient.OperatorAction
	if err := json.Unmarshal(body, &a); err != nil || a.ID == "" || a.WorkloadID == "" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"detail": "malformed action"})
		return
	}
	if s.Async {
		go s.C.HandleOperatorAction(contextWithoutCancel(r), a, "webhook")
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": a.ID})
		return
	}
	out := s.C.HandleOperatorAction(r.Context(), a, "webhook")
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": a.ID, "outcome": out})
}

// verify checks X-River3-Timestamp / X-River3-Delivery / X-River3-Signature exactly as
// security.sign_webhook produces them: HMAC-SHA256(secret, WebhookBase), hex, prefixed
// "sha256=". The timestamp must be within ±webhookSkew, the delivery id must be
// present, and a delivery id is accepted once: ids are remembered for the skew window
// (bounded by maxSeenDeliveries) so a captured request cannot be replayed.
func (s *Server) verify(h http.Header, body []byte, now time.Time) error {
	tsRaw := h.Get("X-River3-Timestamp")
	sig := h.Get("X-River3-Signature")
	delivery := h.Get("X-River3-Delivery")
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return errors.New("missing or malformed timestamp")
	}
	age := now.Sub(time.Unix(ts, 0))
	if age > webhookSkew || age < -webhookSkew {
		return errors.New("timestamp outside the accepted window")
	}
	// Required, not optional: an absent id used to skip the replay check entirely,
	// which made replay protection something the sender could opt out of.
	if delivery == "" || len(delivery) > 128 {
		return errors.New("missing or malformed delivery id")
	}
	if !strings.HasPrefix(sig, "sha256=") {
		return errors.New("missing signature")
	}
	want, err := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
	if err != nil {
		return errors.New("malformed signature")
	}
	mac := hmac.New(sha256.New, s.WebhookSecret)
	mac.Write(sign.Base(tsRaw, delivery, body))
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("bad signature")
	}
	// Only a correctly signed request reaches the replay set, so an attacker without
	// the secret cannot fill it with ids and evict legitimate ones.
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	for len(s.order) > 0 && (now.Sub(s.order[0].at) > webhookSkew || len(s.order) >= maxSeenDeliveries) {
		delete(s.seen, s.order[0].id)
		s.order[0] = seenDelivery{} // let the string go
		s.order = s.order[1:]
	}
	if _, dup := s.seen[delivery]; dup {
		return errors.New("replayed delivery")
	}
	s.seen[delivery] = now
	s.order = append(s.order, seenDelivery{id: delivery, at: now})
	return nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Sign produces the headers the API sends, for tests and for a local sender:
// the signature covers WebhookBase(ts, delivery, body). Same function the gateway
// adapter uses to sign its requests.
func Sign(secret, body []byte, ts int64, delivery string) http.Header {
	return sign.Headers(secret, body, ts, delivery)
}
