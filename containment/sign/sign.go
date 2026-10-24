// Package sign is the one implementation of River3's request signature, used by
// both sides of every signed hop this module takes part in:
//
//   - inbound: the API's operator-action webhook (controller.Server verifies it);
//   - outbound: the gateway session adapter (adapter.Gateway signs with it).
//
// The scheme is the one api/river3_api/security.py sign_webhook produces:
//
//	X-River3-Timestamp:  unix seconds, plain decimal
//	X-River3-Delivery:   unique id per delivery (required; inside the MAC)
//	X-River3-Signature:  "sha256=" + hex( HMAC-SHA256( secret, "<ts>.<delivery>.<body>" ) )
//
// Keeping it in one package means the webhook test that pins the base string also
// pins what the gateway receives (CONTRACTS.md §2.1: "signed exactly like webhooks").
package sign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
)

// Base is the exact byte string both sides MAC: "<ts>.<delivery>.<body>". ts is the
// header text verbatim (the API writes the integer in plain decimal). The delivery id
// is inside the MAC so a captured request cannot be replayed under a fresh id, and a
// request without one is rejected rather than exempted from the replay check.
func Base(ts, delivery string, body []byte) []byte {
	b := make([]byte, 0, len(ts)+len(delivery)+len(body)+2)
	b = append(b, ts...)
	b = append(b, '.')
	b = append(b, delivery...)
	b = append(b, '.')
	return append(b, body...)
}

// Signature returns the X-River3-Signature header value for the given parts.
func Signature(secret []byte, ts, delivery string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(Base(ts, delivery, body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Headers produces the three signed headers (plus Content-Type) for a body sent at
// unix time ts under the given delivery id.
func Headers(secret, body []byte, ts int64, delivery string) http.Header {
	tsRaw := strconv.FormatInt(ts, 10)
	h := http.Header{}
	h.Set("X-River3-Timestamp", tsRaw)
	h.Set("X-River3-Signature", Signature(secret, tsRaw, delivery, body))
	h.Set("X-River3-Delivery", delivery)
	h.Set("Content-Type", "application/json")
	return h
}

// NewDelivery returns a fresh random delivery id (32 hex characters).
func NewDelivery() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("sign: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
