package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"river3.local/containment/adapter"
	"river3.local/containment/apiclient"
	"river3.local/containment/journal"
)

func resumeReq(id string) apiclient.OperatorAction {
	return apiclient.OperatorAction{ID: id, IncidentID: "inc_1", WorkloadID: "worker-01", Action: "resume",
		Operator: "rajiv", Reason: "verified benign after review", Status: "requested"}
}

// --- resume ----------------------------------------------------------------------

func TestOperatorResumeUnpausesVerifiesAndReports(t *testing.T) {
	r := newRig(t)
	mustState(t, r.handle(r.event("ev-1", "file_open", decoyOpen("x"), "success")), journal.Verified)

	out := r.c.HandleOperatorAction(context.Background(), resumeReq("act_1"), "test")
	if out != OpCompleted || r.state(cidWorker) != adapter.Running {
		t.Fatalf("outcome %s state %s", out, r.state(cidWorker))
	}
	res, ok := r.api.result("act_1")
	if !ok || res.Status != "completed" || res.WorkloadState != "running" || res.Detail["operator"] != "rajiv" {
		t.Fatalf("result not reported: %+v %v", res, ok)
	}
}

func TestOperatorResumeOnRunningContainerIsIdempotent(t *testing.T) {
	r := newRig(t)
	out := r.c.HandleOperatorAction(context.Background(), resumeReq("act_2"), "test")
	if out != OpCompleted || len(r.mock.Calls()) != 0 {
		t.Fatalf("%s %v", out, r.mock.Calls())
	}
	res, _ := r.api.result("act_2")
	if res.Detail["note"] != "already running" {
		t.Fatalf("%+v", res)
	}
}

func TestOperatorRequestForAnotherNodeIsIgnored(t *testing.T) {
	r := newRig(t)
	a := resumeReq("act_3")
	a.WorkloadID = "worker-on-node-b"
	if out := r.c.HandleOperatorAction(context.Background(), a, "test"); out != OpIgnored {
		t.Fatal(out)
	}
	if _, reported := r.api.result("act_3"); reported {
		t.Fatal("must not answer for another node's workload")
	}
}

func TestOperatorStaleGenerationIsRefused(t *testing.T) {
	r := newRig(t)
	mustState(t, r.handle(r.event("ev-1", "file_open", decoyOpen("x"), "success")), journal.Verified)
	// The container was re-created while the operator was deciding.
	r.mock.Add(cidWorker, "generation-9", adapter.Paused)
	out := r.c.HandleOperatorAction(context.Background(), resumeReq("act_4"), "test")
	if out != OpFailed || r.state(cidWorker) != adapter.Paused {
		t.Fatalf("%s %s", out, r.state(cidWorker))
	}
	res, _ := r.api.result("act_4")
	if res.Status != "failed" || !strings.HasPrefix(res.Detail["reason"].(string), "STALE_GENERATION") {
		t.Fatalf("%+v", res)
	}
}

func TestOperatorDuplicateDeliveryHandledOnce(t *testing.T) {
	r := newRig(t)
	mustState(t, r.handle(r.event("ev-1", "file_open", decoyOpen("x"), "success")), journal.Verified)
	first := r.c.HandleOperatorAction(context.Background(), resumeReq("act_5"), "webhook")
	second := r.c.HandleOperatorAction(context.Background(), resumeReq("act_5"), "poll")
	if first != OpCompleted || second != OpDuplicate {
		t.Fatalf("%s %s", first, second)
	}
	n := 0
	for _, c := range r.mock.Calls() {
		if strings.HasPrefix(c, "resume:") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("resume called %d times", n)
	}
}

func TestOperatorResultRetriedWhenAPIDown(t *testing.T) {
	r := newRig(t)
	mustState(t, r.handle(r.event("ev-1", "file_open", decoyOpen("x"), "success")), journal.Verified)
	r.api.setDown(true)
	if out := r.c.HandleOperatorAction(context.Background(), resumeReq("act_6"), "test"); out != OpCompleted {
		t.Fatal(out)
	}
	if _, ok := r.api.result("act_6"); ok {
		t.Fatal("API was down")
	}
	r.api.setDown(false)
	r.c.Flush(context.Background())
	if res, ok := r.api.result("act_6"); !ok || res.Status != "completed" {
		t.Fatalf("not retried: %+v", res)
	}
}

// --- terminate ---------------------------------------------------------------------

func TestOperatorTerminateVerified(t *testing.T) {
	r := newRig(t)
	a := resumeReq("act_7")
	a.Action = "terminate"
	if out := r.c.HandleOperatorAction(context.Background(), a, "test"); out != OpCompleted {
		t.Fatal(out)
	}
	res, _ := r.api.result("act_7")
	if res.WorkloadState != "terminated" || r.state(cidWorker) != adapter.Exited {
		t.Fatalf("%+v %s", res, r.state(cidWorker))
	}
}

func TestOperatorTerminateSharedServiceRefused(t *testing.T) {
	r := newRig(t)
	a := resumeReq("act_8")
	a.Action, a.WorkloadID = "terminate", "payments-01"
	if out := r.c.HandleOperatorAction(context.Background(), a, "test"); out != OpFailed {
		t.Fatal(out)
	}
	if r.state(cidPayments) != adapter.Running {
		t.Fatal("shared service was stopped")
	}
}

func TestRecordOnlyActionsAreIgnored(t *testing.T) {
	r := newRig(t)
	a := resumeReq("act_9")
	a.Action = "resolve"
	if out := r.c.HandleOperatorAction(context.Background(), a, "test"); out != OpIgnored {
		t.Fatal(out)
	}
}

func TestPollPicksUpQueuedRequests(t *testing.T) {
	r := newRig(t)
	mustState(t, r.handle(r.event("ev-1", "file_open", decoyOpen("x"), "success")), journal.Verified)
	r.api.enqueue(resumeReq("act_10"))
	r.c.PollOnce(context.Background())
	if r.state(cidWorker) != adapter.Running {
		t.Fatal("queued resume not executed")
	}
	if res, ok := r.api.result("act_10"); !ok || res.Status != "completed" {
		t.Fatalf("%+v", res)
	}
}

// --- HTTP surface ------------------------------------------------------------------

func TestWebhookVerification(t *testing.T) {
	r := newRig(t)
	mustState(t, r.handle(r.event("ev-1", "file_open", decoyOpen("x"), "success")), journal.Verified)
	secret := []byte("0123456789abcdef0123456789abcdef-webhook")
	srv := &Server{C: r.c, WebhookSecret: secret}
	h := srv.Handler()
	body, _ := json.Marshal(resumeReq("act_wh"))
	ts := r.now.Unix()

	post := func(hdr http.Header, b []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/river3/actions", bytes.NewReader(b))
		req.Header = hdr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// wrong secret
	if rec := post(Sign([]byte("not-the-secret-not-the-secret-xx"), body, ts, "d1"), body); rec.Code != 401 {
		t.Fatalf("bad signature accepted: %d", rec.Code)
	}
	// tampered body
	tampered := bytes.Replace(body, []byte(`"resume"`), []byte(`"terminate"`), 1)
	if rec := post(Sign(secret, body, ts, "d2"), tampered); rec.Code != 401 {
		t.Fatalf("tampered body accepted: %d", rec.Code)
	}
	// stale timestamp
	if rec := post(Sign(secret, body, ts-301, "d3"), body); rec.Code != 401 {
		t.Fatalf("stale timestamp accepted: %d", rec.Code)
	}
	// no delivery id: rejected, not exempted from the replay check
	if rec := post(Sign(secret, body, ts, ""), body); rec.Code != 401 {
		t.Fatalf("missing delivery id accepted: %d", rec.Code)
	}
	// the delivery id is inside the MAC: swapping it after signing is tampering
	hdr := Sign(secret, body, ts, "d-signed")
	hdr.Set("X-River3-Delivery", "d-swapped")
	if rec := post(hdr, body); rec.Code != 401 {
		t.Fatalf("delivery id substitution accepted: %d", rec.Code)
	}
	// the pre-A8 base string "<ts>.<body>" (no delivery id) no longer verifies
	old := hmac.New(sha256.New, secret)
	old.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	old.Write(body)
	hdr = Sign(secret, body, ts, "d-old")
	hdr.Set("X-River3-Signature", "sha256="+hex.EncodeToString(old.Sum(nil)))
	if rec := post(hdr, body); rec.Code != 401 {
		t.Fatalf("legacy base string accepted: %d", rec.Code)
	}
	// valid
	if rec := post(Sign(secret, body, ts, "d4"), body); rec.Code != 202 {
		t.Fatalf("valid webhook rejected: %d %s", rec.Code, rec.Body.String())
	}
	if r.state(cidWorker) != adapter.Running {
		t.Fatal("webhook did not resume")
	}
	// replayed delivery id
	if rec := post(Sign(secret, body, ts, "d4"), body); rec.Code != 401 {
		t.Fatalf("replay accepted: %d", rec.Code)
	}
	if len(r.mock.Calls()) != 2 { // one pause, one resume
		t.Fatalf("calls %v", r.mock.Calls())
	}
}

func TestWebhookBaseStringMatchesAPIContract(t *testing.T) {
	// Pinned so a drift on either side (api/river3_api/security.py sign_webhook) is
	// caught here rather than in production.
	got := WebhookBase("1800000000", "0123abcd", []byte(`{"id":"act_1"}`))
	if string(got) != `1800000000.0123abcd.{"id":"act_1"}` {
		t.Fatalf("%q", got)
	}
	secret := []byte("0123456789abcdef0123456789abcdef-webhook")
	mac := hmac.New(sha256.New, secret)
	mac.Write(got)
	h := Sign(secret, []byte(`{"id":"act_1"}`), 1800000000, "0123abcd")
	if h.Get("X-River3-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("Sign does not sign WebhookBase")
	}
}

func TestWebhookReplaySetIsBounded(t *testing.T) {
	r := newRig(t)
	secret := []byte("0123456789abcdef0123456789abcdef-webhook")
	srv := &Server{C: r.c, WebhookSecret: secret}
	body := []byte(`{}`)
	ts := r.now.Unix()
	for i := 0; i < maxSeenDeliveries+500; i++ {
		if err := srv.verify(Sign(secret, body, ts, "d"+strconv.Itoa(i)), body, r.now); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	if len(srv.seen) != maxSeenDeliveries || len(srv.order) != maxSeenDeliveries {
		t.Fatalf("seen=%d order=%d", len(srv.seen), len(srv.order))
	}
	// the newest ids are the ones still remembered
	if err := srv.verify(Sign(secret, body, ts, "d"+strconv.Itoa(maxSeenDeliveries+499)), body, r.now); err == nil {
		t.Fatal("recent delivery id replayed")
	}
	// ids older than the window are forgotten even when the set is not full
	later := r.now.Add(webhookSkew + time.Second)
	if err := srv.verify(Sign(secret, body, later.Unix(), "fresh"), body, later); err != nil {
		t.Fatal(err)
	}
	if len(srv.seen) != 1 {
		t.Fatalf("expired ids kept: %d", len(srv.seen))
	}
}

func TestWebhookDisabledWithoutSecret(t *testing.T) {
	r := newRig(t)
	srv := &Server{C: r.c}
	req := httptest.NewRequest(http.MethodPost, "/river3/actions", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatal(rec.Code)
	}
}

func TestEventsEndpointRequiresSensorToken(t *testing.T) {
	r := newRig(t)
	h := (&Server{C: r.c}).Handler()
	ev := `{"facts":{"id":"http-1","sensor":"lab-sensor","kind":"file_open","outcome":"success",` +
		`"workload":{"id":"worker-01","container_id":"` + cidWorker + `"},"process":{"pid":1,"comm":"python3"},` +
		`"target":{"path":"/opt/config/.db_recovery_creds","path_resolved":true,"access":"read"}},"payload":{}}`

	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(ev))
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 || len(r.mock.Calls()) != 0 {
		t.Fatalf("%d %v", rec.Code, r.mock.Calls())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(ev))
	req.Header.Set("Authorization", "Bearer "+sensorToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out Outcome
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Response == nil || *out.Response != journal.Verified || r.state(cidWorker) != adapter.Paused {
		t.Fatalf("%s", rec.Body.String())
	}

	// unknown JSON fields are refused: the sensor contract is strict
	bad := strings.Replace(ev, `"payload":{}`, `"payload":{},"trust_me":true`, 1)
	req = httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(bad))
	req.Header.Set("Authorization", "Bearer "+sensorToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 422 {
		t.Fatalf("strict decoding not enforced: %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	r := newRig(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	(&Server{C: r.c}).Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"adapter":"mock"`) {
		t.Fatal(rec.Body.String())
	}
}

func TestLoopsStopWithContext(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { r.c.RunLoops(ctx, 5*time.Millisecond, 5*time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loops did not stop")
	}
}
