package controller

import (
	"context"
	"net/http"
)

// contextWithoutCancel detaches background work from a request that will finish
// before the work does (webhook: respond 202, then act), keeping request values.
func contextWithoutCancel(r *http.Request) context.Context {
	return context.WithoutCancel(r.Context())
}
