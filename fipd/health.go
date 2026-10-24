package main

import (
	"net/http"
	"sync"
	"time"
)

// Health answers /healthz: healthy while the last successful reconcile is
// recent, so the kubelet restarts a controller that is stuck or failing.
type Health struct {
	mu     sync.Mutex
	last   time.Time
	maxAge time.Duration
	now    func() time.Time
}

// NewHealth starts healthy, giving the first reconcile maxAge to succeed.
func NewHealth(maxAge time.Duration, now func() time.Time) *Health {
	return &Health{last: now(), maxAge: maxAge, now: now}
}

// Mark records a successful reconcile.
func (h *Health) Mark() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last = h.now()
}

func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/healthz" {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	age := h.now().Sub(h.last)
	h.mu.Unlock()
	if age > h.maxAge {
		http.Error(w, "last successful reconcile "+age.Round(time.Second).String()+" ago", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}
