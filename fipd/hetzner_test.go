package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// fakeAPI is the slice of the Hetzner API fipd calls.
type fakeAPI struct {
	mu       sync.Mutex
	ips      []map[string]interface{}
	listCode int
	assign   int // status code for assign; 0 means 201
	assigned []string
	selector string
}

func floatingIP(id int, ip string, server interface{}) map[string]interface{} {
	return map[string]interface{}{
		"id": id, "ip": ip, "type": "ipv4", "server": server, "name": "watchtower-vpn",
		"description": "", "home_location": map[string]interface{}{"name": "nbg1"},
		"labels": map[string]string{"role": "watchtower-vpn"}, "protection": map[string]bool{"delete": true},
		"dns_ptr": []interface{}{}, "blocked": false, "created": "2026-10-01T00:00:00+00:00",
	}
}

func action(status string) map[string]interface{} {
	return map[string]interface{}{
		"id": 10, "command": "assign_floating_ip", "status": status, "progress": 100,
		"started": "2026-10-23T00:00:00+00:00", "finished": nil, "resources": []interface{}{}, "error": nil,
	}
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	meta := map[string]interface{}{"pagination": map[string]interface{}{"page": 1, "per_page": 50, "last_page": 1, "total_entries": 1}}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/floating_ips":
		f.selector = r.URL.Query().Get("label_selector")
		if f.listCode != 0 {
			w.WriteHeader(f.listCode)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": "unavailable", "message": "down"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"floating_ips": f.ips, "meta": meta})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/floating_ips/"):
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.assigned = append(f.assigned, fmt.Sprintf("%s server=%v", r.URL.Path, body["server"]))
		if f.assign != 0 {
			w.WriteHeader(f.assign)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": "locked", "message": "locked"}})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"action": action("running")})
	case r.Method == http.MethodGet && r.URL.Path == "/actions":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"actions": []interface{}{action("success")}, "meta": meta})
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": "not_found", "message": r.URL.String()}})
	}
}

func client(t *testing.T, api *fakeAPI) *hetzner {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return newHetzner("token",
		hcloud.WithEndpoint(srv.URL),
		hcloud.WithPollOpts(hcloud.PollOpts{BackoffFunc: hcloud.ConstantBackoff(time.Millisecond)}),
		hcloud.WithRetryOpts(hcloud.RetryOpts{BackoffFunc: hcloud.ConstantBackoff(time.Millisecond), MaxRetries: 0}),
	)
}

func TestFind(t *testing.T) {
	api := &fakeAPI{ips: []map[string]interface{}{floatingIP(7, "198.51.100.7", 101)}}
	got, err := client(t, api).Find(context.Background(), "role=watchtower-vpn")
	if err != nil {
		t.Fatal(err)
	}
	if got != (FloatingIP{ID: 7, IP: "198.51.100.7", ServerID: 101}) {
		t.Errorf("Find = %+v", got)
	}
	if api.selector != "role=watchtower-vpn" {
		t.Errorf("label selector %q", api.selector)
	}
}

func TestFindUnassigned(t *testing.T) {
	api := &fakeAPI{ips: []map[string]interface{}{floatingIP(7, "198.51.100.7", nil)}}
	got, err := client(t, api).Find(context.Background(), "x")
	if err != nil || got.ServerID != 0 {
		t.Errorf("Find = %+v, %v", got, err)
	}
}

func TestFindErrors(t *testing.T) {
	for name, api := range map[string]*fakeAPI{
		"none":     {},
		"two":      {ips: []map[string]interface{}{floatingIP(1, "198.51.100.1", nil), floatingIP(2, "198.51.100.2", nil)}},
		"api down": {listCode: http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client(t, api).Find(context.Background(), "x"); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestAssign(t *testing.T) {
	api := &fakeAPI{}
	if err := client(t, api).Assign(context.Background(), 7, 102); err != nil {
		t.Fatal(err)
	}
	if len(api.assigned) != 1 || api.assigned[0] != "/floating_ips/7/actions/assign server=102" {
		t.Errorf("assigned %v", api.assigned)
	}
}

func TestAssignRejected(t *testing.T) {
	api := &fakeAPI{assign: http.StatusConflict}
	if err := client(t, api).Assign(context.Background(), 7, 102); err == nil {
		t.Error("expected an error")
	}
}

func TestEndpointOption(t *testing.T) {
	if endpointOption() != nil {
		t.Error("option set without an endpoint")
	}
	hetznerEndpoint = "http://127.0.0.1:1"
	t.Cleanup(func() { hetznerEndpoint = "" })
	if len(endpointOption()) != 1 {
		t.Error("endpoint not applied")
	}
}
