package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

var goodArgs = []string{
	"--namespace=watchtower-edge",
	"--selector=app.kubernetes.io/name=edge",
	"--floating-ip-selector=role=watchtower-vpn",
	"--interval=5ms",
	"--health-addr=127.0.0.1:0",
}

func getenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var withToken = getenv(map[string]string{"HCLOUD_TOKEN": "t"})

func TestParseFlags(t *testing.T) {
	o, err := parseFlags(goodArgs, withToken, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if o.namespace != "watchtower-edge" || o.interval != 5*time.Millisecond || o.token != "t" {
		t.Errorf("options %+v", o)
	}
	for name, tc := range map[string]struct {
		args []string
		env  func(string) string
		want string
	}{
		"no token":     {goodArgs, getenv(nil), "HCLOUD_TOKEN"},
		"no namespace": {goodArgs[1:], withToken, "--namespace"},
		"bad interval": {append(append([]string{}, goodArgs...), "--interval=0s"), withToken, "--interval"},
		"unknown flag": {[]string{"--nope"}, withToken, "nope"},
		"no selectors": {goodArgs[:1], withToken, "--floating-ip-selector"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFlags(tc.args, tc.env, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// syncBuffer is a log sink the health goroutine can write while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// stub swaps the Kubernetes and Hetzner dependencies for fakes.
func stub(t *testing.T) {
	t.Helper()
	api := httptest.NewServer(&fakeAPI{ips: []map[string]interface{}{floatingIP(7, "198.51.100.7", 101)}})
	t.Cleanup(api.Close)
	origKubeConfig, origNewKube := kubeConfig, newKube
	hetznerEndpoint = api.URL
	kubeConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	newKube = func(*rest.Config) (kubernetes.Interface, error) { return fake.NewSimpleClientset(), nil }
	t.Cleanup(func() {
		hetznerEndpoint = ""
		kubeConfig, newKube = origKubeConfig, origNewKube
	})
}

func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestRun(t *testing.T) {
	stub(t)
	var logs syncBuffer
	if code := run(cancelled(), goodArgs, withToken, &logs); code != 0 {
		t.Errorf("exit %d: %s", code, logs.String())
	}
	if !strings.Contains(logs.String(), `"msg":"starting"`) {
		t.Errorf("logs %s", logs.String())
	}
}

func TestRunFailures(t *testing.T) {
	stub(t)
	if code := run(cancelled(), nil, withToken, &bytes.Buffer{}); code != 2 {
		t.Errorf("bad args exit %d", code)
	}

	kubeConfig = func() (*rest.Config, error) { return nil, errors.New("not in a cluster") }
	if code := run(cancelled(), goodArgs, withToken, &bytes.Buffer{}); code != 1 {
		t.Errorf("no kube config exit %d", code)
	}

	kubeConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	newKube = func(*rest.Config) (kubernetes.Interface, error) { return nil, errors.New("bad config") }
	if code := run(cancelled(), goodArgs, withToken, &bytes.Buffer{}); code != 1 {
		t.Errorf("no kube client exit %d", code)
	}
}

// A health address that cannot bind is logged, not fatal: the controller
// still keeps the Floating IP in place.
func TestRunHealthBindFailure(t *testing.T) {
	stub(t)
	var logs syncBuffer
	args := append(append([]string{}, goodArgs...), "--health-addr=256.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- run(ctx, args, withToken, &logs) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "health endpoint") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(logs.String(), "health endpoint") {
		t.Errorf("bind failure not logged: %s", logs.String())
	}
}

func TestMain_(t *testing.T) {
	stub(t)
	var code = -1
	origSignals := signals
	exit = func(c int) { code = c }
	signals = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, cancel
	}
	oldArgs := os.Args
	os.Args = append([]string{"fipd"}, goodArgs...)
	t.Setenv("HCLOUD_TOKEN", "t")
	t.Cleanup(func() {
		exit = os.Exit
		signals = origSignals
		os.Args = oldArgs
	})
	main()
	if code != 0 {
		t.Errorf("exit %d", code)
	}
}

// The real constructors behind the test seams.
func TestDefaultSeams(t *testing.T) {
	if _, err := newKube(&rest.Config{Host: "https://127.0.0.1:6443"}); err != nil {
		t.Errorf("newKube: %v", err)
	}
	ctx, stop := signals()
	stop()
	<-ctx.Done()
}

func TestHealth(t *testing.T) {
	now := time.Unix(0, 0)
	h := NewHealth(time.Minute, func() time.Time { return now })
	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	if code := get("/healthz"); code != http.StatusOK {
		t.Errorf("fresh: %d", code)
	}
	if code := get("/other"); code != http.StatusNotFound {
		t.Errorf("other path: %d", code)
	}
	now = now.Add(2 * time.Minute)
	if code := get("/healthz"); code != http.StatusServiceUnavailable {
		t.Errorf("stale: %d", code)
	}
	h.Mark()
	if code := get("/healthz"); code != http.StatusOK {
		t.Errorf("after mark: %d", code)
	}
}
