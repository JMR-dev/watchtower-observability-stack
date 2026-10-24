package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type fakeIPs struct {
	fip       FloatingIP
	findErr   error
	assignErr error
	assigned  []int64
}

func (f *fakeIPs) Find(context.Context, string) (FloatingIP, error) { return f.fip, f.findErr }
func (f *fakeIPs) Assign(_ context.Context, _, serverID int64) error {
	f.assigned = append(f.assigned, serverID)
	return f.assignErr
}

func node(name, providerID string, ready bool) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{ProviderID: providerID},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
			{Type: corev1.NodeReady, Status: status},
		}},
	}
}

type podOpt func(*corev1.Pod)

func notReady(p *corev1.Pod)    { p.Status.Conditions[1].Status = corev1.ConditionFalse }
func pending(p *corev1.Pod)     { p.Status.Phase = corev1.PodPending }
func noNode(p *corev1.Pod)      { p.Spec.NodeName = "" }
func noReadyCond(p *corev1.Pod) { p.Status.Conditions = p.Status.Conditions[:1] }
func deleting(p *corev1.Pod) {
	now := metav1.Now()
	p.DeletionTimestamp = &now
}
func otherApp(p *corev1.Pod) { p.Labels = map[string]string{"app.kubernetes.io/name": "other"} }

func pod(name, nodeName string, age time.Duration, opts ...podOpt) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "watchtower-edge",
			Labels:            map[string]string{"app.kubernetes.io/name": "edge"},
			CreationTimestamp: metav1.NewTime(time.Unix(1_800_000_000, 0).Add(-age)),
		},
		Spec: corev1.PodSpec{NodeName: nodeName},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func controller(ips *fakeIPs, objs ...runtime.Object) (*Controller, *fake.Clientset, *bytes.Buffer) {
	kube := fake.NewSimpleClientset(objs...)
	var logs bytes.Buffer
	return &Controller{
		Kube:               kube,
		IPs:                ips,
		Namespace:          "watchtower-edge",
		Selector:           "app.kubernetes.io/name=edge",
		FloatingIPSelector: "role=watchtower-vpn",
		Log:                slog.New(slog.NewTextHandler(&logs, nil)),
	}, kube, &logs
}

var (
	n1 = node("watchtower-1", "hcloud://101", true)
	n2 = node("watchtower-2", "hcloud://102", true)
	n3 = node("watchtower-3", "hcloud://103", true)
)

func TestReconcile(t *testing.T) {
	for name, tc := range map[string]struct {
		current int64
		objs    []runtime.Object
		want    []int64
	}{
		"already on the edge node": {101, []runtime.Object{n1, n2, pod("edge-a", "watchtower-1", time.Hour)}, nil},
		"edge moved":               {101, []runtime.Object{n1, n2, pod("edge-a", "watchtower-2", time.Hour)}, []int64{102}},
		"unassigned":               {0, []runtime.Object{n1, n2, pod("edge-a", "watchtower-2", time.Hour)}, []int64{102}},
		// The dead-node case: the old pod still says Running on a node
		// that stopped reporting; the address must follow the new pod.
		"old pod on dead node": {101, []runtime.Object{
			node("watchtower-1", "hcloud://101", false), n2,
			pod("edge-old", "watchtower-1", time.Hour), pod("edge-new", "watchtower-2", time.Minute),
		}, []int64{102}},
		"terminating old pod": {101, []runtime.Object{
			n1, n2, pod("edge-old", "watchtower-1", time.Hour, deleting), pod("edge-new", "watchtower-2", time.Minute),
		}, []int64{102}},
		"newest of two elsewhere": {101, []runtime.Object{
			n1, n2, n3, pod("edge-b", "watchtower-2", time.Hour), pod("edge-c", "watchtower-3", time.Minute),
		}, []int64{103}},
		"current node wins a tie": {102, []runtime.Object{
			n1, n2, pod("edge-new", "watchtower-1", time.Minute), pod("edge-old", "watchtower-2", time.Hour),
		}, nil},
		"current node listed last": {101, []runtime.Object{
			n1, n2, pod("edge-a", "watchtower-2", time.Minute), pod("edge-b", "watchtower-1", time.Hour),
		}, nil},
		"no qualifying pod": {101, []runtime.Object{
			n1, n2,
			pod("a", "watchtower-2", 0, notReady), pod("b", "watchtower-2", 0, pending),
			pod("c", "", 0, noNode), pod("d", "watchtower-2", 0, noReadyCond),
			pod("e", "watchtower-9", 0), pod("f", "watchtower-2", 0, otherApp),
		}, nil},
		"node without hetzner id": {101, []runtime.Object{
			n1, node("watchtower-2", "kind://x", true), pod("edge-a", "watchtower-2", 0),
		}, nil},
		"node without ready condition": {101, []runtime.Object{
			n1, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "watchtower-2"}}, pod("edge-a", "watchtower-2", 0),
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			ips := &fakeIPs{fip: FloatingIP{ID: 7, IP: "198.51.100.7", ServerID: tc.current}}
			c, _, _ := controller(ips, tc.objs...)
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(ips.assigned) != len(tc.want) || (len(tc.want) == 1 && ips.assigned[0] != tc.want[0]) {
				t.Errorf("assigned %v, want %v", ips.assigned, tc.want)
			}
		})
	}
}

func TestReconcileErrors(t *testing.T) {
	boom := errors.New("boom")
	t.Run("find", func(t *testing.T) {
		c, _, _ := controller(&fakeIPs{findErr: boom})
		if err := c.Reconcile(context.Background()); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("list pods", func(t *testing.T) {
		c, kube, _ := controller(&fakeIPs{})
		kube.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, boom })
		if err := c.Reconcile(context.Background()); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("get node", func(t *testing.T) {
		c, kube, _ := controller(&fakeIPs{}, n1, pod("edge-a", "watchtower-1", 0))
		kube.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, boom })
		if err := c.Reconcile(context.Background()); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("assign", func(t *testing.T) {
		ips := &fakeIPs{fip: FloatingIP{ServerID: 101}, assignErr: boom}
		c, _, _ := controller(ips, n2, pod("edge-a", "watchtower-2", 0))
		if err := c.Reconcile(context.Background()); !errors.Is(err, boom) || !strings.Contains(err.Error(), "server 102") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestServerID(t *testing.T) {
	if id, err := serverID("hcloud://42"); err != nil || id != 42 {
		t.Errorf("hcloud://42 = %d, %v", id, err)
	}
	for _, bad := range []string{"", "aws://42", "hcloud://x"} {
		if _, err := serverID(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// scriptedIPs succeeds once, then fails, and ends the loop on its third
// call. Everything runs on the loop's goroutine, so there is nothing to race.
type scriptedIPs struct {
	calls  int
	cancel context.CancelFunc
}

func (s *scriptedIPs) Find(context.Context, string) (FloatingIP, error) {
	s.calls++
	if s.calls >= 3 {
		s.cancel()
	}
	if s.calls == 1 {
		return FloatingIP{ServerID: 101}, nil
	}
	return FloatingIP{}, errors.New("api down")
}

func (s *scriptedIPs) Assign(context.Context, int64, int64) error { return nil }

// Loop reconciles at once, then on every tick, recording successes and
// logging failures, until the context ends.
func TestLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ips := &scriptedIPs{cancel: cancel}
	c, _, logs := controller(&fakeIPs{}, n1, pod("edge-a", "watchtower-1", 0))
	c.IPs = ips
	var ticks int64
	h := NewHealth(time.Hour, func() time.Time { ticks++; return time.Unix(ticks, 0) })
	start := h.last

	c.Loop(ctx, time.Millisecond, h)

	if ips.calls != 3 {
		t.Errorf("reconciled %d times", ips.calls)
	}
	if !strings.Contains(logs.String(), "api down") {
		t.Errorf("failure not logged: %s", logs.String())
	}
	if !h.last.After(start) {
		t.Error("success not recorded")
	}
}
