package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// FloatingIP is the one address fipd manages.
type FloatingIP struct {
	ID int64
	IP string
	// ServerID is 0 while the address is unassigned.
	ServerID int64
}

// FloatingIPs is the slice of the Hetzner API fipd uses.
type FloatingIPs interface {
	// Find returns the single Floating IP matching a Hetzner label selector.
	Find(ctx context.Context, selector string) (FloatingIP, error)
	// Assign routes the address to a server and waits for Hetzner to finish.
	Assign(ctx context.Context, ipID, serverID int64) error
}

// Controller keeps the Floating IP on the node that runs the edge pod.
type Controller struct {
	Kube kubernetes.Interface
	IPs  FloatingIPs
	// Namespace and Selector find the edge pods.
	Namespace string
	Selector  string
	// FloatingIPSelector finds the Floating IP by its Hetzner labels.
	FloatingIPSelector string
	Log                *slog.Logger
}

// target is a node that may hold the address.
type target struct {
	serverID int64
	node     string
	created  time.Time
}

// Reconcile moves the Floating IP to the edge pod's node if it is elsewhere.
//
// A pod counts only if it is Running and Ready, is not being deleted, and its
// node reports Ready. That last part is the reason fipd exists: a pod on a
// dead node stays "Running" in the API until the node comes back, and an
// address that followed it would stay on the dead node too.
//
// With no such pod (mid-reschedule, say), the address stays where it is: no
// node could answer WireGuard anyway, and moving it would only add churn.
func (c *Controller) Reconcile(ctx context.Context) error {
	fip, err := c.IPs.Find(ctx, c.FloatingIPSelector)
	if err != nil {
		return fmt.Errorf("find floating IP: %w", err)
	}
	pods, err := c.Kube.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{LabelSelector: c.Selector})
	if err != nil {
		return fmt.Errorf("list edge pods: %w", err)
	}

	var best *target
	for i := range pods.Items {
		t, err := c.candidate(ctx, &pods.Items[i])
		if err != nil {
			return err
		}
		if t == nil {
			continue
		}
		if best == nil || t.serverID == fip.ServerID ||
			(best.serverID != fip.ServerID && t.created.After(best.created)) {
			best = t
		}
	}

	if best == nil {
		c.Log.Warn("no ready edge pod on a ready node; leaving the floating IP in place", "ip", fip.IP, "server", fip.ServerID)
		return nil
	}
	if best.serverID == fip.ServerID {
		return nil
	}
	c.Log.Info("moving floating IP", "ip", fip.IP, "from", fip.ServerID, "to", best.serverID, "node", best.node)
	if err := c.IPs.Assign(ctx, fip.ID, best.serverID); err != nil {
		return fmt.Errorf("assign %s to server %d: %w", fip.IP, best.serverID, err)
	}
	return nil
}

// candidate returns the pod's node as a target, or nil if the pod or its node
// does not qualify.
func (c *Controller) candidate(ctx context.Context, pod *corev1.Pod) (*target, error) {
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !podReady(pod) || pod.Spec.NodeName == "" {
		return nil, nil
	}
	node, err := c.Kube.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get node %s: %w", pod.Spec.NodeName, err)
	}
	if !nodeReady(node) {
		return nil, nil
	}
	id, err := serverID(node.Spec.ProviderID)
	if err != nil {
		c.Log.Warn("skipping node without a Hetzner provider ID", "node", node.Name, "err", err)
		return nil, nil
	}
	return &target{serverID: id, node: node.Name, created: pod.CreationTimestamp.Time}, nil
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// serverID parses the hcloud cloud-controller's provider ID, hcloud://<id>.
func serverID(providerID string) (int64, error) {
	raw, ok := strings.CutPrefix(providerID, "hcloud://")
	if !ok {
		return 0, fmt.Errorf("provider ID %q is not hcloud://<id>", providerID)
	}
	return strconv.ParseInt(raw, 10, 64)
}

// Loop reconciles every interval until ctx ends, recording each success.
func (c *Controller) Loop(ctx context.Context, interval time.Duration, health *Health) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := c.Reconcile(ctx); err != nil {
			c.Log.Error("reconcile failed", "err", err)
		} else {
			health.Mark()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
