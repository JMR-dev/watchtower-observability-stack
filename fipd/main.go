// Command fipd keeps watchtower's VPN Floating IP on the node that runs the
// edge pod (wg-easy + Caddy), so WireGuard peers follow the pod when kured
// drains a node or a node dies.
//
// It replaces upstream hcloud-fip-controller, which keeps the address on any
// server that still lists a matching pod as Running; a pod on a dead node
// stays Running in the API indefinitely, so that controller never fails over
// on the one failure that matters. See Controller.Reconcile.
//
// Every node carries the address on eth0 (Ansible), so whichever node Hetzner
// routes it to accepts the traffic; fipd only changes the routing.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

// Swapped in tests.
var (
	exit       = os.Exit
	kubeConfig = rest.InClusterConfig
	newKube    = func(c *rest.Config) (kubernetes.Interface, error) { return kubernetes.NewForConfig(c) }
	signals    = func() (context.Context, context.CancelFunc) {
		return signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	}
	hetznerEndpoint = ""
)

func main() {
	ctx, stop := signals()
	defer stop()
	exit(run(ctx, os.Args[1:], os.Getenv, os.Stderr))
}

type options struct {
	namespace, selector, fipSelector, healthAddr string
	interval                                     time.Duration
	token                                        string
}

func parseFlags(args []string, getenv func(string) string, out io.Writer) (*options, error) {
	fs := flag.NewFlagSet("fipd", flag.ContinueOnError)
	fs.SetOutput(out)
	o := &options{}
	fs.StringVar(&o.namespace, "namespace", "", "namespace of the edge pods")
	fs.StringVar(&o.selector, "selector", "", "label selector of the edge pods")
	fs.StringVar(&o.fipSelector, "floating-ip-selector", "", "Hetzner label selector of the Floating IP")
	fs.StringVar(&o.healthAddr, "health-addr", ":8081", "address of the /healthz endpoint")
	fs.DurationVar(&o.interval, "interval", 10*time.Second, "reconcile interval")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	o.token = getenv("HCLOUD_TOKEN")
	var missing []error
	for name, v := range map[string]string{
		"--namespace": o.namespace, "--selector": o.selector,
		"--floating-ip-selector": o.fipSelector, "HCLOUD_TOKEN": o.token,
	} {
		if v == "" {
			missing = append(missing, fmt.Errorf("%s is required", name))
		}
	}
	if o.interval <= 0 {
		missing = append(missing, errors.New("--interval must be positive"))
	}
	return o, errors.Join(missing...)
}

// run is main without the process exit: it returns the exit code.
func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	o, err := parseFlags(args, getenv, stderr)
	if err != nil {
		log.Error("bad arguments", "err", err)
		return 2
	}
	restCfg, err := kubeConfig()
	if err != nil {
		log.Error("kubernetes config", "err", err)
		return 1
	}
	kube, err := newKube(restCfg)
	if err != nil {
		log.Error("kubernetes client", "err", err)
		return 1
	}

	health := NewHealth(3*o.interval, time.Now)
	srv := &http.Server{Addr: o.healthAddr, Handler: health, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Error("health endpoint", "err", err)
		}
	}()
	defer srv.Close()

	ctl := &Controller{
		Kube:               kube,
		IPs:                newHetzner(o.token, endpointOption()...),
		Namespace:          o.namespace,
		Selector:           o.selector,
		FloatingIPSelector: o.fipSelector,
		Log:                log,
	}
	log.Info("starting", "version", version, "namespace", o.namespace, "selector", o.selector, "interval", o.interval)
	ctl.Loop(ctx, o.interval, health)
	return 0
}
