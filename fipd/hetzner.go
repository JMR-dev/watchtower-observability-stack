package main

import (
	"context"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// hetzner implements FloatingIPs with the Hetzner Cloud API.
type hetzner struct {
	client *hcloud.Client
}

func newHetzner(token string, opts ...hcloud.ClientOption) *hetzner {
	opts = append([]hcloud.ClientOption{
		hcloud.WithToken(token),
		hcloud.WithApplication("watchtower-fipd", version),
	}, opts...)
	return &hetzner{client: hcloud.NewClient(opts...)}
}

func (h *hetzner) Find(ctx context.Context, selector string) (FloatingIP, error) {
	ips, err := h.client.FloatingIP.AllWithOpts(ctx, hcloud.FloatingIPListOpts{
		ListOpts: hcloud.ListOpts{LabelSelector: selector},
	})
	if err != nil {
		return FloatingIP{}, err
	}
	if len(ips) != 1 {
		return FloatingIP{}, fmt.Errorf("want exactly one floating IP labelled %q, found %d", selector, len(ips))
	}
	ip := ips[0]
	out := FloatingIP{ID: ip.ID, IP: ip.IP.String()}
	if ip.Server != nil {
		out.ServerID = ip.Server.ID
	}
	return out, nil
}

func (h *hetzner) Assign(ctx context.Context, ipID, serverID int64) error {
	action, _, err := h.client.FloatingIP.Assign(ctx, &hcloud.FloatingIP{ID: ipID}, &hcloud.Server{ID: serverID})
	if err != nil {
		return err
	}
	return h.client.Action.WaitFor(ctx, action)
}

// endpointOption points the Hetzner client at a test server when one is set.
func endpointOption() []hcloud.ClientOption {
	if hetznerEndpoint == "" {
		return nil
	}
	return []hcloud.ClientOption{hcloud.WithEndpoint(hetznerEndpoint)}
}
