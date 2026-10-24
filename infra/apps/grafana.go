package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Backends as Grafana's datasources reach them, inside the cluster.
const (
	urlMimir = "http://mimir.watchtower.svc.cluster.local:8080/prometheus"
	urlLoki  = "http://loki-query-frontend.watchtower.svc.cluster.local:3100"
	urlTempo = "http://tempo.watchtower.svc.cluster.local:3200"
)

// newGrafana installs Grafana (values/grafana.yaml) with one Mimir, Loki and
// Tempo datasource per tenant in the main org. Each sends the tenant's
// X-Scope-OrgID; scripts/onboard-tenant.sh adds per-tenant orgs.
func newGrafana(ctx *pulumi.Context, cfg *Config, ns *namespaces, opts ...pulumi.ResourceOption) error {
	admin, err := newSecret(ctx, "grafana-admin", ns.apps, map[string]pulumi.StringInput{
		"admin-user":     pulumi.String("admin"),
		"admin-password": cfg.GrafanaAdminPassword,
	}, opts...)
	if err != nil {
		return err
	}
	values, err := loadValues("grafana.yaml")
	if err != nil {
		return err
	}
	set(values, "datasources", datasources(cfg.Tenants))
	_, err = newChart(ctx, chart{
		name: "grafana", chart: "grafana", version: versionGrafana, repo: repoGrafanaCommunity,
		namespace: ns.apps, values: values,
	}, append(opts, pulumi.DependsOn([]pulumi.Resource{admin}))...)
	return err
}

type obj = map[string]interface{}

// datasources ports ansible's datasources.yaml.j2.
func datasources(tenants []Tenant) obj {
	var list []interface{}
	for i, t := range tenants {
		header := obj{"httpHeaderName1": "X-Scope-OrgID"}
		secure := obj{"httpHeaderValue1": t.Slug}
		with := func(extra obj) obj {
			out := obj{}
			for k, v := range header {
				out[k] = v
			}
			for k, v := range extra {
				out[k] = v
			}
			return out
		}
		list = append(list,
			obj{
				"name": "Mimir (" + t.OrgName + ")", "uid": "mimir-" + t.Slug, "type": "prometheus",
				"access": "proxy", "url": urlMimir, "orgId": 1, "isDefault": i == 0, "editable": false,
				"jsonData":       with(obj{"httpMethod": "POST", "manageAlerts": true, "prometheusType": "Mimir"}),
				"secureJsonData": secure,
			},
			obj{
				"name": "Loki (" + t.OrgName + ")", "uid": "loki-" + t.Slug, "type": "loki",
				"access": "proxy", "url": urlLoki, "orgId": 1, "editable": false,
				"jsonData": with(obj{"derivedFields": []interface{}{obj{
					"datasourceUid": "tempo-" + t.Slug,
					"matcherRegex":  `trace_id=(\w+)`,
					"name":          "TraceID",
					"url":           "$${__value.raw}",
				}}}),
				"secureJsonData": secure,
			},
			obj{
				"name": "Tempo (" + t.OrgName + ")", "uid": "tempo-" + t.Slug, "type": "tempo",
				"access": "proxy", "url": urlTempo, "orgId": 1, "editable": false,
				"jsonData": with(obj{
					"tracesToLogsV2": obj{
						"datasourceUid": "loki-" + t.Slug, "spanStartTimeShift": "-1m",
						"spanEndTimeShift": "1m", "filterByTraceID": true,
					},
					"serviceMap": obj{"datasourceUid": "mimir-" + t.Slug},
				}),
				"secureJsonData": secure,
			},
		)
	}
	return obj{"datasources.yaml": obj{"apiVersion": 1, "datasources": list}}
}
