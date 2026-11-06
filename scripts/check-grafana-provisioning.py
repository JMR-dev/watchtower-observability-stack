#!/usr/bin/env python3
"""Checks Grafana's rendered provisioning; scripts/check-grafana.sh runs it.

  check-grafana-provisioning.py static <provisioning dir> <out dir>
      Checks the files' structure the way Grafana will read them, and writes every
      query out for its own parser: <out>/promql-rules.yml (a Prometheus rules
      file for promtool) and <out>/logql.tsv (name, then the URL-encoded query,
      for Loki's format_query), and <out>/expected.json for the api step.

  check-grafana-provisioning.py api <out dir> <full|bare> <api dir>
      Compares what a running Grafana reports (JSON its API returned, saved in
      <api dir>) with expected.json: every rule as written, the contact points and
      policy tree only in the full variant, the dashboard.

Reads the repo's group_vars (the sources) and scripts/healthchecks.sh (the
keywords its check filters on). Needs PyYAML (ansible-core's, in CI). Prints only
names and counts; the provisioning holds no secret (the ping URL is a $__file{}).
"""

import json
import pathlib
import re
import sys
import urllib.parse

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCES = REPO / "ansible/inventory/group_vars/all/telemetry.yml"
HEALTHCHECKS = REPO / "scripts/healthchecks.sh"
QUADLET = REPO / "ansible/.render/watchtower-1/quadlets/grafana.container"
TASKS = REPO / "ansible/roles/grafana/tasks/main.yml"
# What each of roles/grafana's tasks does to the four things the contact point
# file needs, by task name: (state when the URL is there, state when it isn't).
# None leaves it as it was; "quadlet" copies what the quadlet on disk says.
TASK_EFFECTS = {
    "No contact point file without the ping URL": {"file": (None, False)},
    "Grafana's secrets": {"secret": (True, None)},
    "Grafana quadlet": {"quadlet": (True, False)},
    "Load the quadlet before the contact point file can need its secret": {"loaded": ("quadlet", "quadlet")},
    "The telemetry alerts' contact point and notification policy": {"file": (True, None)},
    "Start Grafana": {"loaded": ("quadlet", "quadlet")},
}
SECRET_PATH = "/run/secrets/grafana-telemetry-alert-url"
DURATION = re.compile(r"^([0-9]+(ms|s|m|h|d|w|y))+$")
# Grafana's own limit on a rule's uid, and the characters it allows.
UID = re.compile(r"^[a-zA-Z0-9_-]{1,40}$")
# Sample values for the dashboard's variables, so its queries parse.
DASHBOARD_VARS = {
    "${host:regex}": "blog-vm|silverbullet-vm",
    "$host": "blog-vm|silverbullet-vm",
    "$__rate_interval": "5m",
    "$__interval": "1m",
    "$__auto": "5m",
    "$__range": "1h",
}

errors = []


def fail(message):
    errors.append(message)
    print(f"FAIL  {message}")


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def keywords():
    """The success and failure keywords healthchecks.sh gives the check."""
    text = HEALTHCHECKS.read_text(encoding="utf-8")
    found = {}
    for name in ("TELEMETRY_SUCCESS_KW", "TELEMETRY_FAILURE_KW"):
        m = re.search(rf'^{name}="([^"]+)"', text, re.M)
        if not m:
            fail(f"healthchecks.sh has no {name}")
            found[name] = None
        else:
            found[name] = m.group(1)
    return found["TELEMETRY_SUCCESS_KW"], found["TELEMETRY_FAILURE_KW"]


def check_datasources(prov):
    doc = load_yaml(prov / "datasources/watchtower.yaml")
    uids = {d["uid"] for d in doc.get("datasources", [])}
    if not uids:
        fail("no datasources provisioned")
    return uids


def check_rules(prov, datasource_uids, sources):
    doc = load_yaml(prov / "alerting/telemetry-rules.yaml")
    if doc.get("apiVersion") != 1:
        fail("telemetry-rules.yaml: apiVersion is not 1")
    promql, logql, expected = [], [], {}
    titles = set()
    groups = doc.get("groups") or []
    want_groups = [f"telemetry-{s['name']}" for s in sources]
    got_groups = [g.get("name") for g in groups]
    if got_groups != want_groups:
        fail(f"rule groups {got_groups}, want one per source {want_groups}")
    for group in groups:
        if group.get("orgId") != 1 or group.get("folder") != "Telemetry":
            fail(f"group {group.get('name')}: not org 1, folder Telemetry")
        if not DURATION.match(str(group.get("interval", ""))):
            fail(f"group {group.get('name')}: interval {group.get('interval')!r}")
        if not group.get("rules"):
            fail(f"group {group.get('name')}: no rules")
        for rule in group.get("rules") or []:
            uid = rule.get("uid", "")
            where = f"rule {uid or '?'}"
            if not UID.match(uid):
                fail(f"{where}: uid must be 1-40 of [a-zA-Z0-9_-]")
            if uid in expected:
                fail(f"{where}: uid used twice")
            if rule.get("title") in titles:
                fail(f"{where}: title {rule.get('title')!r} used twice in the folder")
            titles.add(rule.get("title"))
            refs = {d.get("refId") for d in rule.get("data", [])}
            if rule.get("condition") not in refs:
                fail(f"{where}: condition {rule.get('condition')!r} is none of its refIds {sorted(refs)}")
            if not DURATION.match(str(rule.get("for", ""))):
                fail(f"{where}: for {rule.get('for')!r}")
            if rule.get("noDataState") not in ("OK", "NoData", "Alerting", "KeepLast"):
                fail(f"{where}: noDataState {rule.get('noDataState')!r}")
            if rule.get("execErrState") not in ("OK", "Error", "Alerting", "KeepLast"):
                fail(f"{where}: execErrState {rule.get('execErrState')!r}")
            labels = rule.get("labels") or {}
            if labels.get("telemetry") != "true" or not labels.get("host"):
                fail(f"{where}: needs labels telemetry=\"true\" and host, to reach the one notification group")
            annotations = rule.get("annotations") or {}
            if not annotations.get("summary") or not annotations.get("runbook_url"):
                fail(f"{where}: needs a summary and a runbook_url")
            for d in rule.get("data", []):
                ds = d.get("datasourceUid")
                model = d.get("model") or {}
                if ds == "__expr__":
                    if model.get("type") not in ("threshold", "math", "reduce", "classic_conditions", "resample"):
                        fail(f"{where}: expression type {model.get('type')!r}")
                    if model.get("type") == "threshold":
                        for c in model.get("conditions", []):
                            if c.get("evaluator", {}).get("type") not in ("gt", "lt", "within_range", "outside_range"):
                                fail(f"{where}: threshold {c.get('evaluator')}")
                            if model.get("expression") not in refs:
                                fail(f"{where}: threshold reads {model.get('expression')!r}, not a refId")
                    continue
                if ds not in datasource_uids:
                    fail(f"{where}: datasource {ds!r} is not provisioned")
                    continue
                expr = model.get("expr", "")
                if not expr:
                    fail(f"{where}: query {d.get('refId')} has no expr")
                elif ds.startswith("loki-"):
                    if model.get("queryType") != "instant":
                        fail(f"{where}: a Loki alert query must be instant")
                    logql.append((uid, expr))
                else:
                    if model.get("instant") is not True:
                        fail(f"{where}: a Mimir alert query must be instant")
                    promql.append((uid, expr))
            expected[uid] = {"title": rule.get("title"), "summary": annotations.get("summary"), "for": rule.get("for")}
    # Grafana keeps a rule that leaves the file until deleteRules names it; a
    # uid both provisioned and deleted is a contradiction Grafana may resolve
    # either way.
    for entry in doc.get("deleteRules") or []:
        uid = entry.get("uid", "")
        if entry.get("orgId") != 1 or not UID.match(uid):
            fail(f"deleteRules entry {entry}: needs orgId 1 and a valid uid")
        if uid in expected:
            fail(f"rule {uid} is both provisioned and deleted")
    retired = load_yaml(SOURCES).get("watchtower_telemetry_retired_sources") or []
    for name in retired:
        if name in [s["name"] for s in sources]:
            fail(f"{name} is both a source and retired")
    return promql, logql, expected


def check_notifications(prov, success_kw, failure_kw):
    path = prov / "alerting/telemetry-notifications.yaml"
    doc = load_yaml(path)
    points = {c["name"]: c for c in doc.get("contactPoints", [])}
    if set(points) != {"telemetry-healthchecks", "unrouted"}:
        fail(f"contact points {sorted(points)}, want telemetry-healthchecks and unrouted")
    webhook = points.get("telemetry-healthchecks", {}).get("receivers", [{}])[0]
    settings = webhook.get("settings", {})
    # The URL comes from the podman secret, by this exact path, and never inline.
    if settings.get("url") != f"$__file{{{SECRET_PATH}}}":
        fail("the webhook's url must be exactly $__file{" + SECRET_PATH + "}")
    if webhook.get("disableResolveMessage"):
        fail("the webhook must send resolved notifications: they bring the check back up")
    template = (settings.get("payload") or {}).get("template", "")
    first_line = template.splitlines()[0] if template else ""
    for kw in (success_kw, failure_kw):
        if kw and (template.count(kw) != 1 or kw not in first_line):
            fail(f"the payload's first line must hold {kw} exactly once (healthchecks.sh filters on it)")
    if success_kw and failure_kw and (success_kw in failure_kw or failure_kw in success_kw):
        fail("one keyword holds the other")
    policies = doc.get("policies") or []
    if len(policies) != 1:
        fail("want one policy tree")
        return
    root = policies[0]
    receivers = [root.get("receiver")] + [r.get("receiver") for r in root.get("routes", [])]
    for receiver in receivers:
        if receiver not in points:
            fail(f"policy receiver {receiver!r} is not provisioned here (Grafana won't start)")
    routes = root.get("routes", [])
    if len(routes) != 1 or routes[0].get("object_matchers") != [["telemetry", "=", "true"]] or routes[0].get("group_by") != ["telemetry"]:
        fail("want one route: telemetry=\"true\" to telemetry-healthchecks, grouped by telemetry alone (one group)")
    quadlet = QUADLET.read_text(encoding="utf-8") if QUADLET.exists() else ""
    if f"Secret={pathlib.PurePath(SECRET_PATH).name}," not in quadlet:
        fail("the rendered quadlet has no Secret= line for the URL the contact point reads")
    return template


def check_task_order():
    """The contact point file reads its URL through $__file{} from the podman
    secret the quadlet mounts, and Grafana won't start with the file and without
    the mount. A run can stop after any task, and Grafana can restart then (a
    crash under Restart=always takes the unit systemd has loaded; a reboot, the
    quadlet on disk). So after every task, from every starting state, with the
    URL there and gone: a file means the secret exists, and both the quadlet on
    disk and the loaded unit mount it."""
    tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
    names = [t.get("name") for t in tasks]
    for name in TASK_EFFECTS:
        if names.count(name) != 1:
            fail(f"roles/grafana/tasks/main.yml: no single task named {name!r} (check-grafana-provisioning.py models it)")
            return
    order = [n for n in names if n in TASK_EFFECTS]
    starts = {
        "notifying": {"file": True, "secret": True, "quadlet": True, "loaded": True},
        "never had the URL": {"file": False, "secret": False, "quadlet": False, "loaded": False},
        "had it, its secret left": {"file": False, "secret": True, "quadlet": False, "loaded": False},
    }
    for url in (True, False):
        for start, first in starts.items():
            state = dict(first)
            for name in order:
                for thing, (with_url, without) in TASK_EFFECTS[name].items():
                    effect = with_url if url else without
                    if effect == "quadlet":
                        state[thing] = state["quadlet"]
                    elif effect is not None:
                        state[thing] = effect
                if state["file"] and not (state["secret"] and state["quadlet"] and state["loaded"]):
                    fail(f"a run with the URL {'there' if url else 'gone'}, from {start}, that stops after "
                         f"{name!r} leaves the contact point file without its secret mounted: {state}")
                    return
    print(f"ok    order: no run that stops after any of {len(order)} tasks leaves the contact point file without its secret")


def dashboard_queries(prov, datasource_uids):
    path = prov / "dashboards/telemetry/telemetry-fleet.json"
    with open(path, encoding="utf-8") as f:
        dashboard = json.load(f)
    if dashboard.get("uid") != "telemetry-fleet":
        fail("the dashboard's uid is not telemetry-fleet")
    provider = load_yaml(prov / "dashboards/telemetry.yaml")
    paths = [p.get("options", {}).get("path") for p in provider.get("providers", [])]
    if paths != ["/etc/grafana/provisioning/dashboards/telemetry"]:
        fail(f"dashboard provider paths {paths}")
    promql, logql = [], []
    for panel in dashboard.get("panels", []):
        # A panel's own datasource too: Grafana loads a dashboard whose panel
        # names a missing one, and the panel shows nothing.
        if "datasource" in panel and (panel["datasource"] or {}).get("uid") not in datasource_uids:
            fail(f"panel {panel.get('title')!r}: datasource {(panel['datasource'] or {}).get('uid')!r} is not provisioned")
        for target in panel.get("targets", []):
            ds = (target.get("datasource") or panel.get("datasource") or {}).get("uid")
            if ds not in datasource_uids:
                fail(f"panel {panel.get('title')!r}: datasource {ds!r} is not provisioned")
                continue
            expr = target.get("expr", "")
            for var, value in DASHBOARD_VARS.items():
                expr = expr.replace(var, value)
            if "$" in expr:
                fail(f"panel {panel.get('title')!r}: a variable the check can't fill in: {expr}")
            name = f"dashboard-{panel.get('id')}-{target.get('refId')}"
            (logql if ds.startswith("loki-") else promql).append((name, expr))
    return promql, logql, dashboard.get("title")


def static(prov, out):
    prov, out = pathlib.Path(prov), pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    sources = load_yaml(SOURCES)["watchtower_telemetry_sources"]
    success_kw, failure_kw = keywords()
    datasource_uids = check_datasources(prov)
    promql, logql, expected = check_rules(prov, datasource_uids, sources)
    payload = check_notifications(prov, success_kw, failure_kw)
    check_task_order()
    dash_promql, dash_logql, dash_title = dashboard_queries(prov, datasource_uids)
    promql += dash_promql
    logql += dash_logql
    # promtool parses each expression as a rule's.
    rules = {"groups": [{"name": "parse", "rules": [{"alert": re.sub(r"[^A-Za-z0-9_]", "_", n), "expr": e} for n, e in promql]}]}
    (out / "promql-rules.yml").write_text(yaml.safe_dump(rules, sort_keys=False), encoding="utf-8")
    with open(out / "logql.tsv", "w", encoding="utf-8") as f:
        for name, expr in logql:
            f.write(f"{name}\t{urllib.parse.quote(expr, safe='')}\n")
    (out / "expected.json").write_text(json.dumps({"rules": expected, "dashboard": dash_title, "payload": payload}), encoding="utf-8")
    print(f"ok    structure: {len(expected)} rules in {len(sources)} groups, {len(dash_promql) + len(dash_logql)} dashboard queries, "
          f"{len(promql)} PromQL and {len(logql)} LogQL expressions to parse")


def api(out, variant, api_dir):
    out, api_dir = pathlib.Path(out), pathlib.Path(api_dir)
    expected = json.loads((out / "expected.json").read_text(encoding="utf-8"))

    def read(name):
        try:
            return json.loads((api_dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            fail(f"{variant}: Grafana's {name} is not JSON: {error}")
            return None

    rules = read("alert-rules.json") or []
    got = {r.get("uid"): r for r in rules}
    if set(got) != set(expected["rules"]):
        fail(f"{variant}: Grafana has {len(got)} rules, the file {len(expected['rules'])}; "
             f"missing {sorted(set(expected['rules']) - set(got))[:5]}, extra {sorted(set(got) - set(expected['rules']))[:5]}")
    for uid, want in expected["rules"].items():
        rule = got.get(uid)
        if not rule:
            continue
        if rule.get("provenance") != "file":
            fail(f"{variant}: rule {uid} is not file-provisioned")
        # Provisioning expands $... in values: an unescaped $labels would vanish.
        if (rule.get("annotations") or {}).get("summary") != want["summary"]:
            fail(f"{variant}: rule {uid}'s summary changed on the way in: {(rule.get('annotations') or {}).get('summary')!r}")
        if rule.get("title") != want["title"]:
            fail(f"{variant}: rule {uid}'s title is {rule.get('title')!r}")
    points = {c.get("name"): c for c in (read("contact-points.json") or [])}
    policy = read("policies.json") or {}
    if variant == "full":
        hook = points.get("telemetry-healthchecks")
        if not hook or hook.get("provenance") != "file":
            fail("full: no file-provisioned contact point telemetry-healthchecks")
        elif hook.get("settings", {}).get("url") != (api_dir / "stand-in-url").read_text(encoding="utf-8"):
            fail("full: the contact point's URL is not the one in the secret file")
        # A Grafana that dropped the custom payload would send its default
        # JSON body, with neither keyword: every ping ignored, the check never down.
        elif ((hook.get("settings") or {}).get("payload") or {}).get("template") != expected["payload"]:
            fail("full: Grafana didn't keep the contact point's payload template as written")
        if policy.get("receiver") != "unrouted" or policy.get("provenance") != "file":
            fail(f"full: the policy tree's root is {policy.get('receiver')!r}, provenance {policy.get('provenance')!r}")
    else:
        if "telemetry-healthchecks" in points or "unrouted" in points:
            fail("bare: contact points provisioned without the notifications file")
        if policy.get("provenance") == "file":
            fail("bare: a provisioned policy tree without the notifications file")
    dashboard = read("dashboard.json") or {}
    if (dashboard.get("dashboard") or {}).get("title") != expected["dashboard"]:
        fail(f"{variant}: dashboard telemetry-fleet is not loaded")
    elif (dashboard.get("meta") or {}).get("folderTitle") != "Telemetry":
        fail(f"{variant}: the dashboard is in {(dashboard.get('meta') or {}).get('folderTitle')!r}, not Telemetry")
    if not errors:
        print(f"ok    grafana ({variant}): {len(got)} rules as written, "
              f"{'the contact points and policy tree' if variant == 'full' else 'no contact point or policy tree'}, the dashboard")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "static":
        static(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 5 and sys.argv[1] == "api" and sys.argv[3] in ("full", "bare"):
        api(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(__doc__)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
