package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestDumpManifests writes what the program hands the cluster, for
// scripts/check-manifests.sh to validate against a real API server:
//
//	namespaces.yaml   the Namespaces (created for real, before the rest)
//	objects.yaml      every other object the program builds itself
//	charts.tsv        name, chart, repo, version, namespace of each chart
//	charts/<name>.json  the chart's values, as Go merged them
//
// The dump always runs; CI keeps it by pointing WATCHTOWER_MANIFESTS at a
// directory. Each object is one JSON document in a YAML stream: kubectl and
// kubeconform read it, and whole numbers stay integers.
func TestDumpManifests(t *testing.T) {
	m := mustRun(t)
	dir := cmp.Or(os.Getenv("WATCHTOWER_MANIFESTS"), t.TempDir())
	if err := os.MkdirAll(filepath.Join(dir, "charts"), 0o755); err != nil {
		t.Fatal(err)
	}

	var namespaces, objects []map[string]interface{}
	var charts []string
	for _, r := range m.Resources() {
		in := inputs(r)
		switch {
		case r.Type == chartType:
			charts = append(charts, strings.Join([]string{
				in["name"].(string), in["chart"].(string), dig(in, "repositoryOpts.repo").(string),
				in["version"].(string), in["namespace"].(string),
			}, "\t"))
			writeJSON(t, filepath.Join(dir, "charts", in["name"].(string)+".json"), in["values"])
		case strings.HasPrefix(r.Type, "kubernetes:"):
			// An auto-named object would get a random suffix from the
			// provider; the dry-run needs the name the cluster will see.
			if in["apiVersion"] == nil || in["kind"] == nil || dig(in, "metadata.name") == nil {
				t.Errorf("%s %s: no apiVersion, kind or metadata.name", r.Type, r.Name)
				continue
			}
			if in["kind"] == "Namespace" {
				namespaces = append(namespaces, in)
			} else {
				objects = append(objects, in)
			}
		}
	}
	if len(namespaces) == 0 || len(objects) == 0 || len(charts) == 0 {
		t.Fatalf("dumped %d namespaces, %d objects, %d charts", len(namespaces), len(objects), len(charts))
	}
	writeStream(t, filepath.Join(dir, "namespaces.yaml"), namespaces)
	writeStream(t, filepath.Join(dir, "objects.yaml"), objects)
	slices.Sort(charts)
	if err := os.WriteFile(filepath.Join(dir, "charts.tsv"), []byte(strings.Join(charts, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	if err := os.WriteFile(path, marshal(t, v), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeStream writes objects as a YAML stream of JSON documents, sorted so
// the file only changes when an object does.
func writeStream(t *testing.T, path string, objs []map[string]interface{}) {
	t.Helper()
	key := func(o map[string]interface{}) string {
		return fmt.Sprint(o["kind"], "/", dig(o, "metadata.namespace"), "/", dig(o, "metadata.name"))
	}
	slices.SortFunc(objs, func(a, b map[string]interface{}) int { return strings.Compare(key(a), key(b)) })
	var b bytes.Buffer
	for _, o := range objs {
		b.WriteString("---\n")
		b.Write(marshal(t, o))
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
