package gsm

import (
	"errors"
	"strings"
	"testing"

	gcp "github.com/pulumi/pulumi-gcp/sdk/v10/go/gcp"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/pulumitest"
)

const token = "gcp:secretmanager/getSecretVersionAccess:getSecretVersionAccess"

var opts = pulumitest.Options{Project: "p", Stack: "s"}

// answer serves each secret's value from values; an unknown id fails the
// lookup the way Secret Manager does.
func answer(values map[string]string) *pulumitest.Mocks {
	return &pulumitest.Mocks{Calls: map[string]pulumitest.CallFunc{
		token: func(args resource.PropertyMap) (resource.PropertyMap, error) {
			v, ok := values[pulumitest.Str(args, "secret")]
			if !ok {
				return nil, errors.New("NOT_FOUND")
			}
			return resource.PropertyMap{"secretData": resource.NewStringProperty(v)}, nil
		},
	}}
}

// read runs a program that reads ids and returns what it got.
func read(t *testing.T, m *pulumitest.Mocks, ids ...string) ([]string, []pulumi.StringOutput, error) {
	t.Helper()
	var plain []string
	var secret []pulumi.StringOutput
	err := pulumitest.Run(t, opts, func(ctx *pulumi.Context) error {
		p, err := gcp.NewProvider(ctx, "gcp", &gcp.ProviderArgs{Project: pulumi.String("proj")})
		if err != nil {
			return err
		}
		r := New(ctx, "proj", p)
		for _, id := range ids {
			plain = append(plain, r.Plain(id))
			secret = append(secret, r.Secret(id))
		}
		return r.Err()
	}, m)
	return plain, secret, err
}

func TestReadsLatestThroughTheProvider(t *testing.T) {
	m := answer(map[string]string{"a": "alpha\n", "b": "line1\nline2\r\n"})
	plain, secret, err := read(t, m, "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	if plain[0] != "alpha" || plain[1] != "line1\nline2" {
		t.Errorf("values %q", plain)
	}
	for i, s := range secret {
		if !pulumi.IsSecret(s) {
			t.Errorf("secret %d is a plaintext output", i)
		}
	}
	for _, inv := range m.Invokes() {
		if inv.Token != token || pulumitest.Str(inv.Args, "project") != "proj" ||
			!strings.Contains(inv.Provider, "pulumi:providers:gcp::gcp") {
			t.Errorf("invoke %+v", inv)
		}
		// Latest: no version pinned.
		if _, ok := inv.Args["version"]; ok {
			t.Errorf("invoke pins a version: %v", inv.Args)
		}
	}
}

// One run names every bad secret, not just the first.
func TestReportsEveryMissingOrEmptySecret(t *testing.T) {
	_, _, err := read(t, answer(map[string]string{"empty": "\n", "ok": "x"}), "missing", "empty", "ok")
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"secret missing: ", "NOT_FOUND", "secret empty in proj is empty (scripts/secret.sh put empty)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "secret ok") {
		t.Errorf("error %q blames a good secret", err)
	}
}
