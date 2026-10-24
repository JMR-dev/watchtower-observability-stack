package stackcfg

import (
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"watchtower-infra/internal/pulumitest"
)

type values struct {
	s, rs      string
	i, ri      int
	b          bool
	obj, sobj  map[string]string
	list       []string
	secretOK   bool
	readerErrs error
}

func read(t *testing.T, cfg map[string]string, secrets ...string) values {
	t.Helper()
	var v values
	err := pulumitest.Run(t, pulumitest.Options{Project: "p", Stack: "s", Config: cfg, Secrets: secrets},
		func(ctx *pulumi.Context) error {
			r := New(ctx, "ns")
			v.s = r.String("s", "def")
			v.rs = r.RequiredString("rs")
			v.i = r.Int("i", 7)
			v.ri = r.RequiredInt("ri")
			v.b = r.Bool("b", true)
			v.list = []string{"default"}
			r.Object("list", &v.list, false)
			r.Object("obj", &v.obj, true)
			r.SecretObject("sobj", &v.sobj)
			sec := r.Secret("sec")
			v.secretOK = sec != (pulumi.StringOutput{})
			if len(v.rs) > 0 && v.rs == "fail" {
				r.Fail("asked to fail: %s", v.rs)
			}
			v.readerErrs = r.Err()
			return nil
		}, &pulumitest.Mocks{})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReadsEverything(t *testing.T) {
	v := read(t, map[string]string{
		"ns:s": "x", "ns:rs": "y", "ns:i": "3", "ns:ri": "4", "ns:b": "false",
		"ns:list": `["a","b"]`, "ns:obj": `{"k":"v"}`, "ns:sobj": `{"key":"id"}`, "ns:sec": "pw",
	}, "ns:sobj", "ns:sec")
	if v.readerErrs != nil {
		t.Fatal(v.readerErrs)
	}
	if v.s != "x" || v.rs != "y" || v.i != 3 || v.ri != 4 || v.b {
		t.Errorf("scalars %+v", v)
	}
	if len(v.list) != 2 || v.obj["k"] != "v" || v.sobj["key"] != "id" || !v.secretOK {
		t.Errorf("objects %+v", v)
	}
}

func TestDefaultsAndMissingRequired(t *testing.T) {
	v := read(t, map[string]string{})
	if v.s != "def" || v.i != 7 || !v.b || len(v.list) != 1 || v.list[0] != "default" {
		t.Errorf("defaults %+v", v)
	}
	msg := v.readerErrs.Error()
	for _, key := range []string{"ns:rs", "ns:ri", "ns:obj", "ns:sobj", "ns:sec"} {
		if !strings.Contains(msg, key) {
			t.Errorf("missing %s not reported: %s", key, msg)
		}
	}
	if strings.Contains(msg, "ns:s:") || strings.Contains(msg, "ns:list") {
		t.Errorf("optional key reported: %s", msg)
	}
}

func TestMalformedAndFail(t *testing.T) {
	v := read(t, map[string]string{
		"ns:rs": "fail", "ns:i": "seven", "ns:ri": "1", "ns:b": "maybe",
		"ns:list": "not json", "ns:obj": "{}", "ns:sobj": "{}", "ns:sec": "x",
	})
	msg := v.readerErrs.Error()
	for _, want := range []string{"ns:i", "ns:b", "ns:list", "asked to fail"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q not reported: %s", want, msg)
		}
	}
}
