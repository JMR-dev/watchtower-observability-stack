package pulumitest

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type thing struct {
	pulumi.CustomResourceState
}

const lookupToken = "test:index:lookup"

// careful handles every error, the way the real programs must.
func careful(ctx *pulumi.Context) error {
	var a, b thing
	if err := ctx.RegisterResource("test:index:Thing", "a", pulumi.Map{"x": pulumi.String("1")}, &a); err != nil {
		return err
	}
	if err := ctx.RegisterResource("test:index:Other", "b", pulumi.Map{}, &b,
		pulumi.Protect(true), pulumi.IgnoreChanges([]string{"x"}), pulumi.DeleteBeforeReplace(true)); err != nil {
		return err
	}
	var out map[string]interface{}
	return ctx.Invoke(lookupToken, map[string]interface{}{"q": "z"}, &out)
}

// sloppy drops both errors; ErrorPaths must catch it.
func sloppy(ctx *pulumi.Context) error {
	var a thing
	_ = ctx.RegisterResource("test:index:Thing", "a", pulumi.Map{}, &a)
	var out map[string]interface{}
	_ = ctx.Invoke(lookupToken, map[string]interface{}{}, &out)
	return nil
}

func broken(*pulumi.Context) error { return errors.New("boom") }

var opts = Options{
	Project: "proj",
	Stack:   "dev",
	Config:  map[string]string{"proj:key": "v"},
	Secrets: []string{"proj:key"},
}

func TestRecordsResourcesAndInvokes(t *testing.T) {
	m := &Mocks{
		Calls: map[string]CallFunc{lookupToken: func(args resource.PropertyMap) (resource.PropertyMap, error) {
			return resource.PropertyMap{"answer": resource.NewStringProperty("42")}, nil
		}},
		Outputs:      map[string]resource.PropertyMap{"test:index:Thing": {"extra": resource.NewStringProperty("y")}},
		NamedOutputs: map[string]resource.PropertyMap{"b": {"only-b": resource.NewStringProperty("z")}},
		ID:           func(typ, name string) string { return "custom-" + name },
	}
	if err := Run(t, opts, careful, m); err != nil {
		t.Fatal(err)
	}
	if got := len(m.ByType("test:index:Thing")); got != 1 {
		t.Fatalf("ByType found %d", got)
	}
	if got := len(m.ByType("test:index:Missing")); got != 0 {
		t.Fatalf("ByType(missing) found %d", got)
	}
	r := m.Named(t, "a")
	if Str(r.Inputs, "x") != "1" || Str(r.Inputs, "missing") != "" {
		t.Errorf("inputs %v", r.Inputs)
	}
	if b := m.Named(t, "b"); !b.Protect || len(b.IgnoreChanges) != 1 || !b.DeleteBeforeReplace || r.Protect || r.DeleteBeforeReplace {
		t.Errorf("options not recorded: a=%+v b=%+v", r, b)
	}
	if got := m.Invokes(); len(got) != 1 || got[0].Token != lookupToken {
		t.Errorf("invokes %v", got)
	}
}

func TestDefaultIDAndUnknownCall(t *testing.T) {
	m := &Mocks{}
	if err := Run(t, opts, careful, m); err != nil {
		t.Fatal(err)
	}
	if len(m.Resources()) != 2 {
		t.Errorf("resources %v", m.Resources())
	}
}

func TestStrIgnoresNonStrings(t *testing.T) {
	pm := resource.PropertyMap{"n": resource.NewNumberProperty(1)}
	if Str(pm, "n") != "" {
		t.Error("number read as string")
	}
}

func TestUnwrap(t *testing.T) {
	inner := resource.NewStringProperty("s")
	wrapped := resource.MakeSecret(resource.NewOutputProperty(resource.Output{Element: inner, Known: true}))
	if got := Unwrap(wrapped); !reflect.DeepEqual(got, inner) {
		t.Errorf("Unwrap = %v", got)
	}
}

type fakeTB struct {
	testing.TB
	fatal bool
}

func (f *fakeTB) Helper()                       {}
func (f *fakeTB) Fatalf(string, ...interface{}) { f.fatal = true }

func TestNamedFailsWithoutExactlyOne(t *testing.T) {
	m := &Mocks{}
	f := &fakeTB{TB: t}
	m.Named(f, "nope")
	if !f.fatal {
		t.Error("Named did not fail for a missing resource")
	}
}

func TestErrorPaths(t *testing.T) {
	fresh := func() *Mocks { return &Mocks{} }

	ignored, err := ErrorPaths(t, opts, careful, fresh)
	if err != nil || len(ignored) != 0 {
		t.Errorf("careful: ignored %v, err %v", ignored, err)
	}

	ignored, err = ErrorPaths(t, opts, sloppy, fresh)
	want := []string{"invoke " + lookupToken, "resource test:index:Thing::a"}
	if err != nil || !reflect.DeepEqual(ignored, want) {
		t.Errorf("sloppy: ignored %v, err %v", ignored, err)
	}

	if _, err := ErrorPaths(t, opts, broken, fresh); err == nil {
		t.Error("broken baseline not reported")
	}
}

// A program registering the same name twice is still probed once per name.
func TestErrorPathsDeduplicates(t *testing.T) {
	twice := func(ctx *pulumi.Context) error {
		for i := 0; i < 2; i++ {
			var a thing
			if err := ctx.RegisterResource("test:index:Thing", "a", pulumi.Map{}, &a); err != nil {
				return err
			}
			var out map[string]interface{}
			if err := ctx.Invoke(lookupToken, map[string]interface{}{}, &out); err != nil {
				return err
			}
		}
		return nil
	}
	ignored, err := ErrorPaths(t, opts, twice, func() *Mocks { return &Mocks{} })
	if err != nil || len(ignored) != 0 {
		t.Errorf("ignored %v, err %v", ignored, err)
	}
}
