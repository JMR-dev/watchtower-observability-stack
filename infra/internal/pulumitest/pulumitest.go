// Package pulumitest runs a Pulumi program under the SDK's mock runtime: no
// engine, no cloud calls, no credentials. It records every resource and invoke
// so tests can assert on their inputs, and it can make any one of them fail.
//
// Failing a resource has to happen synchronously, inside NewX, for the
// program's `if err != nil { return err }` after that call to run. A failing
// mock NewResource does not do that: the SDK registers resources
// asynchronously and only reports the error when the program ends. So a
// failure is injected through a stack transformation instead: it re-parents the
// named resource, which the SDK rejects before registering anything.
package pulumitest

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Resource is one registered resource, with the options tests assert on.
type Resource struct {
	Type          string
	Name          string
	Inputs        resource.PropertyMap
	Provider      string
	Providers     map[string]string
	Protect       bool
	IgnoreChanges []string
	// DeleteBeforeReplace is true when a replacement must delete first.
	DeleteBeforeReplace bool
}

// Invoke is one function call (a data source lookup).
type Invoke struct {
	Token    string
	Args     resource.PropertyMap
	Provider string
}

// CallFunc answers an invoke.
type CallFunc func(args resource.PropertyMap) (resource.PropertyMap, error)

// Mocks implements pulumi.MockResourceMonitor.
type Mocks struct {
	// Calls answers invokes by token; an unknown token returns no properties.
	Calls map[string]CallFunc
	// Outputs adds output properties to every resource of a type token.
	Outputs map[string]resource.PropertyMap
	// NamedOutputs adds output properties to the resource with this logical
	// name, after Outputs, so one resource can differ from the rest of its
	// type.
	NamedOutputs map[string]resource.PropertyMap
	// ID returns a resource's ID; nil means "<name>_id".
	ID func(typ, name string) string

	failType     string
	failResource string
	failInvoke   string

	mu        sync.Mutex
	resources []Resource
	invokes   []Invoke
}

// NewResource records a registration and echoes its inputs as outputs.
func (m *Mocks) NewResource(a pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	// The RPC getters are nil-safe, so reads (no RegisterRPC) record zero values.
	m.resources = append(m.resources, Resource{
		Type:          a.TypeToken,
		Name:          a.Name,
		Inputs:        a.Inputs,
		Provider:      a.Provider,
		Providers:     a.RegisterRPC.GetProviders(),
		Protect:       a.RegisterRPC.GetProtect(),
		IgnoreChanges: a.RegisterRPC.GetIgnoreChanges(),

		DeleteBeforeReplace: a.RegisterRPC.GetDeleteBeforeReplace(),
	})
	m.mu.Unlock()

	outs := a.Inputs.Copy()
	for k, v := range m.Outputs[a.TypeToken] {
		outs[k] = v
	}
	for k, v := range m.NamedOutputs[a.Name] {
		outs[k] = v
	}
	id := a.Name + "_id"
	if m.ID != nil {
		id = m.ID(a.TypeToken, a.Name)
	}
	return id, outs, nil
}

// Call records an invoke and answers it from Calls.
func (m *Mocks) Call(a pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if a.Token == m.failInvoke {
		return nil, fmt.Errorf("pulumitest: injected failure of invoke %s", a.Token)
	}
	m.mu.Lock()
	m.invokes = append(m.invokes, Invoke{Token: a.Token, Args: a.Args, Provider: a.Provider})
	m.mu.Unlock()
	if fn, ok := m.Calls[a.Token]; ok {
		return fn(a.Args)
	}
	return resource.PropertyMap{}, nil
}

// Resources returns every registered resource.
func (m *Mocks) Resources() []Resource {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Resource(nil), m.resources...)
}

// Invokes returns every recorded invoke.
func (m *Mocks) Invokes() []Invoke {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Invoke(nil), m.invokes...)
}

// ByType returns the resources of one type token.
func (m *Mocks) ByType(typ string) []Resource {
	var out []Resource
	for _, r := range m.Resources() {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

// Named returns the resource with this logical name, failing the test if
// there is not exactly one.
func (m *Mocks) Named(t testing.TB, name string) Resource {
	t.Helper()
	var found []Resource
	for _, r := range m.Resources() {
		if r.Name == name {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one resource named %q, got %d", name, len(found))
		return Resource{}
	}
	return found[0]
}

// Options configures one program run.
type Options struct {
	Project string
	Stack   string
	// Config is the stack configuration, keyed "namespace:key". Values are
	// passed as strings, the way the engine passes them.
	Config map[string]string
	// Secrets lists config keys to mark secret.
	Secrets []string
}

// dummy is the parent the failure transformation moves a resource under.
type dummy struct {
	pulumi.ResourceState
}

// Run runs program under mocks.
func Run(t testing.TB, opts Options, program pulumi.RunFunc, m *Mocks) error {
	t.Helper()
	cfg, _ := json.Marshal(opts.Config)
	t.Setenv("PULUMI_CONFIG", string(cfg))
	secret, _ := json.Marshal(append([]string{}, opts.Secrets...))
	t.Setenv("PULUMI_CONFIG_SECRET_KEYS", string(secret))

	return pulumi.RunErr(func(ctx *pulumi.Context) error {
		if m.failResource != "" {
			failOn(ctx, m.failType, m.failResource)
		}
		return program(ctx)
	}, pulumi.WithMocks(opts.Project, opts.Stack, m))
}

// failOn makes the resource of type typ named name fail inside its NewX call. Both calls
// take constant, valid arguments and cannot fail; if one ever did, the
// injected failure would be missing and ErrorPaths would report the resource.
func failOn(ctx *pulumi.Context, typ, name string) {
	var d dummy
	_ = ctx.RegisterComponentResource("pulumitest:index:Dummy", "pulumitest-dummy", &d)
	_ = ctx.RegisterStackTransformation(func(a *pulumi.ResourceTransformationArgs) *pulumi.ResourceTransformationResult {
		if a.Type != typ || a.Name != name {
			return nil
		}
		return &pulumi.ResourceTransformationResult{Props: a.Props, Opts: append(a.Opts, pulumi.Parent(&d))}
	})
}

// ErrorPaths runs program once to learn every resource and invoke it makes,
// then once per resource and once per invoke with that one made to fail. It
// returns the ones whose failure the program did not return as an error.
// newMocks must return fresh, identically configured mocks on each call.
func ErrorPaths(t testing.TB, opts Options, program pulumi.RunFunc, newMocks func() *Mocks) ([]string, error) {
	t.Helper()
	base := newMocks()
	if err := Run(t, opts, program, base); err != nil {
		return nil, fmt.Errorf("baseline run failed: %w", err)
	}

	var ignored []string
	seen := map[string]bool{}
	for _, r := range base.Resources() {
		key := r.Type + "::" + r.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		m := newMocks()
		m.failType, m.failResource = r.Type, r.Name
		if Run(t, opts, program, m) == nil {
			ignored = append(ignored, "resource "+key)
		}
	}
	seen = map[string]bool{}
	for _, inv := range base.Invokes() {
		if seen[inv.Token] {
			continue
		}
		seen[inv.Token] = true
		m := newMocks()
		m.failInvoke = inv.Token
		if Run(t, opts, program, m) == nil {
			ignored = append(ignored, "invoke "+inv.Token)
		}
	}
	sort.Strings(ignored)
	return ignored, nil
}

// Str returns a string property, or "" if it is absent or not a string.
func Str(pm resource.PropertyMap, key string) string {
	v, ok := pm[resource.PropertyKey(key)]
	if !ok || !v.IsString() {
		return ""
	}
	return v.StringValue()
}

// Unwrap strips the secret and output wrappers mocks may hand back, so tests
// can compare plain values.
func Unwrap(v resource.PropertyValue) resource.PropertyValue {
	for {
		switch {
		case v.IsSecret():
			v = v.SecretValue().Element
		case v.IsOutput():
			v = v.OutputValue().Element
		default:
			return v
		}
	}
}
