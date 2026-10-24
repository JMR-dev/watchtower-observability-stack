// Package stackcfg reads stack configuration and collects every problem
// instead of stopping at the first, so one preview reports all of them.
//
// It uses the SDK's Try* readers throughout: the Require* ones panic on a
// missing key, which ends the program without a useful message.
package stackcfg

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

// Reader reads one config namespace.
type Reader struct {
	ns   string
	c    *config.Config
	errs []error
}

// New returns a Reader for namespace ns (keys "ns:key").
func New(ctx *pulumi.Context, ns string) *Reader {
	return &Reader{ns: ns, c: config.New(ctx, ns)}
}

func get[T any](r *Reader, key string, def T, required bool, try func(string) (T, error)) T {
	v, err := try(key)
	switch {
	case err == nil:
		return v
	case errors.Is(err, config.ErrMissingVar) && !required:
		return def
	default:
		r.errs = append(r.errs, fmt.Errorf("%s:%s: %w", r.ns, key, err))
		return def
	}
}

// String returns key, or def when it is not set.
func (r *Reader) String(key, def string) string {
	return get(r, key, def, false, r.c.Try)
}

// RequiredString returns key, recording an error when it is not set.
func (r *Reader) RequiredString(key string) string {
	return get(r, key, "", true, r.c.Try)
}

// Int returns key, or def when it is not set.
func (r *Reader) Int(key string, def int) int {
	return get(r, key, def, false, r.c.TryInt)
}

// RequiredInt returns key, recording an error when it is not set.
func (r *Reader) RequiredInt(key string) int {
	return get(r, key, 0, true, r.c.TryInt)
}

// Bool returns key, or def when it is not set.
func (r *Reader) Bool(key string, def bool) bool {
	return get(r, key, def, false, r.c.TryBool)
}

// Object decodes key (JSON) into out. A missing optional key leaves out as it
// was, so callers set defaults first.
func (r *Reader) Object(key string, out any, required bool) {
	get(r, key, struct{}{}, required, func(k string) (struct{}, error) {
		return struct{}{}, r.c.TryObject(k, out)
	})
}

// SecretObject decodes a required secret key into out. The decoded value is
// plaintext in memory; callers must wrap anything derived from it with
// pulumi.ToSecret before it reaches a resource or an export.
func (r *Reader) SecretObject(key string, out any) {
	get(r, key, struct{}{}, true, func(k string) (struct{}, error) {
		_, err := r.c.TrySecretObject(k, out)
		return struct{}{}, err
	})
}

// Secret returns a required secret string as a secret output.
func (r *Reader) Secret(key string) pulumi.StringOutput {
	return get(r, key, pulumi.StringOutput{}, true, r.c.TrySecret)
}

// Fail records a validation error.
func (r *Reader) Fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}

// Err returns every recorded problem, or nil.
func (r *Reader) Err() error {
	return errors.Join(r.errs...)
}
