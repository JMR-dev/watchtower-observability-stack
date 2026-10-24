// Package gsm reads secrets from Google Secret Manager while a program runs,
// so nothing secret is stack config, committed to a repository that is
// mirrored publicly. Each read takes the latest enabled version, so storing a
// new one (scripts/secret.sh put) reaches the cluster on the next deploy.
//
// Values come back in plaintext. Anything handed to a resource or an export
// must be wrapped with pulumi.ToSecret, which Secret does, so it is encrypted
// in state.
package gsm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-gcp/sdk/v10/go/gcp/secretmanager"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Reader reads secrets in one project through one explicit provider. It
// collects every problem instead of stopping at the first, so one preview
// names every secret that is missing or empty.
type Reader struct {
	ctx     *pulumi.Context
	project string
	opt     pulumi.InvokeOption
	errs    []error
}

// New returns a Reader for project's secrets, read through provider.
func New(ctx *pulumi.Context, project string, provider pulumi.ProviderResource) *Reader {
	return &Reader{ctx: ctx, project: project, opt: pulumi.Provider(provider)}
}

// Plain returns secret id's latest value in plaintext. A trailing newline,
// the usual leftover of `echo ... |`, is dropped: no value here ends in one
// on purpose.
func (r *Reader) Plain(id string) string {
	v, err := secretmanager.LookupSecretVersion(r.ctx, &secretmanager.LookupSecretVersionArgs{
		Project: &r.project,
		Secret:  id,
	}, r.opt)
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("secret %s: %w", id, err))
		return ""
	}
	data := strings.TrimRight(v.SecretData, "\r\n")
	if data == "" {
		r.errs = append(r.errs, fmt.Errorf("secret %s in %s is empty (scripts/secret.sh put %s)", id, r.project, id))
	}
	return data
}

// Secret returns secret id's latest value as a secret output.
func (r *Reader) Secret(id string) pulumi.StringOutput {
	return pulumi.ToSecret(pulumi.String(r.Plain(id))).(pulumi.StringOutput)
}

// Err returns every recorded problem, or nil.
func (r *Reader) Err() error {
	return errors.Join(r.errs...)
}
