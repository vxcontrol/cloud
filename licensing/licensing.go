// Package licensing downloads the license module of a licence from the PentAGI Cloud API.
//
//	client, err := licensing.New("update.pentagi.com",
//		sdk.WithInstallationID(system.GetInstallationID()),
//		sdk.WithLicenseKey(key),
//	)
//	...
//	var info models.LicenseModuleInfo // supplied by the caller
//	err = client.DownloadModule(ctx, info, file) // a file put in place only on nil
//
// The caller supplies the models.LicenseModuleInfo a download needs. DownloadModule
// streams the module described and verifies it against the description as the bytes
// arrive; a module the API replaced since the description was given is refused as
// ErrModuleSuperseded: get a new description. A licence whose key carries
// sdk.LicenseFlagOffline is served like any other; the flag lets its installation also
// be given a module by hand.
package licensing

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
)

var (
	// ErrModuleSuperseded is a download refused because the module it named is no longer
	// the one served.
	ErrModuleSuperseded = errors.New("licensing: the module was superseded")
	// ErrModuleNotReady is a download refused because no module is served for the
	// licence now.
	ErrModuleNotReady = errors.New("licensing: no module is ready")
	// ErrModuleMismatch is a download whose bytes are not those of its description: their
	// length, their SHA-256 or their signature.
	ErrModuleMismatch = errors.New("licensing: the module does not match its description")
)

// The download, by the name of its route and its path, and the codes of its refusals.
const (
	callModule = "license_module"
	pathModule = "/api/v1/proxy/license/module"

	codeModuleSuperseded = "License.ModuleSuperseded"
	codeModuleNotReady   = "License.ModuleNotReady"
)

var downloadRefusals = map[string]error{codeModuleSuperseded: ErrModuleSuperseded, codeModuleNotReady: ErrModuleNotReady}

// Calls are the calls of the API a Client makes.
type Calls struct {
	Module sdk.CallReqQueryRespWriter
}

// Client asks the API for the license module of a licence. It is safe for concurrent use.
type Client struct {
	calls Calls
}

// New builds the calls of the API against host and returns a Client of them. The options
// are those of the SDK: the licence key, the installation, the transport.
func New(host string, options ...sdk.Option) (*Client, error) {
	var calls Calls
	err := sdk.Build([]sdk.CallConfig{
		{Calls: []any{&calls.Module}, Host: host, Name: callModule, Path: pathModule, Method: sdk.CallMethodGET},
	}, options...)
	if err != nil {
		return nil, err
	}
	return NewFromCalls(calls), nil
}

// NewFromCalls returns a Client of calls made elsewhere: by tests and tools.
func NewFromCalls(calls Calls) *Client {
	return &Client{calls: calls}
}

// DownloadModule streams the module info describes into dst and verifies it in the same
// pass: its length must be info.Size, its SHA-256 info.Hash, and info.Signature must
// verify over models.LicenseModuleDigest of its SHA-512. A byte past info.Size is refused
// before it reaches dst. The module is verified only once its last byte is written, so
// on any error dst holds a partial or unverified module: write it where it is put in
// place only after this returns nil.
//
// errors.Is(err, ErrModuleSuperseded) is a module replaced since info was given: get a new
// description. ErrModuleNotReady is no module served now, ErrModuleMismatch bytes
// that are not the module described; any other error is the SDK's. The download has no
// deadline of its own: ctx bounds it.
func (c *Client) DownloadModule(ctx context.Context, info models.LicenseModuleInfo, dst io.Writer) error {
	if !info.Ready {
		return fmt.Errorf("%w: no module is described", sdk.ErrInvalidRequest)
	}
	if err := info.Valid(); err != nil {
		return fmt.Errorf("%w: %w", sdk.ErrInvalidRequest, err)
	}

	digest, signed := sha256.New(), sha512.New()
	counted := &cappedWriter{w: io.MultiWriter(dst, digest, signed), limit: info.Size}

	if err := c.calls.Module(ctx, map[string]string{"module_id": info.ModuleID}, counted); err != nil {
		return refusal(err, downloadRefusals)
	}

	if counted.written != info.Size {
		return fmt.Errorf("%w: %d bytes, expected %d", ErrModuleMismatch, counted.written, info.Size)
	}
	if actual := hex.EncodeToString(digest.Sum(nil)); !strings.EqualFold(actual, info.Hash) {
		return fmt.Errorf("%w: sha256 %s, expected %s", ErrModuleMismatch, actual, info.Hash)
	}
	if err := info.Signature.ValidateHash(models.LicenseModuleDigest(signed.Sum(nil))); err != nil {
		return fmt.Errorf("%w: the signature does not verify: %w", ErrModuleMismatch, err)
	}
	return nil
}

// refusal gives the refusals of a route, by their codes, the errors of this package. The
// SDK maps a code it does not know to no error of its own: the error matches
// sdk.ErrRequestFailed and its text begins with the code.
func refusal(err error, codes map[string]error) error {
	if !errors.Is(err, sdk.ErrRequestFailed) {
		return err
	}
	for code, refused := range codes {
		if strings.HasPrefix(err.Error(), code+": ") {
			return fmt.Errorf("%w: %w", refused, err)
		}
	}
	return err
}

// cappedWriter counts what passes through it and refuses, writing none of it, a write
// that would take the count past limit.
type cappedWriter struct {
	w       io.Writer
	limit   int64
	written int64
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.limit-w.written {
		return 0, fmt.Errorf("%w: more than %d bytes", ErrModuleMismatch, w.limit)
	}
	n, err := w.w.Write(p)
	w.written += int64(n)
	return n, err
}
