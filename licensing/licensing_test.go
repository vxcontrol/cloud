package licensing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
)

// testModule is 100 KiB; testModuleInfo describes it.
func testModule() []byte {
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

const testModuleID = "9f86d081884c7d659a2feaa0c55ad015"

func testModuleInfo() models.LicenseModuleInfo {
	built := time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)
	refresh := time.Date(2026, 12, 4, 9, 30, 0, 0, time.UTC)
	return models.LicenseModuleInfo{
		Ready:     true,
		ModuleID:  testModuleID,
		BuiltAt:   &built,
		RefreshBy: &refresh,
		Size:      102400,
		Hash:      "27783e87963a4efb6829b531c9ba57b44f45797f6770bd637fbf0d807cbdbae0",
		// well formed and verifying under no key: these tests reach the signature check only to see it fail
		Signature: models.SignatureValue(strings.Repeat("A", 86)),
	}
}

// serve writes body as the SDK writes a download: in frames of 1 KiB, stopping at the
// first write that fails.
func serve(body []byte, w io.Writer) error {
	for len(body) > 0 {
		n := min(len(body), 1024)
		if _, err := w.Write(body[:n]); err != nil {
			return err
		}
		body = body[n:]
	}
	return nil
}

func TestClient_DownloadModule_RefusesWhatDoesNotMatchItsDescription(t *testing.T) {
	module := testModule()
	tampered := append([]byte{}, module...)
	tampered[len(tampered)/2] ^= 0xff
	tamperedHash := sha256.Sum256(tampered)

	for name, tc := range map[string]struct {
		served []byte
		info   func(*models.LicenseModuleInfo)
		hint   string
		dst    []byte
	}{
		"a module one byte short":           {served: module[:len(module)-1], hint: "102399 bytes, expected 102400", dst: module[:len(module)-1]},
		"a module one byte longer":          {served: append(append([]byte{}, module...), 0), hint: "more than 102400 bytes", dst: module},
		"a module of 1 KiB more":            {served: append(append([]byte{}, module...), module[:1024]...), hint: "more than 102400 bytes", dst: module},
		"a module of other bytes":           {served: tampered, hint: "sha256 ", dst: tampered},
		"other bytes described by its hash": {served: tampered, info: func(i *models.LicenseModuleInfo) { i.Hash = hex.EncodeToString(tamperedHash[:]) }, hint: "signature does not verify", dst: tampered},
		// the package signature of these bytes: vector structured_100kb of models
		"the module described, signed as a package": {served: module, info: func(i *models.LicenseModuleInfo) {
			i.Signature = "/qVFpJ8CTXgF4DZmsIsztDiLg7Wdr2OUolaWnNCBGB7CP8XHq7Mb9t8wo4vOU9tC3iiPKMaDiz1wN04KfyJxCw"
		}, hint: "signature does not verify", dst: module},
	} {
		info := testModuleInfo()
		if tc.info != nil {
			tc.info(&info)
		}
		var asked []map[string]string
		client := NewFromCalls(Calls{Module: func(_ context.Context, query map[string]string, w io.Writer) error {
			asked = append(asked, query)
			return serve(tc.served, w)
		}})

		var dst bytes.Buffer
		err := client.DownloadModule(context.Background(), info, &dst)
		switch {
		case err == nil || !strings.Contains(err.Error(), tc.hint):
			t.Errorf("%s: %v, want an error mentioning %q", name, err, tc.hint)
		case !errors.Is(err, ErrModuleMismatch):
			t.Errorf("%s: %v, want ErrModuleMismatch", name, err)
		}
		if !bytes.Equal(dst.Bytes(), tc.dst) {
			t.Errorf("%s: dst holds %d bytes, want %d", name, dst.Len(), len(tc.dst))
		}
		if len(asked) != 1 || !reflect.DeepEqual(asked[0], map[string]string{"module_id": testModuleID}) {
			t.Errorf("%s: the API was asked with %v", name, asked)
		}
	}
}

func TestClient_DownloadModule_RefusesADescriptionOfNoModuleBeforeAsking(t *testing.T) {
	for name, info := range map[string]models.LicenseModuleInfo{
		"no module is ready": {RetryAfterSeconds: 60},
		"a module of no ID":  func() models.LicenseModuleInfo { i := testModuleInfo(); i.ModuleID = ""; return i }(),
		"a module too large": func() models.LicenseModuleInfo { i := testModuleInfo(); i.Size = 41943041; return i }(),
	} {
		called := false
		client := NewFromCalls(Calls{Module: func(context.Context, map[string]string, io.Writer) error {
			called = true
			return nil
		}})
		if err := client.DownloadModule(context.Background(), info, io.Discard); !errors.Is(err, sdk.ErrInvalidRequest) {
			t.Errorf("%s: %v, want sdk.ErrInvalidRequest", name, err)
		}
		if called {
			t.Errorf("%s: the module was asked for", name)
		}
	}
}

func TestClient_DownloadModule_GivesTheRefusalsOfADownloadTheirErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		is   []error
		isnt []error
	}{
		"a module superseded":                    {err: sdk.ErrorFromCode("License.ModuleSuperseded", 0), is: []error{ErrModuleSuperseded, sdk.ErrRequestFailed}, isnt: []error{ErrModuleNotReady}},
		"no module ready":                        {err: sdk.ErrorFromCode("License.ModuleNotReady", 30*time.Second), is: []error{ErrModuleNotReady, sdk.ErrRequestFailed}, isnt: []error{ErrModuleSuperseded}},
		"a code of another route":                {err: sdk.ErrorFromCode("Support.Busy", 0), is: []error{sdk.ErrRequestFailed}, isnt: []error{ErrModuleSuperseded, ErrModuleNotReady}},
		"another code of the licence":            {err: sdk.ErrorFromCode("License.Unknown", 0), is: []error{sdk.ErrRequestFailed}, isnt: []error{ErrModuleSuperseded, ErrModuleNotReady}},
		"a refusal of the SDK":                   {err: sdk.ErrForbidden, is: []error{sdk.ErrForbidden}, isnt: []error{ErrModuleSuperseded, ErrModuleNotReady}},
		"the text of a refusal in a local error": {err: errors.New("License.ModuleSuperseded: a local failure"), isnt: []error{ErrModuleSuperseded, ErrModuleNotReady}},
		"a stream cut":                           {err: io.ErrUnexpectedEOF, is: []error{io.ErrUnexpectedEOF}, isnt: []error{ErrModuleSuperseded, ErrModuleMismatch}},
	} {
		client := NewFromCalls(Calls{Module: func(context.Context, map[string]string, io.Writer) error { return tc.err }})
		err := client.DownloadModule(context.Background(), testModuleInfo(), io.Discard)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		for _, target := range tc.is {
			if !errors.Is(err, target) {
				t.Errorf("%s: %v is not %v", name, err, target)
			}
		}
		for _, target := range tc.isnt {
			if errors.Is(err, target) {
				t.Errorf("%s: %v is %v", name, err, target)
			}
		}
	}
}

// New is the one place the download is bound to its route: the name of the route is what
// the ticket of the call is asked under, before anything else is sent.
func TestNew_AsksForTheTicketOfTheDownloadRoute(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"status":"error","code":"Forbidden"}`)
	}))
	defer server.Close()

	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	client, err := New(server.Listener.Addr().String(),
		sdk.WithTransport(server.Client().Transport.(*http.Transport)),
		sdk.WithMaxRetries(1),
		sdk.WithLogger(sdk.WrapLogrus(quiet)),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.DownloadModule(ctx, testModuleInfo(), io.Discard); !errors.Is(err, sdk.ErrForbidden) {
		t.Errorf("DownloadModule: %v, want sdk.ErrForbidden", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"GET /api/v1/ticket/license_module"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("the server was asked %q, want %q", paths, want)
	}
}
