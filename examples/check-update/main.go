package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
	"github.com/vxcontrol/cloud/system"
)

const (
	DefaultMaxRetries = 3
	DefaultTimeout    = 30 * time.Second
)

type Client struct {
	UpdatesCheck sdk.CallReqBytesRespBytes
}

// transportWithCA returns the default transport, optionally trusting an extra
// CA bundle. This is what a private deployment behind a corporate CA needs; it
// is NOT a way to skip verification, and there is deliberately no flag for that.
func transportWithCA(caPath string) (*http.Transport, error) {
	transport := sdk.DefaultTransport()
	if caPath == "" {
		return transport, nil
	}

	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", caPath)
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}

	return transport, nil
}

func NewClient(serverHost, licenseKey, caPath string) (*Client, error) {
	var client Client

	// Name must match the endpoint the service registers: the PoW ticket is
	// fetched from /api/v1/ticket/{Name}. Path and Name are not interchangeable
	// and neither is guessable — an unknown route answers 403, not 404, so a
	// typo here looks like a permission problem rather than a wrong address.
	configs := []sdk.CallConfig{
		{
			Calls:  []any{&client.UpdatesCheck},
			Host:   serverHost,
			Name:   "updates_check",
			Path:   "/api/v1/proxy/updates/check",
			Method: sdk.CallMethodPOST,
		},
	}

	transport, err := transportWithCA(caPath)
	if err != nil {
		return nil, err
	}

	var buildOptions []sdk.Option
	buildOptions = append(buildOptions,
		sdk.WithTransport(transport),
		// Without this the SDK invents a random installation ID on every build,
		// so the service sees a brand-new installation on each run.
		sdk.WithInstallationID(system.GetInstallationID()),
		sdk.WithClient("Check-Update-Example", "1.0.0"),
		sdk.WithLogger(sdk.WrapLogrus(logrus.StandardLogger())),
		sdk.WithPowTimeout(DefaultTimeout),
		sdk.WithMaxRetries(DefaultMaxRetries),
	)
	if licenseKey != "" {
		// WithLicenseKey silently drops a key that is invalid or expired, and the
		// requests then go out unlicensed. Introspect first if you need to tell
		// the user why their key was ignored.
		buildOptions = append(buildOptions, sdk.WithLicenseKey(licenseKey))
	}

	if err := sdk.Build(configs, buildOptions...); err != nil {
		return nil, err
	}

	return &client, nil
}

func (c *Client) CheckUpdates(
	ctx context.Context, req models.CheckUpdatesRequest,
) (models.CheckUpdatesResponse, error) {
	// Validate before sending: the service answers a malformed request with a
	// server error, which is indistinguishable from an outage on the client side.
	if err := req.Valid(); err != nil {
		return models.CheckUpdatesResponse{}, err
	}

	data, err := json.Marshal(req)
	if err != nil {
		return models.CheckUpdatesResponse{}, err
	}

	body, err := c.UpdatesCheck(ctx, data)
	if err != nil {
		return models.CheckUpdatesResponse{}, err
	}

	// The payload arrives wrapped in {"status":…,"data":…}. Decoding the body
	// straight into CheckUpdatesResponse succeeds and yields an empty update
	// list, so the envelope must be unwrapped explicitly.
	return models.ParseEnvelope[models.CheckUpdatesResponse](body)
}

func main() {
	var (
		serverHost = flag.String("host", "update.pentagi.com", "Cloud server host")
		licenseKey = flag.String("license", "", "License key (optional)")
		strategy   = flag.String("strategy", "stable", "Update strategy: nightly, preview or stable")
		caPath     = flag.String("ca", "", "Extra CA bundle to trust (for private deployments)")
	)
	flag.Parse()

	logrus.SetLevel(logrus.DebugLevel)

	logrus.Printf("starting check update client")
	logrus.Printf("cloud server: %s", *serverHost)
	if *licenseKey != "" {
		// Never the key itself: an example is copied verbatim, and a licence key
		// in a log is a licence key in every backup of that log.
		logrus.Printf("license key: presented (%d characters)", len(*licenseKey))
	}

	client, err := NewClient(*serverHost, *licenseKey, *caPath)
	if err != nil {
		logrus.Fatalf("failed to create client: %v", err)
	}

	installerVersion := "0.0.0"
	request := models.CheckUpdatesRequest{
		// The installer version describes the HOST platform, because the
		// installer is a binary for the machine it runs on.
		InstallerVersion: installerVersion,
		InstallerOS:      models.OSType(runtime.GOOS),
		InstallerArch:    models.ArchType(runtime.GOARCH),
		Strategy:         models.UpdateStrategy(*strategy),
		// Container images and delivered files are reported separately: an image
		// is identified by a registry reference and a digest, a file by a version
		// and a hash, and nothing is ever both.
		Images: []models.ImageComponentInfo{
			{
				Component: models.ComponentTypePentagi,
				Status:    models.ComponentStatusRunning,
				// OS and Arch belong to the IMAGE: a container image is linux
				// even on a darwin host. Read them from `docker inspect`
				// (.Os / .Architecture) rather than assuming the host platform.
				OS:   models.OSTypeLinux,
				Arch: models.ArchTypeAMD64,
				// Both are required: an update is the newest image under the
				// reference this installation follows, so the reference has to
				// be part of the question.
				Repository: "vxcontrol/pentagi",
				Tag:        "latest",
				// ImageHash is the config digest (`docker inspect` → .Id) with
				// the "sha256:" prefix stripped: 64 lowercase hex characters.
				// Omitting it means "not pulled yet" and is answered with an
				// available update.
			},
		},
		Files: []models.FileComponentInfo{
			{
				Component: models.ComponentTypeInstaller,
				Status:    models.ComponentStatusRunning,
				// A file IS a host binary, so here the host platform is right.
				OS:      models.OSType(runtime.GOOS),
				Arch:    models.ArchType(runtime.GOARCH),
				Version: &installerVersion,
			},
		},
		// The third list, and it is not optional. A stack running on someone
		// else's cluster reports no components at all — it has no reference this
		// installation could resolve — so without this, "Langfuse is deployed
		// elsewhere" and "Langfuse is not used" arrive as the same request.
		//
		// Report EVERY stack you know about, including the ones you do not use:
		// staying silent about a stack cannot be told from being too old to
		// speak about it.
		Stacks: []models.StackInfo{
			{Stack: models.ProductStackPentagi, Status: models.StackStatusInstalled},
			{Stack: models.ProductStackInstaller, Status: models.StackStatusInstalled},
			{Stack: models.ProductStackWorker, Status: models.StackStatusUnused},
			{Stack: models.ProductStackLangfuse, Status: models.StackStatusExternal},
			{Stack: models.ProductStackObservability, Status: models.StackStatusUnused},
			{Stack: models.ProductStackGraphiti, Status: models.StackStatusUnused},
			{Stack: models.ProductStackEngine, Status: models.StackStatusUnused},
			{Stack: models.ProductStackBrowser, Status: models.StackStatusUnused},
		},
	}

	resp, err := client.CheckUpdates(context.Background(), request)
	if err != nil {
		logrus.Fatalf("failed to check updates: %v", err)
	}

	for _, update := range resp.Updates {
		logrus.Printf("stack %s: has_update=%t resolution=%s", update.Stack, update.HasUpdate, update.Resolution)
		if update.CurrentVersion != nil {
			mixed := ""
			if update.CurrentVersionMixed {
				// The components came from different releases, so this names the
				// OLDEST of them rather than a version this installation as a
				// whole ever was.
				mixed = " (oldest of several releases)"
			}
			logrus.Printf("  current version: %s%s", *update.CurrentVersion, mixed)
		}
		if update.LatestVersion != nil {
			logrus.Printf("  latest version: %s", *update.LatestVersion)
		}

		// Read the ANSWER through `action`, never through membership. Every
		// component reported is answered exactly once, including the ones with
		// nothing to offer — those come back `unknown` with a reason and no
		// artefact, and a client that inferred "listed means outdated" would act
		// on components that need nothing and skip the explanation for the ones
		// it cannot act on at all.
		for _, image := range update.Images {
			logrus.Printf("  image %s (%s/%s): %s%s", image.Component, image.OS, image.Arch,
				image.Action, reasonOf(image.Reason))
			if image.PullReference != "" {
				// Write this into the compose variable verbatim. It is NOT always
				// repository:tag — under `stable` it pins a more specific tag.
				logrus.Printf("    pull: %s", image.PullReference)
			}
		}
		for _, file := range update.Files {
			logrus.Printf("  file %s (%s/%s): %s%s", file.Component, file.OS, file.Arch,
				file.Action, reasonOf(file.Reason))
			if file.Version != "" {
				logrus.Printf("    package %s %s", file.PackageName, file.Version)
			}
		}

		// Every curated release crossed by applying this update, oldest first —
		// the last entry is the target. Empty means the server sent none, either
		// because there is nothing to cross or because it predates the field, so
		// fall back to the single changelog rather than showing nothing.
		if len(update.Releases) > 0 {
			if update.ReleasesTruncated {
				logrus.Printf("  releases (older entries omitted):")
			} else {
				logrus.Printf("  releases:")
			}
			for _, release := range update.Releases {
				logrus.Printf("    %s stable=%t", release.Version, release.IsStable)
			}
		} else if update.Changelog != nil {
			logrus.Printf("  changelog: %s", *update.Changelog)
		}
	}

	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		logrus.Fatalf("failed to marshal response: %v", err)
	}

	logrus.Println(string(body))
}

// reasonOf renders the explanation attached to an `unknown` component. Absent
// for every other action, and required for that one: without it the client can
// say the server has nothing but not why.
func reasonOf(reason *models.ComponentReason) string {
	if reason == nil {
		return ""
	}
	return " — " + string(*reason)
}
