package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
	"github.com/vxcontrol/cloud/system"
)

const (
	DefaultMaxRetries = 3
	DefaultTimeout    = 60 * time.Second
)

type Client struct {
	packageInfo     sdk.CallReqQueryRespBytes
	packageDownload sdk.CallReqQueryRespWriter
}

// DownloadLatestInstaller fetches the newest installer for this platform into
// the current directory and verifies it.
//
// The file is written under its final name rather than into a temporary
// directory: on managed workstations an executable appearing in the system temp
// directory is what antivirus and EDR products react to first.
func (c *Client) DownloadLatestInstaller(ctx context.Context) (string, error) {
	packageInfo, err := c.GetInstallerInfo(ctx, "latest")
	if err != nil {
		return "", err
	}

	name := fmt.Sprintf("installer_%s", packageInfo.Version)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target path: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", fmt.Errorf("failed to create target file: %w", err)
	}
	// The file is closed before it is removed (Windows removes no open file, and a
	// package that failed its checks must not stay) and before its path is returned
	// (a write can fail as late as Close).
	discard := func(err error) (string, error) {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}

	// Two independent checks over the same stream: the Ed25519 signature over
	// the file's SHA-512 digest, and the SHA-256 the package info announced.
	// The download response carries no Content-Length (the transport encryption
	// removes it), so packageInfo.Size is what a progress indicator should use.
	digest := sha256.New()
	protectedWriter := packageInfo.Signature.ValidateWrapWriter(io.MultiWriter(file, digest))

	downloadReq := models.DownloadPackageRequest{
		Component: models.ComponentTypeInstaller,
		Version:   packageInfo.Version,
		OS:        packageInfo.OS,
		Arch:      packageInfo.Arch,
	}
	if err := downloadReq.Valid(); err != nil {
		return discard(err)
	}
	if err := c.packageDownload(ctx, downloadReq.Query(), protectedWriter); err != nil {
		return discard(fmt.Errorf("failed to download package: %w", err))
	}

	if err := protectedWriter.Valid(); err != nil {
		return discard(fmt.Errorf("failed to validate signature: %w", err))
	}

	if got := hex.EncodeToString(digest.Sum(nil)); got != packageInfo.Hash {
		return discard(fmt.Errorf("hash mismatch: expected %s, got %s", packageInfo.Hash, got))
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("failed to write target file: %w", err)
	}
	return path, nil
}

func (c *Client) GetInstallerInfo(ctx context.Context, version string) (models.PackageInfoResponse, error) {
	packageReq := models.PackageInfoRequest{
		Component: models.ComponentTypeInstaller,
		Version:   version,
		// The installer is a binary for the host, so here the host platform is
		// the right answer — unlike a container image, which is always linux.
		OS:   models.OSType(runtime.GOOS),
		Arch: models.ArchType(runtime.GOARCH),
	}
	if err := packageReq.Valid(); err != nil {
		return models.PackageInfoResponse{}, err
	}

	body, err := c.packageInfo(ctx, packageReq.Query())
	if err != nil {
		return models.PackageInfoResponse{}, fmt.Errorf("failed to get package info: %w", err)
	}

	// Unwrap {"status":…,"data":…} — decoding the body directly would succeed
	// and leave every field at its zero value.
	return models.ParseEnvelope[models.PackageInfoResponse](body)
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

	// Name is the endpoint code the PoW ticket is issued for
	// (/api/v1/ticket/{Name}); Path is the endpoint itself. Both are fixed by
	// the service — an unknown route answers 403, not 404.
	configs := []sdk.CallConfig{
		{
			Calls:  []any{&client.packageInfo},
			Host:   serverHost,
			Name:   "packages_info",
			Path:   "/api/v1/proxy/packages/info",
			Method: sdk.CallMethodGET,
		},
		{
			Calls:  []any{&client.packageDownload},
			Host:   serverHost,
			Name:   "packages_download",
			Path:   "/api/v1/proxy/packages/download",
			Method: sdk.CallMethodGET,
		},
	}

	transport, err := transportWithCA(caPath)
	if err != nil {
		return nil, err
	}

	var buildOptions []sdk.Option
	buildOptions = append(buildOptions,
		sdk.WithTransport(transport),
		sdk.WithInstallationID(system.GetInstallationID()),
		sdk.WithClient("Download-Installer-Example", "1.0.0"),
		sdk.WithLogger(sdk.WrapLogrus(logrus.StandardLogger())),
		sdk.WithPowTimeout(DefaultTimeout),
		sdk.WithMaxRetries(DefaultMaxRetries),
	)
	if licenseKey != "" {
		buildOptions = append(buildOptions, sdk.WithLicenseKey(licenseKey))
	}

	if err := sdk.Build(configs, buildOptions...); err != nil {
		return nil, err
	}

	return &client, nil
}

func main() {
	var (
		serverHost = flag.String("host", "update.pentagi.com", "Cloud server host")
		licenseKey = flag.String("license", "", "License key (optional)")
		caPath     = flag.String("ca", "", "Extra CA bundle to trust (for private deployments)")
	)
	flag.Parse()

	logrus.SetLevel(logrus.DebugLevel)

	logrus.Printf("starting download installer client")
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

	resp, err := client.GetInstallerInfo(context.Background(), "latest")
	if err != nil {
		logrus.Fatalf("failed to get installer info: %v", err)
	}

	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		logrus.Fatalf("failed to marshal response: %v", err)
	}

	logrus.Println(string(body))

	installerPath, err := client.DownloadLatestInstaller(context.Background())
	if err != nil {
		logrus.Fatalf("failed to download installer: %v", err)
	}

	logrus.WithField("installer_path", installerPath).Println("installer downloaded and verified")
}
