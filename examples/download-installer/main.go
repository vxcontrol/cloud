package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
	DefaultTimeout    = 60 * time.Second
)

type Client struct {
	packageInfo     sdk.CallReqQueryRespBytes
	packageDownload sdk.CallReqQueryRespWriter
}

func (c *Client) DownloadLatestInstaller(ctx context.Context) (string, error) {
	packageReq := models.PackageInfoRequest{
		Component: models.ComponentTypeInstaller,
		Version:   "latest",
		OS:        models.OSType(runtime.GOOS),
		Arch:      models.ArchType(runtime.GOARCH),
	}
	body, err := c.packageInfo(ctx, packageReq.Query())
	if err != nil {
		return "", fmt.Errorf("failed to get package info: %w", err)
	}

	var packageInfo models.PackageInfoResponse
	if err := json.Unmarshal(body, &packageInfo); err != nil {
		return "", fmt.Errorf("failed to unmarshal package info: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "pentagi-installer")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name()) // TODO: testing purposes
	defer tmpFile.Close()

	protectedWriter := packageInfo.Signature.ValidateWrapWriter(tmpFile)
	downloadReq := models.DownloadPackageRequest{
		Component: models.ComponentTypeInstaller,
		Version:   packageInfo.Version,
		OS:        packageInfo.OS,
		Arch:      packageInfo.Arch,
	}
	if err := c.packageDownload(ctx, downloadReq.Query(), protectedWriter); err != nil {
		return "", fmt.Errorf("failed to download package: %w", err)
	}

	if err := protectedWriter.Valid(); err != nil {
		return "", fmt.Errorf("failed to validate signature: %w", err)
	}

	return tmpFile.Name(), nil
}

func (c *Client) GetInstallerInfo(ctx context.Context, version string) (models.PackageInfoResponse, error) {
	packageReq := models.PackageInfoRequest{
		Component: models.ComponentTypeInstaller,
		Version:   version,
		OS:        models.OSType(runtime.GOOS),
		Arch:      models.ArchType(runtime.GOARCH),
	}
	body, err := c.packageInfo(ctx, packageReq.Query())
	if err != nil {
		return models.PackageInfoResponse{}, fmt.Errorf("failed to get package info: %w", err)
	}

	var packageInfo models.PackageInfoResponse
	if err := json.Unmarshal(body, &packageInfo); err != nil {
		return models.PackageInfoResponse{}, fmt.Errorf("failed to unmarshal package info: %w", err)
	}

	return packageInfo, nil
}

func NewClient(serverHost, licenseKey string) (*Client, error) {
	var client Client

	configs := []sdk.CallConfig{
		{
			Calls:  []any{&client.packageInfo},
			Host:   serverHost,
			Name:   "package_info",
			Path:   "/api/v1/packages/info",
			Method: sdk.CallMethodGET,
		},
		{
			Calls:  []any{&client.packageDownload},
			Host:   serverHost,
			Name:   "package_download",
			Path:   "/api/v1/packages/download",
			Method: sdk.CallMethodGET,
		},
	}

	var buildOptions []sdk.Option
	buildOptions = append(buildOptions,
		sdk.WithTransport(sdk.DefaultTransport()),
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
	)
	flag.Parse()

	logrus.SetLevel(logrus.DebugLevel)

	logrus.Printf("starting check update client")
	logrus.Printf("cloud server: %s", *serverHost)
	if *licenseKey != "" {
		logrus.Printf("license key: %s", *licenseKey)
	}

	client, err := NewClient(*serverHost, *licenseKey)
	if err != nil {
		logrus.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.GetInstallerInfo(context.Background(), "latest")
	if err != nil {
		logrus.Fatalf("failed to check updates: %v", err)
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

	logrus.WithField("installer_path", installerPath).Println("installer downloaded")
}
