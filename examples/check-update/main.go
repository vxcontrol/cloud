package main

import (
	"context"
	"encoding/json"
	"flag"
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

func NewClient(serverHost, licenseKey string) (*Client, error) {
	var client Client

	configs := []sdk.CallConfig{
		{
			Calls:  []any{&client.UpdatesCheck},
			Host:   serverHost,
			Name:   "updates_check",
			Path:   "/api/v1/updates/check",
			Method: sdk.CallMethodPOST,
		},
	}

	var buildOptions []sdk.Option
	buildOptions = append(buildOptions,
		sdk.WithTransport(sdk.DefaultTransport()),
		sdk.WithInstallationID(system.GetInstallationID()),
		sdk.WithClient("Check-Update-Example", "1.0.0"),
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

func (c *Client) CheckUpdates(
	ctx context.Context, req models.CheckUpdatesRequest,
) (models.CheckUpdatesResponse, error) {
	var resp models.CheckUpdatesResponse

	data, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}

	body, err := c.UpdatesCheck(ctx, data)
	if err != nil {
		return resp, err
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, err
	}

	return resp, nil
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

	resp, err := client.CheckUpdates(context.Background(), models.CheckUpdatesRequest{
		InstallerVersion: "0.0.0",
	})
	if err != nil {
		logrus.Fatalf("failed to check updates: %v", err)
	}

	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		logrus.Fatalf("failed to marshal response: %v", err)
	}

	logrus.Println(string(body))
}
