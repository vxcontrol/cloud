package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/cloud/anonymizer"
	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
	"github.com/vxcontrol/cloud/sdk/sse"
	"github.com/vxcontrol/cloud/system"
)

const (
	DefaultMaxRetries = 3
	DefaultTimeout    = 60 * time.Second
	issueWaitTimeout  = 5 * time.Minute
	issuePollInterval = 5 * time.Second
)

type Client struct {
	errorReport                sdk.CallReqBytesRespBytes
	issueCreate                sdk.CallReqBytesRespBytes
	issueStatus                sdk.CallReqWithArgsRespBytes
	issueInvestigate           sdk.CallReqBytesRespBytes
	issueInvestigateWithStream sdk.CallReqBytesRespReader
	anonymizer                 anonymizer.Anonymizer
}

// ReportError sends an automated error report to support
func (c *Client) ReportError(
	ctx context.Context, component models.ComponentType, errorDetails map[string]any,
) error {
	// anonymize sensitive data before transmission
	if err := c.anonymizer.Anonymize(&errorDetails); err != nil {
		return fmt.Errorf("failed to anonymize error details, sending original data: %w", err)
	}

	errorReq := models.SupportErrorRequest{
		Component:    component,
		Version:      "0.0.0",
		OS:           models.OSType(runtime.GOOS),
		Arch:         models.ArchType(runtime.GOARCH),
		ErrorDetails: errorDetails,
	}

	data, err := json.Marshal(errorReq)
	if err != nil {
		return fmt.Errorf("failed to marshal error request: %w", err)
	}

	responseData, err := c.errorReport(ctx, data)
	if err != nil {
		return fmt.Errorf("failed to report error: %w", err)
	}

	// Unwrap {"status":…,"data":…}: decoding the body directly always "succeeds"
	// and hides a failure the server described in the envelope.
	if _, err := models.ParseEnvelope[models.SupportErrorResponse](responseData); err != nil {
		return err
	}

	return nil
}

// CreateSupportIssue creates a support issue with AI assistance
func (c *Client) CreateSupportIssue(
	ctx context.Context, component models.ComponentType, errorDetails any, logs []models.SupportLogs,
) (uuid.UUID, error) {
	// anonymize error details before transmission
	if err := c.anonymizer.Anonymize(&errorDetails); err != nil {
		return uuid.Nil, fmt.Errorf("failed to anonymize error details, sending original data: %w", err)
	}

	// anonymize logs before transmission
	if err := c.anonymizer.Anonymize(&logs); err != nil {
		return uuid.Nil, fmt.Errorf("failed to anonymize logs, sending original data: %w", err)
	}

	issueReq := models.SupportIssueRequest{
		Component:    component,
		Version:      "0.0.0",
		OS:           models.OSType(runtime.GOOS),
		Arch:         models.ArchType(runtime.GOARCH),
		Logs:         logs,
		ErrorDetails: errorDetails,
	}

	data, err := json.Marshal(issueReq)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to marshal issue request: %w", err)
	}

	responseData, err := c.issueCreate(ctx, data)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create issue: %w", err)
	}

	response, err := models.ParseEnvelope[models.SupportIssueResponse](responseData)
	if err != nil {
		return uuid.Nil, err
	}

	return response.IssueID, nil
}

// InvestigateIssue starts AI-powered investigation of a support issue
func (c *Client) InvestigateIssue(
	ctx context.Context, issueID uuid.UUID, userInput string,
) (string, error) {
	investigationReq := models.SupportInvestigationRequest{
		IssueID:   issueID,
		UseStream: false,
		UserInput: userInput,
	}

	data, err := json.Marshal(investigationReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal investigation request: %w", err)
	}

	responseData, err := c.issueInvestigate(ctx, data)
	if err != nil {
		return "", fmt.Errorf("failed to investigate issue: %w", err)
	}

	response, err := models.ParseEnvelope[models.SupportInvestigationResponse](responseData)
	if err != nil {
		return "", err
	}

	return response.Answer, nil
}

// InvestigateIssueWithStream starts AI-powered investigation of a support issue
// and renders the answer live, as it streams in.
//
// The stream is an event stream, not the JSON envelope the non-streaming form
// uses: `event: <name>` / `data: <json>` frames, opening with `start` and ending
// with exactly one of `done` and `error`. The sdk/sse package reads it: it hands
// over the events of the call, consumes the heartbeats, and returns nil only for
// a stream that ended with `done` — a refusal of the server comes back as an
// *sse.Error that errors.Is matches against the errors of the sdk package, and
// a connection lost on the way as sse.ErrStreamCut, never as a short answer.
//
// Buffering the whole thing with io.ReadAll before printing anything — the
// simplest thing to write — is also the one thing that defeats the point of
// streaming: the caller would wait exactly as long as the non-stream call and
// then see the full answer appear at once. streamRenderer (stream_render.go)
// prints each event as it arrives, which is what makes the assistant's answer
// visibly "type itself" in the terminal.
func (c *Client) InvestigateIssueWithStream(
	ctx context.Context, issueID uuid.UUID, userInput string,
) (string, error) {
	investigationReq := models.SupportInvestigationRequest{
		IssueID:   issueID,
		UseStream: true,
		UserInput: userInput,
	}

	data, err := json.Marshal(investigationReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal investigation request: %w", err)
	}

	stream, err := c.issueInvestigateWithStream(ctx, data)
	if err != nil {
		return "", fmt.Errorf("failed to investigate issue: %w", err)
	}
	defer stream.Close()

	renderer := &streamRenderer{}
	err = sse.Read(stream, sdk.ErrorFromCode, renderer.handle)
	renderer.breakLine()
	if err != nil {
		return "", fmt.Errorf("failed to read investigation stream: %w", err)
	}
	// The SSE done event precedes the authenticated end of the encrypted stream.
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return "", fmt.Errorf("failed to verify investigation stream: %w", err)
	}
	fmt.Println("--- done ---")

	return renderer.answer.String(), nil
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
	// initialize anonymizer for automatic PII/secrets protection
	// automatically masks credentials, emails, IPs, database URLs, API keys, etc.
	anon, err := anonymizer.NewAnonymizer(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create anonymizer: %w", err)
	}

	client := Client{
		anonymizer: anon,
	}

	configs := []sdk.CallConfig{
		{
			Calls:  []any{&client.errorReport},
			Host:   serverHost,
			Name:   "errors_report",
			Path:   "/api/v1/proxy/errors/report",
			Method: sdk.CallMethodPOST,
		},
		{
			Calls:  []any{&client.issueCreate},
			Host:   serverHost,
			Name:   "support_issues",
			Path:   "/api/v1/proxy/support/issues",
			Method: sdk.CallMethodPOST,
		},
		{
			Calls:  []any{&client.issueStatus},
			Host:   serverHost,
			Name:   "support_issue_status",
			Path:   "/api/v1/proxy/support/issues/:issueID/status",
			Method: sdk.CallMethodGET,
		},
		{
			Calls:  []any{&client.issueInvestigate, &client.issueInvestigateWithStream},
			Host:   serverHost,
			Name:   "support_investigate",
			Path:   "/api/v1/proxy/support/investigate",
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
		sdk.WithInstallationID(system.GetInstallationID()),
		sdk.WithClient("Report-Errors-Example", "1.0.0"),
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

func getErrorDetails() map[string]any {
	return map[string]any{
		"error_type":   "connection_timeout",
		"message":      "Failed to connect to target host admin@company.com with API key sk-1234567890abcdef",
		"target_host":  "192.168.1.100",
		"port":         443,
		"timeout_ms":   5000,
		"retry_count":  3,
		"stack_trace":  "goroutine panic at scanner.go:142",
		"database_url": "postgres://user:password123@db.internal:5432/app",
		"api_endpoint": "https://api.service.com/v1/data?token=abc123xyz789",
		"user_email":   "john.doe@company.com",
		"config_path":  "/etc/myapp/config.yml",
	}
}

func getComponentsLogs() []models.SupportLogs {
	return []models.SupportLogs{
		{
			Component: models.ComponentTypePentagi,
			Logs: []string{
				"ERROR: Scanner pattern match timeout after 30s for user john.doe@company.com",
				"WARN: Memory usage exceeded 80% threshold, DB connection postgres://admin:secret@db:5432/prod",
				"INFO: Switching to backup scanning method with API key sk-abcd1234efgh5678",
				"ERROR: Backup method failed - insufficient permissions for file /home/user/.ssh/id_rsa",
				"DEBUG: Processing request from IP 10.0.1.50 with session token sess_9876543210",
				"TRACE: Credit card validation failed for 4532-1234-5678-9012",
			},
		},
	}
}

func getIssueDetails() map[string]any {
	return map[string]any{
		"problem_description": "Scanner fails to detect specific vulnerability patterns on server admin@prod.company.com",
		"affected_patterns":   []string{"CVE-2023-1234", "CVE-2023-5678"},
		"environment":         "production",
		"severity":            "high",
		"server_config":       "aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"affected_users":      []string{"admin@company.com", "support@company.com", "security@company.com"},
		"database_info":       "mysql://root:supersecret@prod-db.internal:3306/vulnerabilities",
		"internal_token":      "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.token",
	}
}

func main() {
	var (
		serverHost = flag.String("host", "support.pentagi.com", "Cloud server host")
		licenseKey = flag.String("license", "", "License key (optional)")
		example    = flag.String("example", "all", "Example to run: error, issue, investigate, stream, all")
		// The "investigate" and "stream" examples are normally run standalone,
		// against an issue created by a previous "-example issue" invocation:
		// that command prints the issue_id you pass here. Leave empty to have
		// the example create a fresh issue for a self-contained demo run.
		issueID = flag.String("issue-id", "", "Existing issue ID to continue (from a prior -example issue run)")
		caPath  = flag.String("ca", "", "Extra CA bundle to trust (for private deployments)")
	)
	flag.Parse()

	logrus.SetLevel(logrus.DebugLevel)

	logrus.Printf("starting support client")
	logrus.Printf("server: %s", *serverHost)
	if *licenseKey != "" {
		logrus.Printf("license: configured")
	}

	client, err := NewClient(*serverHost, *licenseKey, *caPath)
	if err != nil {
		logrus.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	switch *example {
	case "error":
		runErrorReporting(ctx, client)
	case "issue":
		runIssueCreation(ctx, client)
	case "investigate":
		runInvestigation(ctx, client, parseIssueID(*issueID))
	case "stream":
		runStreamInvestigation(ctx, client, parseIssueID(*issueID))
	case "all":
		runAllExamples(ctx, client)
	default:
		logrus.Fatalf("unknown example: %s. Use: error, issue, investigate, stream, all", *example)
	}

	logrus.Println("support client demonstration completed")
}

// parseIssueID returns uuid.Nil for an empty flag (meaning "create a new
// issue"), so callers can use it directly without a separate presence check.
func parseIssueID(raw string) uuid.UUID {
	if raw == "" {
		return uuid.Nil
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		logrus.Fatalf("invalid -issue-id %q: %v", raw, err)
	}

	return id
}

func runErrorReporting(ctx context.Context, client *Client) {
	logrus.Println("=== Automated Error Reporting ===")

	if err := client.ReportError(
		ctx, models.ComponentTypePentagi, getErrorDetails(),
	); err != nil {
		logrus.Errorf("failed to report error: %v", err)
		return
	}

	logrus.Println("error reported successfully with data anonymization")
}

func runIssueCreation(ctx context.Context, client *Client) uuid.UUID {
	logrus.Println("=== Support Issue Creation ===")

	issueID, err := client.CreateSupportIssue(
		ctx, models.ComponentTypePentagi, getIssueDetails(), getComponentsLogs(),
	)
	if err != nil {
		logrus.Errorf("failed to create support issue: %v", err)
		return uuid.Nil
	}

	// This ID is what "-example investigate -issue-id <id>" and
	// "-example stream -issue-id <id>" expect: it is the only handle the
	// client has for continuing the conversation the server keeps per issue.
	logrus.WithField("issue_id", issueID).Println(
		"support issue created with data anonymization; " +
			"pass it to -issue-id to continue investigating it",
	)

	return issueID
}

// resolveIssueID creates an issue if needed and waits for it to accept a turn.
func resolveIssueID(ctx context.Context, client *Client, issueID uuid.UUID) (uuid.UUID, error) {
	if issueID != uuid.Nil {
		logrus.WithField("issue_id", issueID).Println("using existing issue")
	} else {
		var err error
		issueID, err = client.CreateSupportIssue(
			ctx, models.ComponentTypePentagi, getIssueDetails(), getComponentsLogs(),
		)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to create support issue: %w", err)
		}
		logrus.WithField("issue_id", issueID).Println("created issue")
	}

	ctx, cancel := context.WithTimeout(ctx, issueWaitTimeout)
	defer cancel()

	for {
		data, err := client.issueStatus(ctx, []string{issueID.String()})
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to get support issue status: %w", err)
		}
		status, err := models.ParseEnvelope[models.SupportIssueStatusResponse](data)
		if err != nil {
			return uuid.Nil, fmt.Errorf("failed to parse support issue status: %w", err)
		}
		if err := status.Valid(); err != nil {
			return uuid.Nil, fmt.Errorf("invalid support issue status: %w", err)
		}
		if status.Status == models.SupportIssueStatusProcessed {
			return issueID, nil
		}
		select {
		case <-ctx.Done():
			return uuid.Nil, fmt.Errorf("waiting for support issue: %w", ctx.Err())
		case <-time.After(issuePollInterval):
		}
	}
}

func runInvestigation(ctx context.Context, client *Client, issueID uuid.UUID) {
	logrus.Println("=== AI Investigation ===")

	issueID, err := resolveIssueID(ctx, client, issueID)
	if err != nil {
		logrus.Error(err)
		return
	}

	// Log processing is complete; the call waits for the assistant's answer.
	userInput := "The scanner works fine with other CVE patterns but consistently fails on these two specific ones. Could this be related to pattern complexity or memory constraints?"

	answer, err := client.InvestigateIssue(ctx, issueID, userInput)
	if err != nil {
		logrus.Errorf("failed to investigate issue: %v", err)
		return
	}

	logrus.WithField("answer", answer).Println("AI investigation result")

	// follow-up investigation, same issue_id continues the conversation
	followUpInput := "Based on your analysis, what specific configuration changes would you recommend to resolve the memory constraint issue?"

	followUpAnswer, err := client.InvestigateIssue(ctx, issueID, followUpInput)
	if err != nil {
		logrus.Errorf("failed to investigate follow-up: %v", err)
		return
	}

	logrus.WithFields(logrus.Fields{
		"issue_id": issueID,
		"answer":   followUpAnswer,
	}).Println("follow-up recommendations")
}

func runStreamInvestigation(ctx context.Context, client *Client, issueID uuid.UUID) {
	logrus.Println("=== AI Streamed Investigation ===")

	issueID, err := resolveIssueID(ctx, client, issueID)
	if err != nil {
		logrus.Error(err)
		return
	}

	// After log processing, the answer arrives incrementally as SSE events.
	userInput := "Please provide a detailed analysis of the scanner performance issues and step-by-step troubleshooting guide."

	// The renderer prints the answer live, token by token, as it streams in —
	// see stream_render.go. The returned string is the same text, assembled,
	// for callers that need it programmatically rather than on a terminal.
	if _, err := client.InvestigateIssueWithStream(ctx, issueID, userInput); err != nil {
		logrus.Errorf("failed to stream investigate issue: %v", err)
		return
	}

	logrus.WithField("issue_id", issueID).Println("streamed investigation complete")
}

// runAllExamples walks the full, real-world flow end to end:
//  1. report a client-side error — logged server-side, no reply expected;
//  2. create one support issue and get its issue_id back;
//  3. investigate that same issue (non-stream, then a follow-up), waiting
//     for the server to analyze it and answer;
//  4. continue the very same issue over the streamed endpoint.
//
// Steps 3 and 4 reuse one issue_id on purpose, to demonstrate that it is the
// identifier client code must keep in order to hold a multi-turn
// conversation with the server about one issue.
func runAllExamples(ctx context.Context, client *Client) {
	runErrorReporting(ctx, client)

	issueID := runIssueCreation(ctx, client)
	if issueID == uuid.Nil {
		return
	}

	runInvestigation(ctx, client, issueID)
	runStreamInvestigation(ctx, client, issueID)
}
