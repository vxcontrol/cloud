package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vxcontrol/cloud/anonymizer"
	"github.com/vxcontrol/cloud/models"
	"github.com/vxcontrol/cloud/sdk"
	"github.com/vxcontrol/cloud/system"
)

const (
	DefaultMaxRetries = 3
	DefaultTimeout    = 60 * time.Second
)

type Client struct {
	errorReport               sdk.CallReqBytesRespBytes
	issueCreate               sdk.CallReqBytesRespBytes
	issueInvestigate          sdk.CallReqBytesRespBytes
	issueInvestigateWithSteam sdk.CallReqBytesRespReader
	anonymizer                anonymizer.Anonymizer
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

	var response models.SupportErrorResponse
	if err := json.Unmarshal(responseData, &response); err != nil {
		return fmt.Errorf("failed to unmarshal error response: %w", err)
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

	var response models.SupportIssueResponse
	if err := json.Unmarshal(responseData, &response); err != nil {
		return uuid.Nil, fmt.Errorf("failed to unmarshal issue response: %w", err)
	}

	return response.IssueID, nil
}

// InvestigateIssue starts AI-powered investigation of a support issue
func (c *Client) InvestigateIssue(
	ctx context.Context, issueID uuid.UUID, userInput string,
) (string, error) {
	investigationReq := models.SupportInvestigationRequest{
		IssueID:   issueID,
		UseSteam:  false,
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

	var response models.SupportInvestigationResponse
	if err := json.Unmarshal(responseData, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal investigation response: %w", err)
	}

	return response.Answer, nil
}

// InvestigateIssueWithSteam starts AI-powered investigation of a support issue with steam response
func (c *Client) InvestigateIssueWithSteam(
	ctx context.Context, issueID uuid.UUID, userInput string,
) (string, error) {
	investigationReq := models.SupportInvestigationRequest{
		IssueID:   issueID,
		UseSteam:  true,
		UserInput: userInput,
	}

	data, err := json.Marshal(investigationReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal investigation request: %w", err)
	}

	stream, err := c.issueInvestigateWithSteam(ctx, data)
	if err != nil {
		return "", fmt.Errorf("failed to investigate issue: %w", err)
	}

	response, err := io.ReadAll(stream)
	if err != nil {
		return "", fmt.Errorf("failed to read investigation response: %w", err)
	}

	return string(response), nil
}

func NewClient(serverHost, licenseKey string) (*Client, error) {
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
			Name:   "error_report",
			Path:   "/api/v1/errors/report",
			Method: sdk.CallMethodPOST,
		},
		{
			Calls:  []any{&client.issueCreate},
			Host:   serverHost,
			Name:   "issue_create",
			Path:   "/api/v1/issues/create",
			Method: sdk.CallMethodPOST,
		},
		{
			Calls:  []any{&client.issueInvestigate, &client.issueInvestigateWithSteam},
			Host:   serverHost,
			Name:   "issue_investigate",
			Path:   "/api/v1/issues/investigate",
			Method: sdk.CallMethodPOST,
		},
	}

	var buildOptions []sdk.Option
	buildOptions = append(buildOptions,
		sdk.WithTransport(sdk.DefaultTransport()),
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
		example    = flag.String("example", "all", "Example to run: error, issue, investigate, steam, all")
	)
	flag.Parse()

	logrus.SetLevel(logrus.DebugLevel)

	logrus.Printf("starting support client")
	logrus.Printf("server: %s", *serverHost)
	if *licenseKey != "" {
		logrus.Printf("license: configured")
	}

	client, err := NewClient(*serverHost, *licenseKey)
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
		runInvestigation(ctx, client)
	case "steam":
		runSteamInvestigation(ctx, client)
	case "all":
		runAllExamples(ctx, client)
	default:
		logrus.Fatalf("unknown example: %s. Use: error, issue, investigate, steam, all", *example)
	}

	logrus.Println("support client demonstration completed")
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

func runIssueCreation(ctx context.Context, client *Client) {
	logrus.Println("=== Support Issue Creation ===")

	issueID, err := client.CreateSupportIssue(
		ctx, models.ComponentTypePentagi, getIssueDetails(), getComponentsLogs(),
	)
	if err != nil {
		logrus.Errorf("failed to create support issue: %v", err)
		return
	}

	logrus.WithField("issue_id", issueID).Println("support issue created with data anonymization")
}

func runInvestigation(ctx context.Context, client *Client) {
	logrus.Println("=== AI Investigation ===")

	// first create an issue
	issueID, err := client.CreateSupportIssue(
		ctx, models.ComponentTypePentagi, getIssueDetails(), getComponentsLogs(),
	)
	if err != nil {
		logrus.Errorf("failed to create support issue: %v", err)
		return
	}

	logrus.WithField("issue_id", issueID).Println("created issue")

	// then investigate
	userInput := "The scanner works fine with other CVE patterns but consistently fails on these two specific ones. Could this be related to pattern complexity or memory constraints?"

	answer, err := client.InvestigateIssue(ctx, issueID, userInput)
	if err != nil {
		logrus.Errorf("failed to investigate issue: %v", err)
		return
	}

	logrus.WithField("answer", answer).Println("AI investigation result")

	// follow-up investigation
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

func runSteamInvestigation(ctx context.Context, client *Client) {
	logrus.Println("=== AI Steam Investigation ===")

	// first create an issue
	issueID, err := client.CreateSupportIssue(
		ctx, models.ComponentTypePentagi, getIssueDetails(), getComponentsLogs(),
	)
	if err != nil {
		logrus.Errorf("failed to create support issue: %v", err)
		return
	}

	logrus.WithField("issue_id", issueID).Println("created issue")

	// steam investigation
	userInput := "Please provide a detailed analysis of the scanner performance issues and step-by-step troubleshooting guide."

	steamAnswer, err := client.InvestigateIssueWithSteam(ctx, issueID, userInput)
	if err != nil {
		logrus.Errorf("failed to steam investigate issue: %v", err)
		return
	}

	logrus.WithFields(logrus.Fields{
		"issue_id": issueID,
		"answer":   steamAnswer,
	}).Println("steam investigation result")
}

func runAllExamples(ctx context.Context, client *Client) {
	runErrorReporting(ctx, client)
	runIssueCreation(ctx, client)
	runInvestigation(ctx, client)
	runSteamInvestigation(ctx, client)
}
