# Contributing to VXControl Cloud SDK

Thank you for your interest in contributing to the VXControl Cloud SDK! We welcome contributions from the cybersecurity community and value your help in making this SDK more robust and useful for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security Considerations](#security-considerations)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

This project adheres to ethical cybersecurity practices and responsible disclosure principles. By participating, you agree to:

- Use the SDK and related tools only for legitimate security research and defensive purposes
- Follow responsible disclosure practices for any vulnerabilities discovered
- Respect the intellectual property rights of VXControl and other contributors
- Maintain professional conduct in all interactions with the community
- **Comply with [Terms of Service](TERMS_OF_SERVICE.md)** when testing or using cloud services

## Important Legal Notice

⚠️ **Before contributing or testing cloud integration features, read the [Terms of Service](TERMS_OF_SERVICE.md).**

This SDK provides access to sensitive cybersecurity capabilities through cloud services. Contributors must understand and comply with legal and ethical requirements for:
- Working with threat intelligence and vulnerability data
- Testing AI-powered troubleshooting features with anonymized data
- Handling computational resources and security analysis tools

All contributions involving cloud services integration must align with authorized, defensive cybersecurity purposes only.

## How to Contribute

### Types of Contributions Welcome

1. **Bug Reports**: Help us identify and fix issues in the SDK
2. **Feature Requests**: Suggest new capabilities or improvements
3. **Code Contributions**: Submit bug fixes, optimizations, or new features
4. **Documentation**: Improve existing documentation or add new guides
5. **Examples**: Create practical examples demonstrating SDK usage
6. **Testing**: Enhance test coverage and identify edge cases

### Before You Start

- Check existing issues to avoid duplicating work
- For major changes, create an issue to discuss your proposal first
- Ensure your contribution aligns with the project's security and ethical standards

## Development Setup

### Prerequisites

- Go 1.24.0 or later
- Git
- Linux, macOS, or Windows (for development)
- Access to internet (for dependency downloads and testing)

### Environment Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/your-username/cloud.git
   cd cloud
   ```

2. **Install dependencies**:
   ```bash
   go mod download
   go mod tidy
   ```

3. **Run tests to verify setup**:
   ```bash
   go test ./...
   go test -v ./models -run TestSignature  # Test signature validation
   go test -bench=. ./anonymizer           # Benchmark anonymizer performance
   ```

4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Coding Standards

### Go Style Guidelines

Follow standard Go conventions and best practices:

- Use `gofmt` for code formatting
- Follow [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Use meaningful variable and function names
- Keep functions focused and concise
- Add comments for complex logic, not obvious operations

### Project-Specific Standards

- **Error handling**: Use typed errors and wrap with context using fmt.Errorf
- **Logging**: Use structured logging with lowercase message starts (project standard)
- **Security**: Never log sensitive data (keys, tokens, credentials, PII)
- **Performance**: Optimize for minimal memory allocations and CPU overhead
- **Testing**: Write comprehensive tests with unique scenarios avoiding duplication
- **Comments**: Start with lowercase letters, focus on why/how rather than what
- **Anonymization**: Use anonymizer package for all data sent to AI services

### Code Organization

```
cloud/
├── sdk/                    # Main SDK package
│   ├── sdk.go              # Core SDK structure and configuration
│   ├── calls.go            # Call type definitions and function generation
│   ├── transport.go        # HTTP transport and PoW integration
│   ├── cypher.go           # Streaming encryption/decryption
│   ├── pow.go              # Memory-hard proof-of-work algorithm
│   ├── license.go          # License validation and introspection
│   ├── logger.go           # Structured logging abstraction
│   ├── mock_test.go        # Mock server for testing
│   ├── *_test.go           # Comprehensive test files
│   └── testdata/           # Test fixtures and data
├── models/                 # Type-safe data models with validation
│   ├── types.go            # Component, OS, and architecture enums
│   ├── update.go           # Update service models
│   ├── package.go          # Package service models
│   ├── support.go          # Support service models
│   ├── signature.go        # Ed25519 signature validation
│   └── *_test.go           # Model validation tests
├── anonymizer/             # PII/secrets masking engine
│   ├── anonymizer.go       # Core anonymization interface
│   ├── replacer.go         # Pattern replacement engine
│   ├── wrapper.go          # Streaming anonymization wrapper
│   ├── patterns/           # Pattern recognition database
│   └── testdata/           # Anonymization test datasets
├── system/                 # Cross-platform system utilities
│   ├── installation_id.go  # Stable machine-specific UUID generation
│   ├── utils*.go           # Platform-specific machine identification
│   └── *_test.go           # System utility tests
└── examples/               # Production-ready integration examples
```

## Testing Guidelines

### Test Requirements

All contributions must include appropriate tests:

- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test component interactions
- **Performance tests**: Benchmark critical paths
- **Security tests**: Validate cryptographic operations

### Test Structure

```go
func TestFeatureName(t *testing.T) {
    tests := []struct {
        name     string
        input    InputType
        expected OutputType
        wantErr  bool
    }{
        {
            name:     "valid input scenario",
            input:    validInput,
            expected: expectedOutput,
            wantErr:  false,
        },
        // Add edge cases and error scenarios
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := functionUnderTest(tt.input)

            if tt.wantErr && err == nil {
                t.Error("expected error but got nil")
                return
            }
            if !tt.wantErr && err != nil {
                t.Errorf("unexpected error: %v", err)
                return
            }
            if !tt.wantErr && result != tt.expected {
                t.Errorf("expected %v, got %v", tt.expected, result)
            }
        })
    }
}
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test -v ./sdk                           # SDK functionality tests
go test -v ./models -run TestSignature     # Signature validation tests
go test -v ./anonymizer                    # Anonymization tests
go test -v ./system                        # System utilities tests

# Run benchmarks
go test -bench=. ./sdk                     # SDK performance benchmarks
go test -bench=. ./anonymizer              # Anonymizer performance benchmarks
go test -bench=BenchmarkSignature ./models # Signature performance benchmarks
go test -bench=BenchmarkGetInstallationID ./system # Installation ID benchmarks

# Run examples
cd examples/check-update && go build .
cd examples/download-installer && go build .
cd examples/report-errors && go build .
```

### Test Data

- Store test data in `testdata/` directories
- Use appropriate formats: JSON for API data, YAML for patterns, TXT for datasets
- Never include real credentials or sensitive information
- Use realistic but fabricated data for testing anonymization
- Document test scenarios clearly with descriptive names

## Documentation

### Documentation Standards

- Write clear, concise documentation
- Include practical examples
- Use proper Go documentation format
- Update relevant documentation when making changes

### Documentation Types

1. **Code Comments**: Document public APIs and complex logic
2. **README Updates**: Update main README for significant changes
3. **API Documentation**: Update API.md for new endpoints
4. **Examples**: Create or update examples for new features

### Example Documentation

```go
// ReportError sends an automated error report to support with data anonymization.
// All sensitive data is automatically masked before transmission to AI services.
//
// Example:
//   client := &Client{anonymizer: anon, errorReport: errorReportFunc}
//
//   errorDetails := map[string]any{
//       "message": "Connection failed to admin@company.com",
//       "api_key": "sk-1234567890abcdef",
//   }
//
//   err := client.ReportError(ctx, models.ComponentTypePentagi, errorDetails)
//   if err != nil {
//       return fmt.Errorf("failed to report error: %w", err)
//   }
func (c *Client) ReportError(ctx context.Context,
    component models.ComponentType, errorDetails map[string]any) error {
    // anonymize sensitive data before transmission
    if err := c.anonymizer.Anonymize(&errorDetails); err != nil {
        return fmt.Errorf("failed to anonymize error details: %w", err)
    }
    // Implementation...
}
```

## Security Considerations

### Security Review Process

All contributions undergo security review:

- **Cryptographic changes**: Require thorough review and testing
- **Network code**: Must follow secure communication practices
- **Input validation**: All user inputs must be properly validated
- **Error handling**: Avoid leaking sensitive information in errors

### Security Testing

- Test error conditions and edge cases
- Validate input sanitization
- Test cryptographic operations with known vectors
- Verify that sensitive data is properly protected

### Responsible Disclosure

If you discover security vulnerabilities:

1. **Do not** create public issues for security vulnerabilities
2. Email info@vxcontrol.com with "SECURITY" in subject line
3. Allow reasonable time for assessment and remediation
4. Follow coordinated disclosure practices

## Submitting Changes

### Pull Request Process

1. **Ensure your code follows all guidelines above**
2. **Update documentation** for any user-facing changes
3. **Add or update tests** for your changes
4. **Run the full test suite** and ensure all tests pass
5. **Use conventional commit format** for commit messages
6. **Create a clear pull request description**

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring without functionality changes
- `perf`: Performance improvements
- `security`: Security fixes or improvements

**Examples:**
```bash
git commit -m "feat(sdk): add streaming encryption support"
git commit -m "fix(anonymizer): resolve pattern matching edge case"
git commit -m "docs(readme): update installation instructions"
git commit -m "test(models): add comprehensive signature validation tests"
```

### Pull Request Template

```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass locally
- [ ] Performance impact assessed

## Security Review
- [ ] No sensitive data exposed in logs or errors
- [ ] Input validation implemented where applicable
- [ ] Cryptographic operations follow established patterns
- [ ] No new attack surfaces introduced

## Documentation
- [ ] Code comments added for complex logic
- [ ] API documentation updated (if applicable)
- [ ] Examples updated (if applicable)
- [ ] README updated (if applicable)
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs tests and security scans
2. **Code review**: Maintainers review code quality and security
3. **Security review**: Additional review for security-sensitive changes
4. **Documentation review**: Ensure documentation is complete and accurate

### Merge Criteria

Pull requests are merged when:
- All automated checks pass
- Code review is approved by maintainers
- Security review is completed (if applicable)
- Documentation is complete and accurate
- Changes align with project goals and standards

## Getting Help

### Community Support

- **Documentation**: Check existing documentation first (README.md, API.md)
- **Examples**: Review production-ready examples in examples/ directory
- **Discord Community**: [Join our Discord](https://discord.gg/2xrMh7qX6m) for real-time support
- **Telegram Channel**: [Join our Telegram](https://t.me/+Ka9i6CNwe71hMWQy) for updates

### Maintainer Contact

For complex contributions or questions:
- Create an issue for discussion
- Email: info@vxcontrol.com with "SDK Contribution" in subject line
- For security issues: Email info@vxcontrol.com with "SECURITY" in subject line

## Recognition

Contributors are recognized through:
- Release notes for significant contributions
- Special recognition for security improvements and vulnerability reports
- Community acknowledgment in Discord and Telegram channels

Thank you for helping make VXControl Cloud SDK better for the entire cybersecurity community!
