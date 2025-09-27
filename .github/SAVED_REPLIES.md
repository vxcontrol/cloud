# Saved Replies

These are standardized responses for the VXControl Cloud SDK Development Team to use when responding to Issues and Pull Requests. Using these templates helps maintain consistency in our communications and saves time.

Since GitHub currently does not support repository-wide saved replies, team members should maintain these individually. All responses are versioned for easier updates.

While these are templates, please customize them to fit the specific context and:
- Welcome new contributors
- Thank them for their contribution
- Provide context for your response
- Outline next steps

You can add these saved replies to [your personal GitHub account here](https://github.com/settings/replies).

## Issue Responses

### Issue: Already Fixed (v1)
```
Thank you for reporting this issue! This has been resolved in a recent release. Please update to the latest version (see our releases page) and verify if the issue persists.

If you continue experiencing problems after updating, please:
1. Check your configuration against our documentation (README.md, API.md)
2. Verify your Go version compatibility (Go 1.24.0+)
3. Test with our working examples in the examples/ directory
4. Include SDK version, license type, and relevant error logs
```

### Issue: Need More Information (v1)
```
Thank you for your report! To help us better understand and address your issue, please provide additional information:

1. VXControl Cloud SDK version and Go version
2. Which SDK components are affected (sdk, models, anonymizer)
3. Target cloud services (Update, Package, Support, AI Investigation)
4. License type and any relevant error messages
5. Minimal code example demonstrating the issue
6. Expected vs actual behavior

Please update your issue using our bug report template for consistency.
```

### Issue: Cannot Reproduce (v1)
```
Thank you for reporting this issue! Unfortunately, I cannot reproduce the problem with the provided information. To help us investigate:

1. Verify you're using the latest SDK version
2. Provide your complete SDK configuration (CallConfig, Options)
3. Share relevant error logs and stack traces
4. Include step-by-step reproduction instructions with minimal code example
5. Specify which cloud services are involved (Update/Package/Support/AI)
6. Include Go version and target OS

Please update your issue with these details so we can better assist you.
```

### Issue: Expected Behavior (v1)
```
Thank you for your report! This appears to be the expected behavior because:

[Explanation of why this is working as designed]

If you believe this behavior should be different, please:
1. Describe your integration use case in detail
2. Explain why the current SDK behavior doesn't meet your needs
3. Suggest alternative API behavior that would work better
4. Consider whether this affects other SDK users

We're always open to improving VXControl Cloud SDK functionality.
```

### Issue: Missing Template (v1)
```
Thank you for reporting this! To help us process your issue efficiently, please use our issue templates:

- Bug Report Template for SDK issues, integration problems, or security concerns
- Enhancement Template for new features, API improvements, or performance optimizations

Please edit your issue to include the template information. This helps ensure we have all necessary details to assist you effectively.
```

### Issue: PR Welcome (v1)
```
Thank you for raising this issue! We welcome contributions from the cybersecurity community.

If you'd like to implement this yourself:
1. Check our [contribution guidelines](CONTRIBUTING.md)
2. Review the SDK architecture documentation
3. Consider security implications (especially for cryptographic modifications)
4. Include comprehensive tests and documentation
5. Ensure backward compatibility with existing integrations

Feel free to ask questions if you need guidance. We're here to help!
```

## PR Responses

### PR: Ready to Merge (v1)
```
Excellent work! This PR meets our quality standards and I'll proceed with merging it.

If you're interested in further contributions, check our:
- Open issues for enhancement opportunities
- Examples directory for integration pattern improvements
- Documentation that could benefit from additional clarity

Thank you for improving VXControl Cloud SDK for the cybersecurity community!
```

### PR: Needs Work (v1)
```
Thank you for your contribution! A few items need attention before we can merge:

[List specific items that need addressing]

Common requirements:
- Comprehensive tests with unique scenarios
- Package documentation (doc.go) updates for public APIs
- Security considerations for cryptographic changes
- Performance benchmarks for critical path modifications
- Anonymization implementation for AI-related features

Please update your PR addressing these points. Let us know if you need any clarification.
```

### PR: Missing Template (v1)
```
Thank you for your contribution! Please update your PR to use our PR template.

The template helps ensure we have:
- Clear description of changes and affected SDK components
- Testing information and benchmark results
- Security considerations for cryptographic modifications
- Documentation updates (doc.go, README.md, API.md)
- Integration notes for SDK users

This helps us review your changes effectively and ensure quality.
```

### PR: Missing Issue (v1)
```
Thank you for your contribution! We require an associated issue for each PR to:
- Discuss approach before implementation
- Track related changes and dependencies
- Maintain clear project history

Please:
1. Create an issue describing the problem or enhancement
2. Link it to this PR using "Closes #issue-number"
3. Update the PR description with the issue reference

This helps us maintain good project organization and review quality.
```

### PR: Inactive (v1)
```
This PR has been inactive for a while. To keep our review process efficient:

1. If you're still working on this:
   - Let us know your timeline
   - Update with latest main branch
   - Address any existing feedback

2. If you're no longer working on this:
   - We can close it
   - Someone else can pick it up

Please let us know your preference within the next week.
```

### General: Need Help (v1)
```
I need additional expertise on this. Pinging:
- @asdek for technical review and architecture decisions

[Specific questions or concerns that need addressing]
```
