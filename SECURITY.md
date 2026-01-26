# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainer directly with details of the vulnerability
3. Include steps to reproduce the issue
4. Allow reasonable time for a fix before public disclosure

## Security Measures Implemented

This platform implements multiple security best practices:

### Authentication & Authorization

- **OAuth2 Token Management**: Secure token caching with automatic refresh
- **API Key Protection**: Environment variable and encrypted secrets storage
- **Thread-Safe Token Handling**: File locking prevents race conditions

### Data Protection

- **Encrypted Secrets**: Age encryption for sensitive configuration files
- **No Hardcoded Credentials**: All secrets loaded from environment or encrypted files
- **Secure File Operations**: Atomic write pattern (temp file + rename)

### Network Security

- **SSL/TLS Verification**: Enabled by default with certificate chain support
- **Proxy Support**: Corporate proxy compatibility with certificate bundling
- **Rate Limiting**: Intelligent backoff on 429 responses

### Input Validation

- **Parameterized Queries**: No raw string concatenation in API calls
- **Input Sanitization**: User inputs validated before processing
- **Output Encoding**: Proper escaping in web templates

### Dependency Management

- **Regular Updates**: Dependencies reviewed and updated for security patches
- **Vulnerability Scanning**: Automated checks via `safety` and `bandit`
- **Pinned Versions**: Critical dependencies pinned to tested versions

## Security Scanning

Run security checks locally:

```bash
# Static analysis with bandit
bandit -r services/ my_bot/ src/ web/ -ll

# Dependency vulnerability check
safety check -r requirements.txt

# Or use the Makefile
make security
```

## Environment Configuration

### Required Security Settings

```bash
# Never commit .env files
# Use .env.sample as a template

# Minimum recommended settings:
SSL_VERIFY=true
LOG_LEVEL=INFO  # Avoid DEBUG in production
```

### Secrets Management

For production deployments:

1. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.)
2. Or use age-encrypted files with `misc_scripts/encrypt_secrets.sh`
3. Never store plaintext credentials in version control

## Secure Development Guidelines

When contributing to this project:

1. **No Credentials in Code**: Use environment variables or config files
2. **Validate All Inputs**: Especially from external APIs and user input
3. **Use Parameterized Queries**: Never concatenate user input into queries
4. **Log Safely**: Never log sensitive data (tokens, passwords, PII)
5. **Handle Errors Gracefully**: Don't expose stack traces to users
6. **Keep Dependencies Updated**: Check for vulnerabilities regularly

## Audit Log

Security-relevant changes are tracked in commit history with clear descriptions.

## Contact

For security concerns, contact the maintainer via LinkedIn or GitHub.

---

*This security policy follows industry best practices and OWASP guidelines.*
