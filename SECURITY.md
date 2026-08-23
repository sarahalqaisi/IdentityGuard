# Security Policy

## Supported versions

Security fixes are applied to the latest release on `main`.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Do not open a public issue containing exploit details, identity data, credentials, or secrets. Include affected version, reproduction steps using synthetic data, impact, and suggested mitigation when possible.

## Deployment boundary

IdentityGuard is a local-first demonstration platform using synthetic data. It has no authentication or authorization layer and must not be exposed to the internet as-is. Authentication, RBAC, CSRF protection, rate limiting, TLS termination, audit logging, privacy/retention governance, and environment-specific hardening are required before handling real data.

The application recommends remediation but never changes identity-provider state. It has no credential collection, password cracking, phishing, or account-takeover functionality.
