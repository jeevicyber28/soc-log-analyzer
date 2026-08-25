# Security Policy

## Scope

SOC Log Analyzer is a local defensive-analysis tool. It reads supplied files and does not perform network scanning, authentication attempts, exploitation, or contact with source IP addresses.

## Reporting a vulnerability

If you find a security issue in the code, open a private report with the maintainer rather than publishing exploit details immediately. Include the affected file, a safe reproduction using synthetic data, the potential impact, and a suggested remediation.

Do not upload real logs, passwords, API keys, tokens, personal data, or private network information when reporting an issue.

## Data safety

Use only logs you are authorized to analyze. Sanitize all examples before committing them. If credentials or personal data are accidentally committed, revoke or rotate the affected secret first, then remove the data from the repository and its history.
