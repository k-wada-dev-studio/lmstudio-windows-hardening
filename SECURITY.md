# Security policy

## Supported versions

Only the newest tagged release is supported. The current `0.1.0-preview` release
is a preview and should be evaluated on a non-production Windows account first.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability, leaked credential, local
path disclosure, or bypass that could expose prompts, documents, model data, or
network access. Use GitHub's private vulnerability reporting feature for this
repository. If private reporting is not enabled, contact the repository owner
privately and ask for a secure reporting channel without including exploit or
secret details in the first message.

Include the affected release, Windows and LM Studio versions, prerequisites,
impact, and minimal reproduction steps. Remove usernames, tokens, model files,
logs, and other personal data. Maintainers should acknowledge a report within
seven days and provide status updates at least every fourteen days.

## Sensitive artifacts

Backups may contain settings that predate hardening, including service tokens or
plugin configuration. Logs and state files can reveal usernames, local paths,
model names, and installed runtimes. Never attach the following to a public issue:

- `%USERPROFILE%\.lmstudio\settings.json` or `mcp.json`
- `%USERPROFILE%\.lmstudio\secure-setup\backups`
- full logs or `setup-state.json` without careful redaction
- model weights, access tokens, or private prompts/documents

The repository `.gitignore` excludes common copies of these artifacts, but it
cannot protect files that are explicitly force-added.
