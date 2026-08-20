# GitHub publishing checklist

The repository is prepared locally but should remain a preview until real-machine
validation is recorded.

## Before the first push

1. Read every tracked file and inspect `git status`.
2. Run both PowerShell test scripts.
3. Search once more for usernames, absolute home paths, tokens, model names that
   should remain private, settings, logs, backups, and model binaries.
   Confirm `config/deployment.local.psd1` is ignored and absent from the commit;
   only `deployment.local.psd1.example` belongs in the public repository.
4. Choose a descriptive repository name that does not imply affiliation with LM
   Studio. `windows-local-ai-hardening` is the current working name.
5. Keep the independent-project notice and do not use the LM Studio logo as the
   repository or project logo.
6. Create the repository without generating another README, license, or gitignore.
7. Commit intentionally, push `main`, and confirm Actions passes before creating a
   release.

## Recommended repository settings

- enable private vulnerability reporting
- enable secret scanning and push protection where available
- protect `main` and require the `PowerShell checks` workflow for pull requests
- require pull-request review for workflow changes
- disallow force pushes and branch deletion on `main`
- grant workflows read-only permissions by default
- enable Dependabot alerts if future dependencies are added

After enabling private vulnerability reporting, verify that `SECURITY.md` directs
reporters to a working private channel. The issue form deliberately refuses blank
public issues and warns users not to upload sensitive LM Studio artifacts.

## Preview release notes

State clearly that automated tests do not exercise UAC, Windows Firewall, LM
Studio GUI startup, GPU inference, or live external-traffic blocking. Link to the
manual checklist in `docs/OPERATIONS.md` and publish tested environment results
before changing the version from preview to stable.
