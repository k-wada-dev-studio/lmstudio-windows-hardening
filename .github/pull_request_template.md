## Purpose

Describe the security property, defect, or documentation gap addressed.

## Safety impact

- Enforced boundary changed:
- New elevated behavior:
- Failure mode:
- Rollback behavior:

## Verification

- [ ] `tests/Test-Static.ps1` passes in Windows PowerShell 5.1
- [ ] `tests/Test-Behavior.ps1` passes in Windows PowerShell 5.1
- [ ] No real settings, MCP files, backups, logs, local usernames, tokens, model files, or runtimes are included
- [ ] Documentation and threat model are updated where behavior changed
- [ ] Manual Windows/LM Studio testing is described, or explicitly marked not performed
