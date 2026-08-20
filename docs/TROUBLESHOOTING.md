# Troubleshooting

## Setup says LM Studio is still running

Exit the GUI and tray/background service, then check Task Manager for LM Studio,
`llmster`, or `lms`. The scripts intentionally do not terminate processes because
that could lose unsaved work or interrupt a write.

## `lms` is not found

Start LM Studio normally once and use its documented CLI bootstrap process. Close
it again before setup. Do not download an unofficial CLI binary to work around the
check. See the official [CLI documentation](https://lmstudio.ai/docs/cli).

## The approved model or runtime is missing

Setup never downloads them. The deployment owner should confirm
`config/deployment.local.psd1` points to an accessible folder containing exactly
one top-level GGUF, and that a compatible runtime is already installed. Users do
not need to discover or enter a `modelKey`.

## Shared-model symbolic-link registration fails

Confirm the source is a UNC path accessible to the same Windows account and the
GGUF is not being renamed or disconnected. Setup uses one elevated child process
for the symbolic link and Firewall rules. If organizational Windows policy blocks
symbolic links, ask the administrator to approve that deployment design; do not
replace `--symbolic-link` with the default import mode because the default moves
the source model.

## Additional local LLMs are rejected

This project intentionally enforces a single-LLM policy. Remove or archive the
other LLMs outside the active LM Studio inventory, then run setup again. Embedding
models are handled separately.

## Firewall setup is refused

Confirm all Windows Firewall profiles are enabled. On managed devices, Group
Policy may set `AllowLocalFirewallRules` to false; local scripts cannot override
that security policy. Ask the organization administrator for an approved design.
If the organization already enforces equivalent protection, the deployment owner
can set `ProjectFirewall = 'OFF'` in the private deployment configuration.
The launcher will clearly say that this external protection is not verified by the
project. Do not use `-SkipFirewall` as a substitute—the saved setup state remains
incomplete by design.

## UAC was cancelled

No broad fallback is attempted. Re-run the command and approve the scoped model-
link operation and the project Firewall ON/OFF operation after reviewing the script. Restore does not
request UAC by default; cancellation during an explicit `-RemoveFirewall` operation leaves the managed blocking rules in place.

## Secure launch reports new or changed executables

LM Studio or a runtime was probably updated. Close all related processes and
re-run `Setup-LMStudio.ps1` so the new executable inventory is recorded and, when
`ProjectFirewall = 'ON'`, receives verified rules. Do not manually suppress the drift check.

## Secure launch reports a non-loopback listener

The launcher found an LM Studio-related process listening on `0.0.0.0`, `::`, a
LAN address, or another non-loopback address. Close LM Studio completely and run
the secure launcher again so it can correct public API auto-start and bind settings
before GUI startup. If the refusal repeats, treat it as an LM Studio behavior or
schema change; keep the Firewall/organization boundary active and review the log.

## Secure launch reports runtime inventory drift

Re-run setup after reviewing the installed runtimes. Drift may be a legitimate
update, but it can also mean an unreviewed execution path was added.

## JSON changed but launch failed

The launcher creates a timestamped backup before correcting drift. The enforced
selected network control remains the primary boundary. Review the newest log in
`%USERPROFILE%\.lmstudio\secure-setup\logs` and fix the first reported error.

## Restore cannot find a backup

Only an original setup backup contains `SettingsPath` in its manifest. If setup
found the JSON already hardened, it may not have needed to create one. Launch and
restore-safety backups are intentionally not treated as the original profile.
Restore cannot invent pre-hardening settings; use your independently retained
backup or reconfigure LM Studio manually while keeping the Firewall block.

## Restore reports a hash mismatch

Do not edit the backup or manifest to make the error disappear. Select another
original backup or inspect the affected files offline. A mismatch can indicate
corruption or tampering.

## Where are logs and backups?

They are below `%USERPROFILE%\.lmstudio\secure-setup`. Treat them as sensitive:
they can contain local paths and pre-hardening configuration. Redact carefully
before sharing excerpts and never upload the backup directory.
