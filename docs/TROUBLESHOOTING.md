# Troubleshooting

## One-click preview rejects the installer

Do not bypass the check. Confirm the staged file, SHA-256, product version, and
signer-certificate thumbprint in the private deployment configuration. A vendor
certificate renewal requires a new deployment-owner trust decision.

## One-click install reports a version mismatch immediately after installation

Some LM Studio Windows builds expose the installed `LM Studio.exe` version as an
empty value or a Windows-normalized numeric `ProductVersion`; the exact release
remains in `FileVersion`. Current code handles that vendor packaging difference
by requiring the exact file or product version and all three independent installed
signals to agree: the executable's Authenticode signer thumbprint,
`resources\app\package.json`, and the current-user Windows uninstall registration.
Do not weaken or remove those checks. Update the package and re-run the same
`0-Install-and-Setup.cmd`; the correctly installed fixed version is reused rather
than installed again.

## One-click runtime provisioning fails

`OnlinePinned` requires temporary external access for the exact configured
runtime. Re-run the same `0-Install-and-Setup.cmd`; completed installation and
profile phases are revalidated instead of blindly repeated. If external access
is forbidden, have the organization prepare the runtime independently and set
`RuntimeProvisioning = 'Existing'`.

## Complete uninstall preview is refused

Close LM Studio, `lms`, `llmster`, and model runtimes first. The combined
uninstaller also refuses an unknown application version, a changed signer,
missing or inconsistent Windows uninstall registration, a reparse-point data
root, or simultaneous normal and quarantine directories. Do not bypass those
checks. Correct the reported state and rerun `6-Uninstall-and-Delete-All.cmd`.

If the vendor uninstaller succeeded but data or project Firewall cleanup did
not, rerunning is supported. Fixed quarantine directories are recognized.
Shared-folder models are not cleanup targets.

Some NSIS builds remove the application, uninstaller, and Windows registration
but leave an empty `Programs\LM Studio` directory. Current code treats the vendor
uninstall as successful once those three application signals disappear, verifies
the remaining current-user install directory is both fixed and empty, and removes
only that empty directory. A non-empty residue is never deleted automatically.

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
one primary top-level GGUF and at most one matching `mmproj-*.gguf`, and that a compatible runtime is already installed. Users do
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

## PDF works but image upload is unavailable

PDF chat can extract text without the loaded LLM accepting image pixels. Image
input requires a vision-capable model package. For split GGUF distributions,
place the model's matching `mmproj-*.gguf` beside the primary GGUF and run setup
again. Setup accepts one primary plus one projector as one approved model; it
rejects multiple projector variants. The first secure launch must report
`vision: true`. If it still reports false, verify that the primary model,
projector, runtime, and LM Studio version are mutually compatible. See LM
Studio's official [image input documentation](https://lmstudio.ai/docs/python/llm-prediction/image-input).

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
