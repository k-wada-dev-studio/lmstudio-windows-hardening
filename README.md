# Windows Local AI Hardening

Unofficial Windows PowerShell scripts for running a previously installed LM
Studio model with network access reduced as far as this project can reasonably
enforce.

> **Preview:** `0.1.0-preview` has static and simulated behavior tests, but has
> not yet been validated across every Windows, LM Studio, accelerator, and runtime
> combination. Test it on a non-production Windows account before relying on it.

> **Live retest required:** On 2026-08-20 the real model loaded and inferred
> successfully, but `lms daemon up` did not start. That dependency has now been
> removed from the code, but the revised shared-folder flow still needs a complete retest. See the
> [live test report](docs/LIVE-TEST-2026-08-20.md).

[日本語版 README](README.ja.md)

## Easiest way to use it

A deployment owner first identifies exactly **one model** in the private
deployment configuration: one primary GGUF, plus at most one matching
`mmproj-*.gguf` image projector when the model supports vision. Users install LM
Studio and its compatible runtime. This project downloads neither models nor runtimes.

1. Close LM Studio completely.
2. Double-click `1-Setup.cmd`.
3. Approve the single Windows administrator prompt for model-link setup (and Firewall setup when `ProjectFirewall = 'ON'`).
4. For normal use, double-click `2-Start-Secure.cmd`.

Setup automatically registers the primary GGUF and optional projector through
managed symbolic links. The first secure GUI launch detects and saves its
`modelKey` and verifies LM Studio's reported `vision` capability. Users do not look up a key or change My Models
or LM Studio JSON settings. Another local LLM causes a safe stop. Saved state
contains the `modelKey` and a SHA-256 path identity, never the plaintext share
path. Double-click `3-Restore.cmd` to restore the pre-setup configuration, or
`Check-Package.cmd` to run package tests.

To permanently delete chat history, chat attachments, LM Studio server logs,
and this project's execution logs, fully close LM Studio and double-click
`4-Delete-Private-Data.cmd`. It requires confirmation and keeps models,
runtimes, settings, credentials, backups, and setup state.

The command files only launch the bundled local `.ps1` files. Their
`ExecutionPolicy Bypass` applies to that one PowerShell process and does not
change the machine-wide execution policy.

## What it does

The project uses two layers:

1. **Network protection ownership is explicit.** The default `ProjectFirewall = 'OFF'`
   delegates enforcement to organizational Firewall, EDR, or network policy;
   this project neither creates nor audits those external controls. Selecting
   `ProjectFirewall = 'ON'` makes Windows Firewall the project-verified boundary.
   Per-program inbound and outbound block rules then cover non-loopback IPv4 and
   IPv6 traffic for the LM Studio GUI, CLI/daemon, and discovered runtime executables.
2. **LM Studio JSON settings are defense in depth.** A small set of network,
   development-plugin, MCP, and automatic-loading settings is reset before use.
   Unrelated JSON properties are preserved. Public API auto-start is disabled,
   and its saved bind address is restricted to `127.0.0.1` if that internal
   configuration file exists.

Setup prepares the shared-model link, selected network-management state, and JSON policy. The first secure
GUI launch verifies and records the model and compatible runtime, rejects other
LLMs, and loads only the approved model. No script downloads models, runtimes, or
applications.

LM Studio documents that chatting with downloaded models, local document chat,
and its local server can operate offline, while search, downloads, runtime
acquisition, and update checks require connectivity. See the official
[offline operation](https://lmstudio.ai/docs/app/offline) and
[CLI documentation](https://lmstudio.ai/docs/cli).

## Requirements

- Windows 10 or 11
- Windows Firewall enabled when `ProjectFirewall = 'ON'`, or separately verified organizational protection when it is `'OFF'`
- Windows PowerShell 5.1
- LM Studio initialized at least once
- deployment configuration prepared by the package owner
- the approved primary GGUF (and its matching `mmproj-*.gguf` for image input) reachable and compatible runtime installed
- `lms` CLI available
- LM Studio and `llmster` fully closed during setup and restore

The default security path requires one administrator approval prompt for the
short model-link operation and the project Firewall ON/OFF operation. Run the main scripts as the normal LM
Studio user.

### One-time package-owner preparation

Copy `config\deployment.local.psd1.example` to
`config\deployment.local.psd1`, then set `ModelSourcePath` to the UNC path of
the shared folder or GGUF file. `ProjectFirewall` defaults to `'OFF'`, which
delegates enforcement to the organization and is not a verified network block by
this project. Select `'ON'` when this project should create and audit its own
Windows Firewall rules. External management is an explicit delegation, not a request to disable protection. A
folder must contain exactly one top-level primary GGUF and may contain one
top-level `mmproj-*.gguf`. More than one primary or projector is rejected. When
`ModelSourcePath` names the primary file directly, the optional projector can be
set with `VisionProjectorPath`. The local file is gitignored so the private share name is not published. Users
who receive the configured package do not perform this step.

To change an already configured PC, close LM Studio, edit `ProjectFirewall`, and
run `1-Setup.cmd` again. Switching to `'OFF'` removes only the rules previously
created in this project's `LM Studio Secure Local-Only` group. It does not disable
Windows Firewall or change organization-owned rules.

## PowerShell usage

1. Review [the threat model](docs/THREAT-MODEL.md) and all three scripts.
2. While normal internet access is still available, install LM Studio and the
   intended runtime, and have the package owner prepare the private deployment
   configuration.
3. Close LM Studio and `llmster` completely.
4. Run setup. The shared GGUF is registered and its `modelKey` is detected automatically:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Setup-LMStudio.ps1
```

Advanced users can explicitly provide the exact `modelKey` if needed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Setup-LMStudio.ps1 `
    -AllowedModel 'publisher/model-key'
```

5. For routine use, start LM Studio only through the secure launcher:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Start-LMStudio-Secure.ps1
```

6. To return the JSON files to the verified pre-setup backup while safely keeping
   this project's Firewall rules:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Restore-LMStudio.ps1
```

Only an intentional full removal uses the explicit `-RemoveFirewall` PowerShell
option. External connectivity is no longer blocked by this project afterward.
When `ProjectFirewall = 'OFF'`, restore never changes organization-owned Firewall, EDR,
or network policy.
Read [Operations](docs/OPERATIONS.md) before updating LM Studio or changing models.

## Files created or changed

The `secure-setup` directory and everything below it are **project-owned files,
not standard LM Studio files**.

| Location | Owner/source | Project behavior |
|---|---|---|
| `%USERPROFILE%\.lmstudio\settings.json` | LM Studio | Changes only enforced fields after backup |
| `%USERPROFILE%\.lmstudio\mcp.json` | LM Studio | Empties `mcpServers` after backup |
| `%USERPROFILE%\.lmstudio\.internal\http-server-config.json` | LM Studio internal | If present, disables API auto-start and binds the saved configuration to loopback after backup |
| `config\deployment.local.psd1` | Deployment owner | Private share location; gitignored and not user-edited |
| `%USERPROFILE%\.lmstudio\models\secure-deployment\` | This project | Managed symbolic links to the primary GGUF and optional `mmproj` projector |
| `%USERPROFILE%\.lmstudio\secure-setup\` | This project | Created on first setup as the managed area |
| `secure-setup\setup-state.json` | This project | Setup result; approved-model identity and runtime validation are finalized only after the first successful secure launch |
| `secure-setup\last-launch.json` | This project | Successful launch result and path identity hash |
| `secure-setup\logs\` | This project | Setup, launch, and restore logs |
| `secure-setup\backups\` | This project | Pre-change and restore-safety JSON backups |
| Firewall group `LM Studio Secure Local-Only` | This project | Created only when `ProjectFirewall = 'ON'`; blocks covered non-loopback traffic |

## Delete private data

`4-Delete-Private-Data.cmd` permanently clears only these four fixed locations:

- `%USERPROFILE%\.lmstudio\conversations` — chat history
- `%USERPROFILE%\.lmstudio\user-files` — chat attachments and metadata
- `%USERPROFILE%\.lmstudio\server-logs` — LM Studio server logs
- `%USERPROFILE%\.lmstudio\secure-setup\logs` — this project's setup, launch, and restore logs

Restore remains a configuration-recovery operation and never silently erases
history. Private-data deletion requires a separate confirmation, refuses
symbolic links and junctions, and leaves unrelated LM Studio data unchanged.
It is ordinary filesystem deletion, not cryptographic secure erasure.

Do not edit `setup-state.json` manually. Missing, damaged, or inconsistent state
causes the launcher to stop without starting LM Studio; re-run setup to recover.
Backups and logs may contain prior settings, local paths, and model names, so never
attach them to a public GitHub issue.

Using a shared folder necessarily requires LAN/SMB traffic to read the model. The
project's Firewall rules cover discovered LM Studio-related executables; they do
not claim to block Windows' own file-sharing traffic. A local model copy is
required for a strictly disconnected system. Verify share permissions and access
on the actual PC after a secure launch.

## Safety behavior

- Setup is repeatable and records setup completion only after the shared-model link,
  JSON policy, and selected network-management state succeed.
- Model and runtime validation occurs during the first secure launch; verified state
  is committed only after the approved model loads successfully.
- When a separate projector is configured, the first secure launch requires LM
  Studio to report `vision: true`; later launches detect capability drift. A
  one-file text-only deployment remains supported.
- JSON changes use a validated temporary file, atomic replacement, backup, and
  rollback.
- With `ProjectFirewall = 'ON'`, a secure launch refuses stale, missing, disabled, profile-limited,
  protocol/port-limited, or otherwise incomplete Firewall rules and detects newly
  introduced LM Studio/runtime executables.
- A full project Firewall audit runs during setup and then at most once every 24 hours while it is `ON`.
  Launches inside that window verify the recorded audit and executable inventory,
  avoiding a long elevated audit on every start.
- `ProjectFirewall = 'OFF'` launches display a warning and never claim that external
  controls were verified. Both modes stop when the executable inventory changes.
- After GUI readiness and again after model loading, the launcher checks actual
  TCP listeners. It fails if an LM Studio-related process listens on `0.0.0.0`,
  `::`, a LAN address, or any other non-loopback address.
- Restore accepts only a hashed original setup backup for the same LM Studio
  profile below the managed backup root and first creates a separate
  restore-safety backup. It refuses while a related runtime is still running and
  keeps the project Firewall rules unless full removal is explicitly requested.
- No script kills a process, weakens a host-wide Firewall default, downloads
  content, or silently permits additional language models.
- Logs, backups, and state stay below `%USERPROFILE%\.lmstudio\secure-setup`.

## Important limitations

This is hardening automation, not a sandbox or endpoint-security product.

- A local administrator, kernel-level software, or another process can bypass or
  alter these controls.
- Windows Firewall rules are attached to executable paths. Re-run setup after an
  LM Studio or runtime update; the launcher refuses unexpected new executables.
- LM Studio's JSON schema is internal and can change. JSON policy is therefore
  secondary to the selected network boundary, and release testing still matters.
- The rules permit loopback communication. Another local process could still
  interact with a local service if one is exposed without authentication.
- Public API settings are an internal LM Studio JSON format. Post-start listener
  verification and the independent network boundary remain separate controls if
  a future LM Studio version changes that format.
- Other applications, plugins, model tools, or user-created scripts are outside
  the rules unless their executable paths are discovered and recorded by setup.
- Organization-managed Firewall policy can disable local rule merging.
  `ProjectFirewall = 'ON'` detects this and stops instead of claiming protection. A
  deployment owner may select `'OFF'` only after confirming the
  organization's alternative enforcement.

See [Troubleshooting](docs/TROUBLESHOOTING.md) for common failures.

## Repository layout

```text
*.cmd      Double-click entry points for setup, launch, restore, private-data deletion, and checks
src/       Setup, secure launch, verified restore, and scoped private-data deletion scripts
config/    Human-reviewable policy baseline
docs/      Threat model and operating guidance
tests/     Static and simulated behavior checks
.github/   Least-privilege CI and contribution templates
```

`config/settings.baseline.json` documents enforced values; it is intentionally
not treated as a vendor-supported configuration API. The scripts contain and
verify the actual merge policy so that a replaced baseline file cannot silently
weaken runtime behavior.

## Testing

```powershell
powershell.exe -NoProfile -File .\tests\Test-Static.ps1
powershell.exe -NoProfile -File .\tests\Test-Behavior.ps1
```

These tests do not change the real LM Studio profile or Windows Firewall. A final
release should additionally be tested manually on a disposable Windows machine
using the checklist in [Operations](docs/OPERATIONS.md).

## Project status and trademarks

This repository is independent and unofficial. It is not affiliated with or
endorsed by LM Studio or Element Labs, Inc. See [NOTICE](NOTICE.md). Licensed
under the [MIT License](LICENSE).
