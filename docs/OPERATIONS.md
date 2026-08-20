# Operations guide

## 1. Provision before lockdown

Use trusted official sources while normal internet access is still available.

1. Install and start LM Studio once so its profile and `lms` CLI are initialized.
2. Install a compatible runtime and place one intended primary GGUF on the
   approved Windows shared folder. For image input, also place exactly one
   matching `mmproj-*.gguf` beside it. Do not place two projector variants there.
3. As the deployment owner, copy `config/deployment.local.psd1.example` to the
   gitignored `config/deployment.local.psd1`, set `ModelSourcePath`, and select
   `ProjectFirewall`. The package default is `'OFF'`, which delegates network
   enforcement to the organization and is not verified by this project. Select
   `'ON'` when project-created and audited Windows Firewall rules are required. Users do
   not change LM Studio's My Models or JSON settings. Setup registers the shared
   primary GGUF and optional projector through managed symbolic links and detects
   its `modelKey` automatically.
4. Close LM Studio, tray/background helpers, and `llmster` completely.
5. Keep a separate recovery path to the original installer and documentation.

Do not place real `settings.json`, `mcp.json`, logs, models, or runtime binaries
inside this repository.

To change `ProjectFirewall` after setup, close LM Studio, change `'ON'` or
`'OFF'` in the private configuration, and run setup again. Switching to `'OFF'`
removes only the project-owned Firewall group after first invalidating the old
secure-launch state. Organization-owned controls are never changed.

## 2. Review and test the package

Run both tests from an ordinary PowerShell prompt:

```powershell
powershell.exe -NoProfile -File .\tests\Test-Static.ps1
powershell.exe -NoProfile -File .\tests\Test-Behavior.ps1
```

Read the scripts and compare `config/settings.baseline.json` with your policy.
The baseline is documentation; changing it alone does not change enforcement.

## 3. Initial setup

Run as the normal LM Studio user:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Setup-LMStudio.ps1
```

The non-technical entry point is `1-Setup.cmd`. If an explicit selection is
required for automation, append `-AllowedModel 'publisher/model-key'` to the
PowerShell command. The first secure launch verifies this value and rejects an
inventory containing another LLM.

If a specific runtime must be pinned, pass its exact installed identifier using
`-RequiredRuntime`. `ProjectFirewall = 'ON'` or `'OFF'` belongs in the private deployment configuration,
not on the user's command line. Avoid `-SkipFirewall`; it deliberately leaves the
state incomplete and is not a substitute for `ProjectFirewall = 'OFF'`. The policy is intentionally limited to one local LLM; embedding
models are inventoried separately.

Expected result:

- Windows displays one UAC approval for the scoped model-link and project Firewall ON/OFF child operation
- the shared model package (primary GGUF and optional projector) is link-registered; it is not moved, copied, loaded, or downloaded
- model and runtime validation is marked pending for the first secure GUI launch
- a backup is created only if JSON values need to change
- `secure-setup\setup-state.json` reports `Complete: true` and the selected Firewall mode
- the state contains no plaintext share path
- LM Studio remains closed

## 4. Routine launch

Always use:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\src\Start-LMStudio-Secure.ps1
```

The launcher audits the recorded state and exact executable inventory. In
with `ProjectFirewall = 'ON'` it also audits the project rules; with `'OFF'` it
warns that organizational enforcement is delegated and not verified here. It
re-applies JSON defense-in-depth if necessary, disables public API auto-start,
restricts its saved bind address to loopback, and starts LM Studio as the normal user.
It rejects any actual LM Studio-related TCP listener outside loopback. On the
first run it resolves the managed model and records the runtime/path hashes; later
runs check them for drift. It unloads prior models, loads the approved model, and
verifies its identity and reported vision capability. A configured projector must
produce `vision: true` or the launch fails closed.
If any check fails, treat the refusal as a security signal rather than bypassing
the script.

## 5. Update LM Studio, runtime, or model

Updates intentionally require a new trust decision because executable paths and
runtime inventory may change.

1. Close LM Studio and `llmster`.
2. Restore JSON. The safe default keeps the existing network block:

   ```powershell
   .\src\Restore-LMStudio.ps1
   ```

3. If the official updater cannot work with the block present, explicitly run
   restore with `-RemoveFirewall`. Understand that external connectivity is then
   restored for those binaries.
4. Apply the trusted update and acquire the new model/runtime, if required.
5. Close all LM Studio processes again.
6. Re-run setup with the new exact model/runtime identifiers.
7. Run the secure launcher and verify its summary and log.

Never add a broad allow rule to compensate for an update. Setup should discover
and protect the new executable paths.

## 6. Restore and recovery

Standard restore:

```powershell
.\src\Restore-LMStudio.ps1
```

The newest verified original setup backup is selected. Launch-time backups and
`restore-safety-*` directories are excluded. To choose an older original backup,
pass its directory with `-BackupPath`; it must still be below the managed backup
root and pass manifest/hash validation.

The restore sequence is deliberately conservative:

1. refuse while LM Studio processes are active
2. verify the original backup and hashes
3. back up current files to `restore-safety-*`
4. restore JSON and mark secure launch incomplete
5. remove only the recorded primary-model and optional projector symbolic links below the project-owned model directory
6. when project Firewall is `ON`, keep the fixed managed Firewall group by default and
   remove it only with `-RemoveFirewall`; when it is `OFF`, leave organization-owned controls unchanged

If explicitly requested Firewall removal or UAC approval fails, the JSON restore may already be
complete, but blocking rules remain. This is the safer failure state. Review the
log and re-run restore; do not manually delete unrelated Firewall rules.

## 7. Delete private chat data and logs

Close LM Studio and all runtimes, then use `4-Delete-Private-Data.cmd`. The
entry point requires an explicit confirmation and removes only chat history,
chat attachments, LM Studio server logs, and this project's logs. It does not
remove models, runtimes, settings, credentials, backups, or setup state.

For a read-only inventory, run:

```powershell
.\src\Remove-LMStudio-PrivateData.ps1 -PreviewOnly
```

Deletion refuses reparse points, stages the fixed directories in a same-volume
quarantine, and rolls back if staging fails. Normal filesystem deletion is not
cryptographic secure erasure.

## 8. Manual release checklist

Before tagging a stable release, test on a disposable Windows machine:

- clean profile, first setup, and repeat setup
- settings file with unrelated unknown keys preserved
- MCP file present, absent, and populated
- UAC accepted and cancelled
- Firewall disabled and local-rule merging disabled
- both `ProjectFirewall = 'ON'` and `'OFF'`, including contradictory or unknown saved mode state
- LM Studio running during setup/restore
- allowed model missing, duplicate, and extra LLM present
- text-only model, valid model-plus-mmproj image input, missing/mismatched projector, and two projectors
- compatible runtime present, missing, and changed after setup
- application/runtime update introducing a new executable
- launch success, load timeout, and wrong loaded identifier
- restore with original MCP present and absent
- restore with a modified backup hash
- second restore and recovery from a simulated write failure
- IPv4 and IPv6 external connection attempts blocked; loopback still works
- public API previously set to auto-start on `0.0.0.0:8080` is corrected before launch
- wildcard IPv4/IPv6 or LAN listeners cause secure launch to fail
- shared-folder model access succeeds when that deployment mode is intended

Record Windows edition/build, LM Studio version, CPU/GPU, runtime identifier, and
test outcome without publishing personal paths or sensitive logs.
