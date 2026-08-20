# Changelog

All notable changes are documented here. This project follows Semantic
Versioning after the first stable release.

## Unreleased

- Add a verified complete-uninstall entry point. It runs only the pinned signed
  current-user vendor uninstaller, confirms application removal, deletes the
  fixed profile, legacy Roaming settings, and updater cache through link-safe
  quarantines, removes only project-owned Firewall groups, and preserves shared
  model targets.
  Empty fixed install directories left by the vendor NSIS uninstaller are
  verified and removed without treating a successful uninstall as a timeout.

- Add a one-click Windows entry point that validates and silently installs a
  pinned LM Studio NSIS package, bootstraps the user profile and CLI, optionally
  downloads one exact runtime non-interactively, transitions through a temporary
  first-run network boundary, runs secure setup, and opens the approved model.
  Runtime acquisition now requires an explicit deployment policy, and both the
  bootstrap and routine launch verify the pinned runtime as an exact inventory row.
  Installed-version verification also supports LM Studio builds whose product
  version is empty or Windows-normalized while the file version remains exact,
  while still requiring matching signed-executable, Electron-package, and Windows
  uninstall-registration evidence.
  The first-run handoff now waits for a confirmed GUI-backed CLI connection
  instead of treating early `settings.json` and `lms.exe` extraction as full
  application readiness.

- Add a separate post-uninstall complete-profile deletion entry point. It
  verifies the fixed current-user target and application absence, previews the
  inventory, requires two confirmations, stages the profile on the same volume,
  and deletes links without following shared-folder targets.

- Add an explicitly confirmed private-data deletion entry point for LM Studio
  chat history, chat attachments, LM Studio server logs, and project logs. The
  operation validates fixed profile paths, refuses reparse points, stages data
  on the same volume, and preserves models, settings, credentials, backups, and
  setup state.

- Fix listener verification so outbound `ESTABLISHED` TCP connections are not
  misclassified as non-loopback listening sockets.
- Default `ProjectFirewall` to `OFF`, delegating network enforcement to the
  organization unless the deployment owner explicitly selects project-managed rules.
- Support one approved VLM package as a primary GGUF plus an optional matching
  `mmproj-*.gguf`. Register, validate, record, and restore both managed links;
  require LM Studio to report `vision: true` when a projector is configured.
- Replace the deployment-facing Firewall mode names with the simpler
  `ProjectFirewall = 'ON'` / `'OFF'` switch. Switching to `OFF` during setup
  removes only this project's rule group and invalidates the old launch state
  before reducing protection; the former mode names remain accepted for compatibility.
- Make Restore keep project-managed Firewall rules by default; require explicit
  `-RemoveFirewall` for full removal, accurately report post-removal state-write
  failures, and remove dangling managed model links even when their share is offline.
- Disable LM Studio public API auto-start, save its bind address as loopback,
  back up and restore the internal server configuration, and fail launch when
  actual LM Studio-related TCP listeners are reachable beyond loopback.
- Add deployment-controlled Firewall ownership: project-managed mode creates and audits
  local rules, while externally managed mode delegates enforcement without falsely
  reporting the organization's policy as verified by this project.
- Add package-owner deployment configuration and automatic shared-GGUF symbolic-
  link registration so end users never change LM Studio model settings.
- Replace plaintext model paths in setup and launch state with a normalized
  SHA-256 path identity, and reject every legacy setup-state schema.
- Remove the non-working headless-daemon preflight. Defer model, runtime, and
  estimate validation to the first normal-user secure GUI launch, then persist
  the verified identities for drift checks.
- Use load estimation and actual loading as the default GGUF/runtime
  compatibility check instead of searching human-readable runtime output.
- Cache a complete Firewall verification for 24 hours while still checking the
  executable inventory on every launch, avoiding a long elevated audit each time.

## 0.1.0-preview — 2026-08-19

- Add a repeatable initial hardening script for LM Studio on Windows.
- Add a secure launcher that audits Firewall state and loads one approved model.
- Add a verified restore path with safety backup and scoped Firewall cleanup.
- Add a documented policy baseline, threat model, operating guide, tests, and CI.
- Verify Firewall profiles, protocols, ports, interfaces, services, applications,
  and address filters before declaring localhost-only operation.
- Reject elevated main setup, active runtime restoration, foreign-profile backups,
  and additional local LLMs.
- Add numbered double-click entry points, automatic single-model detection, and a
  clear inventory of LM Studio-owned versus project-owned files.

This preview has static and simulated behavior coverage. Real-machine testing
across LM Studio versions, Windows editions, accelerators, and runtimes is still
needed before a stable release.
