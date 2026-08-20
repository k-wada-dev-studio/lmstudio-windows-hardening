# Changelog

All notable changes are documented here. This project follows Semantic
Versioning after the first stable release.

## Unreleased

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
