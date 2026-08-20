# Threat model

## Objective

Allow one explicitly selected, already installed language model to run locally in
LM Studio on Windows while reducing accidental or application-initiated external
network communication. With `ProjectFirewall = 'ON'`, fail closed when the project-managed
boundary cannot be verified. With `ProjectFirewall = 'OFF'`, make the trust delegation
and lack of project verification explicit.

## Assets

- prompts, responses, local documents, and embeddings
- model and runtime inventory
- access tokens and plugin/MCP configuration that may exist in old settings
- the integrity of the approved-model decision
- the integrity of an optional vision projector paired with the approved model
- the integrity of the Windows host's network boundary

## Trust boundaries

```text
Internet / LAN
      |
      | ProjectFirewall ON: verified per-executable non-loopback block
      | ProjectFirewall OFF: organization-owned policy (not verified here)
      v
Selected network boundary  <---- deployment-owner decision
      |
      | loopback remains available
      v
LM Studio GUI <----> lms / llmster <----> inference runtime
      |
      v
User profile: settings, MCP file, model data, logs, backups, state
```

With `ProjectFirewall = 'ON'`, Windows Firewall is the enforced and project-verified
boundary. With `ProjectFirewall = 'OFF'`, the organization-owned control is a trusted
deployment assumption and this project never reports it as verified. LM Studio
JSON settings and model selection are defense in depth. The normal-user process
creates and validates a short-lived hashed request before elevation; the elevated
child accepts only the fixed model-link operation and, when selected, project
Firewall setup. Requests expire after fifteen minutes.

## In-scope threats

- accidental update, discovery, proxy, plugin, or MCP network activity by covered
  LM Studio executables
- LM Studio settings drifting back to network-friendly or development values
- public API auto-start or a non-loopback listener exposing a local service
- an additional local LLM being selected or loaded unintentionally
- a runtime or application update introducing a new executable without a rule
- partial JSON writes, invalid JSON, interrupted setup, and failed restoration
- a modified, wrong-type, or stale backup being chosen for restoration
- overly broad administrator execution when only model-link and Firewall work needs elevation
- logs or backups being accidentally committed to the public repository
- plaintext model/share paths being unnecessarily persisted in launch state
- a substituted installer or runtime being accepted during automated provisioning
- unbounded network access during first-use runtime acquisition
- substituted uninstall commands, deletion of unrelated user directories, or
  following shared-model links during complete removal

## Out of scope

- malicious local administrators, kernel drivers, Windows compromise, or physical
  access
- traffic tunneled by another executable not covered by the discovered paths
- malware that alters the scripts, state, Firewall policy, or binaries before use
- data exposure over loopback to another local process
- effectiveness of organization-level Firewall, EDR, VPN, proxy, DNS, router,
  hypervisor, or container controls selected through `ProjectFirewall = 'OFF'`
- confidentiality of prompts already sent to extensions or tools before hardening
- supply-chain guarantees for LM Studio, models, runtimes, Windows, or hardware

## Controls and failure modes

| Risk | Control | Failure behavior |
|---|---|---|
| External traffic from covered binary | Inbound/outbound non-loopback block rules, verified for every profile/protocol/port/interface/service | Setup/launch stops if rules cannot be installed and fully verified |
| Organizational enforcement delegated | Explicit `ProjectFirewall = 'OFF'` state, zero project-rule claim, warning on every launch | No false verified/localhost-only claim; deployment owner remains responsible for validation |
| New binary after update | Recorded executable inventory plus launch-time discovery | Launch refuses and asks for setup to be re-run |
| Internal setting drift | Narrow merge of enforced values before setup/launch | Existing file is backed up; failed verification rolls back |
| Public API exposure | Disable auto-start, save loopback bind address, then inspect actual listeners after GUI and model startup | Launch fails on any LM Studio-related non-loopback TCP listener |
| Wrong model | Exact local inventory resolution and load verification | Launch unloads and stops; it does not substitute a model |
| Model or projector path changes | Setup-owned symbolic-link registration plus SHA-256 identities of link targets and the indexed model path; plaintext share paths are not saved in setup or launch state | Setup/launch stops instead of selecting another file |
| Missing or incompatible vision projector | At most one `mmproj-*.gguf` is paired with the one primary GGUF; the first launch requires LM Studio to report `vision: true` and later launches detect capability drift | Launch stops instead of silently presenting a text-only model as image-capable |
| Additional local LLM | Refused | User must remove it from the active inventory before setup or launch |
| Corrupt or foreign-profile restore source | Manifest type, location, target paths, JSON, and SHA-256 validation | Restore stops before changing live files |
| Partial restore | Restore-safety backup and atomic replacement | Files are reverted; project-managed rules remain restrictive and external controls remain untouched |
| UAC cancellation | Main work stays non-elevated | Setup remains incomplete or restore leaves blocking rules |
| Installer substitution | SHA-256, valid Authenticode signature, pinned signer thumbprint, product name/version, and tested NSIS format | Installation stops before executing the file |
| Runtime substitution or ambiguous selection | Exact `name@version` query, non-interactive selection, post-download inventory verification, and first-load compatibility check | Workflow stops without marking secure setup complete |
| First-run provisioning traffic | Temporary non-loopback bootstrap block; `OnlinePinned` logs and opens a bounded runtime-only provisioning phase | Failure attempts graceful process shutdown and restores the bootstrap block |
| Uninstaller substitution | Pinned version, Authenticode signer, package metadata, Windows registration, and a constructed fixed argument list | Complete uninstall stops before executing the vendor uninstaller |
| Overbroad local-data deletion | Three exact current-user roots, same-parent quarantines, and a link-safe tree walk | Unknown paths and reparse-point roots are refused; shared targets are not followed |
| Overbroad Firewall cleanup | Two exact project-owned Firewall groups handled by a short-lived hashed elevation request | Organization-owned and unrelated rules are not selected |

## Residual risk

Per-program Firewall rules, delegated organization controls, and internal settings are not equivalent to network
namespace isolation. High-sensitivity deployments should add an isolated Windows
account or VM, deny network at a hypervisor/router boundary, encrypt storage, and
apply independent monitoring appropriate to the data classification.

A model stored on a Windows share requires intentional LAN/SMB access. File-share
traffic performed by Windows components is outside the discovered LM Studio
executable rules. Strictly disconnected deployments must keep the model local.
The path hash prevents ordinary plaintext persistence, but it is an integrity
identifier rather than a secret and may be guessable when candidate paths are
already known.

The gitignored deployment configuration contains the plaintext share path and is
trusted package-owner input. End users do not edit it or LM Studio model settings.
Symbolic-link creation is checked before setup can complete; unsupported Windows
link policy or permission causes a fail-closed setup result.

Review this model whenever LM Studio changes executable layout, CLI JSON output,
runtime management, local-server behavior, or settings storage.
