# Contributing

Thank you for helping improve the project. Changes should keep the default path
fail-closed, offline-capable, and compatible with Windows PowerShell 5.1.

Before opening a pull request:

1. Describe the security property or failure mode being changed.
2. Keep downloads, process termination, broad Firewall edits, and silent policy
   relaxation out of the scripts.
3. Add or update a test for behavior changes.
4. Run `powershell.exe -NoProfile -File .\tests\Test-Static.ps1` and
   `powershell.exe -NoProfile -File .\tests\Test-Behavior.ps1`.
5. Confirm that no personal paths, logs, tokens, settings, MCP configuration,
   model files, or generated backups are staged.

Use focused commits and explain any new elevated operation. Do not commit vendor
binaries or generated model/runtime content. By contributing, you agree that your
contribution is licensed under the repository's MIT License.
