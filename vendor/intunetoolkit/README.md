# IntuneToolKit Vendored Scripts

These PowerShell scripts are copied from the IntuneToolKit project
by AliAlame (GitHub user `CYEBRSYSTEM-AliAlame`).

Original repository:
https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit

Vendored scripts:
- Export-IntuneDashboard.ps1
- Find-IntunePolicyConflict.ps1
- Get-IntuneBitLockerKeys.ps1
- Invoke-IntuneBulkActions.ps1
- Test-IntuneUpdateRingHealth.ps1
- Get-IntuneUpdateComplianceReport.ps1
- Get-IntuneGroupPolicies.ps1
- Get-EntraAppRegistrationAudit.ps1
- Get-IntuneComplianceReport.ps1

IAMinistrator invokes these via its PowerShell handler using `pwsh -File`.

## Script resolution order

IAMinistrator resolves scripts in this order:

1. `--scripts-dir <path>/<script>.ps1` — explicit path override
2. `<exe_dir>/vendor/intunetoolkit/<script>.ps1` — beside the installed `iam` binary
3. `vendor/intunetoolkit/<script>.ps1` — relative to the current working directory

This means the scripts in this directory are used automatically when no
`--scripts-dir` flag is provided, as long as the binary is run from the
repository root or the `vendor/` tree is placed beside the installed binary.

## Attribution

All scripts in this directory remain the work of **AliAlame**
(https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit).
They are included here unmodified for local invocation convenience.
