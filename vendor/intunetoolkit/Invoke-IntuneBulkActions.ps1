#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Performs bulk device actions across Intune-managed devices.
.DESCRIPTION
    Filters devices by OS, compliance status, enrollment type, or group, then
    executes bulk actions: sync, retire, wipe, reboot, or collect diagnostics.
.PARAMETER Action
    Action to perform: Sync, Retire, Wipe, Reboot, CollectDiagnostics.
.PARAMETER Filter
    PowerShell scriptblock filter evaluated against each device object.
.PARAMETER GroupId
    AAD group object ID to target (optional; combined with Filter).
.PARAMETER WhatIf
    Preview devices that would be targeted without executing.

Attribution: IntuneToolKit by AliAlame
  https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Sync','Retire','Wipe','Reboot','CollectDiagnostics')]
    [string]$Action,
    [Parameter()][scriptblock]$Filter,
    [Parameter()][string]$GroupId,
    [Parameter()][switch]$WhatIf,
    [Parameter()][string]$ExportPath
)

function Write-Status { param([string]$Msg,[string]$Color='Cyan'); Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color }
function Write-Section { param([string]$Msg); Write-Host "`n$('='*60)" -ForegroundColor DarkGray; Write-Host "  $Msg" -ForegroundColor Yellow; Write-Host "$('='*60)" -ForegroundColor DarkGray }

function Invoke-MgGraph-Safe {
    param([string]$Uri,[string]$Method='GET',[object]$Body=$null)
    try {
        $params = @{ Uri=$Uri; Method=$Method; ErrorAction='Stop' }
        if ($Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10); $params['ContentType'] = 'application/json' }
        $response = Invoke-MgGraphRequest @params
        $results = @()
        if ($null -ne $response.value) { $results += $response.value } elseif ($response) { $results += $response }
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            if ($null -ne $response.value) { $results += $response.value }
        }
        return ,$results
    } catch { Write-Verbose "Graph call failed: $_"; return @() }
}

Write-Section "AUTHENTICATION"
$context = Get-MgContext
if (-not $context) {
    $scopes = @('DeviceManagementManagedDevices.Read.All')
    if (-not $WhatIf) { $scopes += 'DeviceManagementManagedDevices.PrivilegedOperations.All' }
    Connect-MgGraph -Scopes $scopes -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "LOADING DEVICES"
$allDevices = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,managementAgent,enrolledDateTime,lastSyncDateTime,managementState'
Write-Status "$($allDevices.Count) total managed devices" "Green"

$targetDevices = $allDevices

if ($GroupId) {
    Write-Status "Filtering by group $GroupId" "Cyan"
    $members = Invoke-MgGraph-Safe -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id"
    $memberIds = $members | ForEach-Object { $_.id }
    $targetDevices = $targetDevices | Where-Object { $_.id -in $memberIds }
    Write-Status "$($targetDevices.Count) devices in group" "Cyan"
}

if ($Filter) {
    $targetDevices = $targetDevices | Where-Object { & $Filter $_ }
    Write-Status "$($targetDevices.Count) devices after filter" "Cyan"
}

if ($targetDevices.Count -eq 0) { Write-Host "`n  No devices matched criteria." -ForegroundColor Yellow; exit 0 }

Write-Section "TARGET DEVICES ($($targetDevices.Count))"
$targetDevices | Select-Object deviceName, userPrincipalName, operatingSystem, complianceState, managementState | Format-Table -AutoSize

if ($WhatIf) { Write-Host "`n  [WHATIF] Would perform '$Action' on $($targetDevices.Count) devices." -ForegroundColor Cyan; exit 0 }

$confirm = Read-Host "`n  Confirm: perform '$Action' on $($targetDevices.Count) devices? [y/N]"
if ($confirm -notmatch '^y') { Write-Host "  Aborted." -ForegroundColor Yellow; exit 0 }

Write-Section "EXECUTING: $Action"

$actionMap = @{
    'Sync'               = 'syncDevice'
    'Retire'             = 'retire'
    'Wipe'               = 'wipe'
    'Reboot'             = 'rebootNow'
    'CollectDiagnostics' = 'collectDiagnostics'
}
$actionEndpoint = $actionMap[$Action]

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$success = 0; $failed = 0
$i = 0
foreach ($device in $targetDevices) {
    $i++
    Write-Progress -Activity "Executing $Action" -Status "$i of $($targetDevices.Count): $($device.deviceName)" -PercentComplete (($i/$targetDevices.Count)*100)
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($device.id)/$actionEndpoint"
    $body = if ($Action -eq 'Wipe') { @{ keepEnrollmentData=$false; keepUserData=$false; macOsUnlockCode=$null } } else { $null }
    try {
        $params = @{ Uri=$uri; Method='POST'; ErrorAction='Stop' }
        if ($body) { $params['Body'] = ($body | ConvertTo-Json); $params['ContentType'] = 'application/json' }
        Invoke-MgGraphRequest @params | Out-Null
        $success++
        $results.Add([PSCustomObject]@{ DeviceName=$device.deviceName; UPN=$device.userPrincipalName; Action=$Action; Status='Success'; Error='' })
        Write-Status "OK: $($device.deviceName)" "Green"
    } catch {
        $failed++
        $results.Add([PSCustomObject]@{ DeviceName=$device.deviceName; UPN=$device.userPrincipalName; Action=$Action; Status='Failed'; Error=$_.Exception.Message })
        Write-Status "FAILED: $($device.deviceName) - $_" "Red"
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity "Executing $Action" -Completed

Write-Section "RESULTS"
Write-Host "  Success: $success" -ForegroundColor Green
Write-Host "  Failed:  $failed" -ForegroundColor $(if($failed -gt 0){'Red'}else{'Green'})

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "BulkActions_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$results | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path" "Green"
