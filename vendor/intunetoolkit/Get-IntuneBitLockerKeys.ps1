#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Retrieves BitLocker recovery keys for Intune-managed Windows devices.
.DESCRIPTION
    Queries Microsoft Graph for BitLocker recovery key metadata (key ID,
    creation date, drive type, device) and optionally exports key values
    with explicit confirmation. Flags devices with no key escrow.
.PARAMETER IncludeKeyValues
    If set, retrieves the actual key strings (requires additional Graph permission).
.PARAMETER ExportPath
    Optional. Export to CSV.

Attribution: IntuneToolKit by AliAlame
  https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit
#>

[CmdletBinding()]
param(
    [Parameter()][switch]$IncludeKeyValues,
    [Parameter()][string]$ExportPath
)

function Write-Status { param([string]$Msg,[string]$Color='Cyan'); Write-Host "  [$((Get-Date).ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color }
function Write-Section { param([string]$Msg); Write-Host "`n$('='*60)" -ForegroundColor DarkGray; Write-Host "  $Msg" -ForegroundColor Yellow; Write-Host "$('='*60)" -ForegroundColor DarkGray }

function Invoke-MgGraph-Safe {
    param([string]$Uri,[string]$Method='GET')
    try {
        $response = Invoke-MgGraphRequest -Uri $Uri -Method $Method -ErrorAction Stop
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
$requiredScopes = @('BitLockerKey.ReadBasic.All')
if ($IncludeKeyValues) { $requiredScopes += 'BitLockerKey.Read.All' }
$context = Get-MgContext
if (-not $context) {
    Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
    $context = Get-MgContext
}
Write-Status "Signed in as: $($context.Account)" "Green"

Write-Section "RETRIEVING BITLOCKER KEY METADATA"
$keys = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?$select=id,createdDateTime,volumeType,deviceId'
Write-Status "$($keys.Count) BitLocker keys found" "Green"

# Gather device info
Write-Status "Loading device list for correlation..." "Cyan"
$devices = Invoke-MgGraph-Safe -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,userPrincipalName,operatingSystem,complianceState'
$deviceMap = @{}
foreach ($d in $devices) { if ($d.azureADDeviceId) { $deviceMap[$d.azureADDeviceId] = $d } }
Write-Status "$($devices.Count) managed devices loaded" "Green"

$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$noKeyDevices = [System.Collections.Generic.List[string]]::new()

Write-Section "BITLOCKER KEY INVENTORY"
Write-Host ""

$i = 0
foreach ($key in ($keys | Sort-Object deviceId, volumeType)) {
    $i++
    if ($i % 50 -eq 0) { Write-Progress -Activity "Processing keys" -Status "$i of $($keys.Count)" -PercentComplete (($i/$keys.Count)*100) }

    $device = $deviceMap[$key.deviceId]
    $deviceName = if ($device) { $device.deviceName } else { "Unknown (AzureAD ID: $($key.deviceId))" }
    $upn = if ($device) { $device.userPrincipalName } else { 'Unknown' }
    $compliance = if ($device) { $device.complianceState } else { 'Unknown' }

    $keyValue = ''
    if ($IncludeKeyValues) {
        try {
            $kv = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys/$($key.id)?`$select=key" -Method GET -ErrorAction Stop
            $keyValue = $kv.key
        } catch { $keyValue = '[ERROR: insufficient permissions or key unavailable]' }
    }

    $report.Add([PSCustomObject]@{
        KeyId        = $key.id
        DeviceName   = $deviceName
        DeviceId     = $key.deviceId
        UPN          = $upn
        VolumeType   = $key.volumeType
        CreatedDate  = $key.createdDateTime
        Compliance   = $compliance
        KeyValue     = $keyValue
    })
}
Write-Progress -Activity "Processing keys" -Completed

# Devices with NO key
$devicesWithKeys = $keys | ForEach-Object { $_.deviceId } | Sort-Object -Unique
$windowsDevices = $devices | Where-Object { $_.operatingSystem -eq 'Windows' }
foreach ($wd in $windowsDevices) {
    if ($wd.azureADDeviceId -notin $devicesWithKeys) {
        $noKeyDevices.Add($wd.deviceName)
    }
}

Write-Section "SUMMARY"
Write-Host "  Total keys found         : $($keys.Count)" -ForegroundColor White
Write-Host "  Unique devices with keys : $(($devicesWithKeys).Count)" -ForegroundColor White
Write-Host "  Windows devices, no key  : $($noKeyDevices.Count)" -ForegroundColor $(if($noKeyDevices.Count -gt 0){'Yellow'}else{'Green'})
if ($noKeyDevices.Count -gt 0 -and $noKeyDevices.Count -le 20) {
    Write-Host ""
    Write-Host "  Devices missing BitLocker escrow:" -ForegroundColor Yellow
    foreach ($n in $noKeyDevices) { Write-Host "    $n" -ForegroundColor DarkYellow }
}

# Add no-key devices to report as gap entries
foreach ($n in $noKeyDevices) {
    $d = $devices | Where-Object { $_.deviceName -eq $n } | Select-Object -First 1
    $report.Add([PSCustomObject]@{
        KeyId=''; DeviceName=$n; DeviceId=if($d){$d.azureADDeviceId}else{''};
        UPN=if($d){$d.userPrincipalName}else{''}; VolumeType=''; CreatedDate='';
        Compliance=if($d){$d.complianceState}else{''}; KeyValue='[NO KEY ESCROWED]'
    })
}

$path = if ($ExportPath) { $ExportPath } else { Join-Path $env:TEMP "BitLockerKeys_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$report | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
Write-Status "Exported to: $path ($($report.Count) rows)" "Green"
Write-Host ""
