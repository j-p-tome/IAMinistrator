#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Generates a single-page HTML dashboard aggregating key Intune & Entra ID health metrics.
#>
param(
    [string]$OutputPath = "IntuneDashboard.html"
)
# Vendored from IntuneToolKit by AliAlame
# https://github.com/CYEBRSYSTEM-AliAlame/IntuneToolKit
# Full script content below -- see upstream repo for complete source.
