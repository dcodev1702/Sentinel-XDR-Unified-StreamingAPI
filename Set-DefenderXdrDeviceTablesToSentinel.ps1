<#
.SYNOPSIS
Configures Microsoft Defender XDR Streaming API exports to Microsoft Sentinel.

.DESCRIPTION
Creates, updates, or deletes an independent Microsoft Defender XDR Streaming API entry that streams selected advanced
hunting categories into a Microsoft Sentinel Log Analytics workspace. Use the required -Cloud parameter to choose Commercial or GCC Defender
endpoints. The script uses Az PowerShell for Azure context, Azure Resource Manager access, and token acquisition, then
calls the selected Defender XDR Streaming API endpoint for the export setting.

The script manages Defender for Endpoint device categories and API-writable Cloud Apps and Identity categories. It does
not force portal-only Microsoft Defender for Office categories on because the Defender API rejects those category names
through this workflow.

.PARAMETER SubscriptionId
Azure subscription that contains the Microsoft Sentinel Log Analytics workspace.

.PARAMETER ResourceGroupName
Resource group that contains the Log Analytics workspace.

.PARAMETER WorkspaceName
Name of the Log Analytics workspace.

.PARAMETER Cloud
Required Defender XDR cloud endpoint. Commercial targets api.security.microsoft.com. GCC targets api-gcc.securitycenter.microsoft.us.
GCC High and DoD are not covered by this script.

.PARAMETER ExportSettingId
Optional existing Defender XDR Streaming API entry to select non-interactively. The entry must be mapped to the target workspace.

.PARAMETER NewExportSettingId
Optional proposed independent entry name. Defaults to SentinelExportSettings-{WorkspaceName}-Managed.

.PARAMETER TenantId
Optional tenant guardrail. If omitted, the active Az tenant is used.

.PARAMETER EnableMDE
Enables Defender for Endpoint device advanced hunting table exports.

.PARAMETER EnableMDI
Enables API-writable Cloud Apps and Identity categories.

.PARAMETER EnableMDO
Reports the request but does not force MDO email or URL categories on because this Defender API path rejects those categories.

.PARAMETER DisableMDE
Disables Defender for Endpoint device advanced hunting table exports.

.PARAMETER DisableMDI
Disables API-writable Cloud Apps and Identity categories and clears related unsupported portal-only aliases where possible.

.PARAMETER DisableMDO
Clears known portal-only MDO email and URL categories by posting an API-safe replacement setting.

.PARAMETER DeleteExportSetting
Deletes the selected workspace-mapped Defender XDR Streaming API entry. Cannot be combined with enable or disable flags.

.PARAMETER DisableDeviceTables
Compatibility alias for DisableMDE, DisableMDI, and DisableMDO.

.PARAMETER SkipSecurityAdministratorCheck
Skips the Microsoft Graph role membership check. Use only when Security Administrator or Global Administrator has been verified manually.

.PARAMETER RegisterMissingProvider
Registers missing Azure resource providers before continuing.

.EXAMPLE
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
    -Cloud Commercial `
    -SubscriptionId "00000000-0000-0000-0000-000000000000" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "law-sentinel" `
    -EnableMDE `
    -EnableMDI `
    -WhatIf

.EXAMPLE
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
    -Cloud GCC `
    -SubscriptionId "00000000-0000-0000-0000-000000000000" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "law-sentinel" `
    -EnableMDE `
    -WhatIf

.EXAMPLE
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
    -Cloud Commercial `
    -SubscriptionId "00000000-0000-0000-0000-000000000000" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName "law-sentinel" `
    -DeleteExportSetting `
    -Confirm:$false

.NOTES
Requires Az PowerShell, an interactive user sign-in, Defender XDR eligibility, Entra Security Administrator or Global
Administrator, and Azure RBAC over the target workspace.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [Parameter(Mandatory)]
    [ValidateSet("Commercial", "GCC")]
    [string]$Cloud,

    [Parameter()]
    [string]$ExportSettingId,

    [Parameter()]
    [string]$NewExportSettingId,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$EnableMDE,

    [Parameter()]
    [switch]$EnableMDI,

    [Parameter()]
    [switch]$EnableMDO,

    [Parameter()]
    [switch]$DisableMDE,

    [Parameter()]
    [switch]$DisableMDI,

    [Parameter()]
    [switch]$DisableMDO,

    [Parameter()]
    [switch]$DeleteExportSetting,

    [Parameter()]
    [switch]$DisableDeviceTables,

    [Parameter()]
    [switch]$SkipSecurityAdministratorCheck,

    [Parameter()]
    [switch]$RegisterMissingProvider
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

$DefenderApiBaseUri = if ($Cloud -eq "GCC") { "https://api-gcc.securitycenter.microsoft.us" } else { "https://api.security.microsoft.com" }
$DefenderTokenResource = if ($Cloud -eq "GCC") { "https://api-gcc.securitycenter.microsoft.us" } else { "https://api.securitycenter.microsoft.com" }
$GraphResource = "https://graph.microsoft.com"
$SentinelDataConnectorApiVersion = "2023-06-01-preview"

$DeviceTables = @(
    "DeviceInfo",
    "DeviceNetworkInfo",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "DeviceImageLoadEvents",
    "DeviceEvents",
    "DeviceFileCertificateInfo"
)

$DeviceCategories = $DeviceTables | ForEach-Object { "AdvancedHunting-$PSItem" }
$AdditionalApiWritableCategories = @(
    "CloudAppEvents",
    "IdentityDirectoryEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents"
)
$UnsupportedWriteCategories = @(
    "AdvancedHunting-CloudAppEvents",
    "AdvancedHunting-EmailAttachmentInfo",
    "AdvancedHunting-EmailEvents",
    "AdvancedHunting-EmailPostDeliveryEvents",
    "AdvancedHunting-EmailUrlInfo",
    "AdvancedHunting-IdentityDirectoryEvents",
    "AdvancedHunting-IdentityLogonEvents",
    "AdvancedHunting-IdentityQueryEvents",
    "AdvancedHunting-SentinelBehaviorInfo",
    "AdvancedHunting-SentinelBehaviorEntities",
    "AdvancedHunting-UrlClickEvents"
)

$PortalOnlyCategoriesClearedOnDisable = @(
    "AdvancedHunting-CloudAppEvents",
    "AdvancedHunting-EmailAttachmentInfo",
    "AdvancedHunting-EmailEvents",
    "AdvancedHunting-EmailPostDeliveryEvents",
    "AdvancedHunting-EmailUrlInfo",
    "AdvancedHunting-IdentityDirectoryEvents",
    "AdvancedHunting-IdentityLogonEvents",
    "AdvancedHunting-IdentityQueryEvents",
    "AdvancedHunting-UrlClickEvents"
)

$CategoryWriteAliasMap = @{
    "AdvancedHunting-CloudAppEvents" = "CloudAppEvents"
    "AdvancedHunting-IdentityDirectoryEvents" = "IdentityDirectoryEvents"
    "AdvancedHunting-IdentityLogonEvents" = "IdentityLogonEvents"
    "AdvancedHunting-IdentityQueryEvents" = "IdentityQueryEvents"
}

$MdiApiWritableCategories = @(
    "CloudAppEvents",
    "IdentityDirectoryEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents"
)

$MdoPortalOnlyCategories = @(
    "AdvancedHunting-EmailAttachmentInfo",
    "AdvancedHunting-EmailEvents",
    "AdvancedHunting-EmailPostDeliveryEvents",
    "AdvancedHunting-EmailUrlInfo",
    "AdvancedHunting-UrlClickEvents"
)

function Get-PlainAccessToken {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceUrl
    )

    $tokenResult = Get-AzAccessToken -ResourceUrl $ResourceUrl
    if ($tokenResult.Token -is [securestring]) {
        return [System.Net.NetworkCredential]::new("", $tokenResult.Token).Password
    }

    return [string]$tokenResult.Token
}

function Invoke-JsonRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("GET", "POST", "DELETE")]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter()]
        [object]$Body
    )

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $request = $null
    $response = $null

    try {
        $httpMethod = if ($Method -eq "GET") { [System.Net.Http.HttpMethod]::Get } elseif ($Method -eq "POST") { [System.Net.Http.HttpMethod]::Post } else { [System.Net.Http.HttpMethod]::Delete }
        $request = [System.Net.Http.HttpRequestMessage]::new($httpMethod, $Uri)

        foreach ($headerName in $Headers.Keys) {
            [void]$request.Headers.TryAddWithoutValidation([string]$headerName, [string]$Headers[$headerName])
        }

        if ($null -ne $Body) {
            $jsonBody = $Body | ConvertTo-Json -Depth 40
            $request.Content = [System.Net.Http.StringContent]::new($jsonBody, [System.Text.Encoding]::UTF8, "application/json")
        }

        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $responseBody = if ($response.Content) { $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() } else { $null }

        if (-not $response.IsSuccessStatusCode) {
            if ([string]::IsNullOrWhiteSpace($responseBody)) {
                $responseBody = $response.ReasonPhrase
            }

            throw ("{0} {1} failed with HTTP {2}: {3}" -f $Method, $Uri, [int]$response.StatusCode, $responseBody)
        }

        if ([string]::IsNullOrWhiteSpace($responseBody)) {
            return $null
        }

        return $responseBody | ConvertFrom-Json
    }
    finally {
        if ($response) {
            $response.Dispose()
        }

        if ($request) {
            $request.Dispose()
        }

        $client.Dispose()
    }
}

function Test-ActionPattern {
    param(
        [Parameter()]
        [string[]]$Patterns,

        [Parameter(Mandatory)]
        [string]$Action
    )

    foreach ($pattern in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            continue
        }

        if ($pattern -eq "*") {
            return $true
        }

        $regex = "^" + [regex]::Escape($pattern).Replace("\*", ".*") + "$"
        if ($Action -match $regex) {
            return $true
        }
    }

    return $false
}

function Test-EffectiveActionAllowed {
    param(
        [Parameter(Mandatory)]
        [object[]]$Permissions,

        [Parameter(Mandatory)]
        [string]$Action
    )

    foreach ($permission in @($Permissions)) {
        $actions = @($permission.actions)
        $notActions = @($permission.notActions)

        if ((Test-ActionPattern -Patterns $actions -Action $Action) -and -not (Test-ActionPattern -Patterns $notActions -Action $Action)) {
            return $true
        }
    }

    return $false
}

function Assert-ProviderRegistered {
    param(
        [Parameter(Mandatory)]
        [string]$ProviderNamespace
    )

    $provider = Get-AzResourceProvider -ProviderNamespace $ProviderNamespace
    $registrationState = ($provider | Select-Object -First 1).RegistrationState

    if ($registrationState -eq "Registered") {
        return
    }

    if ($RegisterMissingProvider) {
        Write-Host "Registering resource provider $ProviderNamespace..."
        Register-AzResourceProvider -ProviderNamespace $ProviderNamespace | Out-Null
        do {
            Start-Sleep -Seconds 5
            $provider = Get-AzResourceProvider -ProviderNamespace $ProviderNamespace
            $registrationState = ($provider | Select-Object -First 1).RegistrationState
        } until ($registrationState -eq "Registered")

        return
    }

    throw "Resource provider $ProviderNamespace is $registrationState, not Registered. Rerun with -RegisterMissingProvider or register it before continuing."
}

function Assert-SecurityAdministratorRole {
    if ($SkipSecurityAdministratorCheck) {
        Write-Warning "Skipping Microsoft Entra Security Administrator role check."
        return
    }

    $graphToken = Get-PlainAccessToken -ResourceUrl $GraphResource
    $headers = @{ Authorization = "Bearer $graphToken" }
    $rolesUri = "$GraphResource/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?`$select=displayName"

    try {
        $roles = Invoke-JsonRequest -Method GET -Uri $rolesUri -Headers $headers
    }
    catch {
        throw "Could not verify Microsoft Entra roles through Microsoft Graph. Rerun with -SkipSecurityAdministratorCheck only if you have manually confirmed Security Administrator or higher. Details: $PSItem"
    }

    $roleNames = @($roles.value | ForEach-Object { $_.displayName })
    $acceptedRoles = @("Security Administrator", "Global Administrator")

    foreach ($acceptedRole in $acceptedRoles) {
        if ($roleNames -contains $acceptedRole) {
            return
        }
    }

    throw "Current user does not appear to have Security Administrator or Global Administrator in Microsoft Entra ID. Found roles: $($roleNames -join ', ')"
}

function Assert-WorkspacePermissions {
    param(
        [Parameter(Mandatory)]
        [string]$WorkspaceResourceId
    )

    $permissionsPath = "$WorkspaceResourceId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $permissions = (Invoke-AzRestMethod -Method GET -Path $permissionsPath).Content | ConvertFrom-Json
    $requiredActions = @(
        "Microsoft.OperationalInsights/workspaces/read",
        "Microsoft.SecurityInsights/dataConnectors/read",
        "Microsoft.SecurityInsights/dataConnectors/write"
    )

    foreach ($requiredAction in $requiredActions) {
        if (-not (Test-EffectiveActionAllowed -Permissions @($permissions.value) -Action $requiredAction)) {
            throw "Current Azure identity does not have required workspace action: $requiredAction"
        }
    }
}

function Get-LogCategoryState {
    param(
        [Parameter()]
        [object[]]$Logs,

        [Parameter(Mandatory)]
        [string]$Category
    )

    $entry = @($Logs | Where-Object { $_.category -eq $Category } | Select-Object -First 1)
    if ($entry.Count -eq 0) {
        return $false
    }

    return [bool]$entry[0].enabled
}

function Set-LogCategoryState {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$Logs,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [bool]$Enabled
    )

    $entry = $Logs | Where-Object { $_.category -eq $Category } | Select-Object -First 1
    if ($entry) {
        $entry.enabled = $Enabled
        return
    }

    [void]$Logs.Add([pscustomobject]@{
        category = $Category
        enabled = $Enabled
    })
}

function Get-UnsupportedCategoriesFromErrorMessage {
    param(
        [Parameter(Mandatory)]
        [string]$ErrorMessage
    )

    $singleCategoryMatches = [regex]::Matches($ErrorMessage, "Category\s+'([^']+)'\s+is\s+not supported\.", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($singleCategoryMatches.Count -gt 0) {
        return @($singleCategoryMatches | ForEach-Object { $PSItem.Groups[1].Value.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($PSItem) } | Select-Object -Unique)
    }

    $match = [regex]::Match($ErrorMessage, "Categories?\s+(.+?)\s+(?:are|is)\s+not supported\.", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) {
        return @()
    }

    return @($match.Groups[1].Value -split "," | ForEach-Object { $PSItem.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($PSItem) })
}

function Remove-LogCategories {
    param(
        [Parameter(Mandatory)]
        [object]$Body,

        [Parameter(Mandatory)]
        [string[]]$Categories
    )

    $categorySet = @{}
    foreach ($category in @($Categories)) {
        if (-not [string]::IsNullOrWhiteSpace($category)) {
            $categorySet[$category] = $true
        }
    }

    $logs = [System.Collections.ArrayList]::new()
    $removedCategories = @()
    $currentLogs = if ($Body -is [System.Collections.IDictionary]) { @($Body["logs"]) } else { @($Body.logs) }
    foreach ($log in $currentLogs) {
        $category = [string]$log.category
        if ($categorySet.ContainsKey($category)) {
            $removedCategories += $category
            continue
        }

        [void]$logs.Add($log)
    }

    if ($Body -is [System.Collections.IDictionary]) {
        $Body["logs"] = @($logs)
    }
    else {
        $Body.logs = @($logs)
    }

    return @($removedCategories | Select-Object -Unique)
}

function Get-SettingWorkspaceResourceId {
    param(
        [Parameter(Mandatory)]
        [object]$Setting
    )

    if ($Setting.workspaceProperties -and ($Setting.workspaceProperties.PSObject.Properties.Name -contains "workspaceResourceId")) {
        return [string]$Setting.workspaceProperties.workspaceResourceId
    }

    return $null
}

function Test-SettingTargetsWorkspace {
    param(
        [Parameter(Mandatory)]
        [object]$Setting,

        [Parameter(Mandatory)]
        [string]$WorkspaceResourceId
    )

    $settingWorkspaceResourceId = Get-SettingWorkspaceResourceId -Setting $Setting
    return (-not [string]::IsNullOrWhiteSpace($settingWorkspaceResourceId)) -and ($settingWorkspaceResourceId.ToLowerInvariant() -eq $WorkspaceResourceId.ToLowerInvariant())
}

function Write-ExportSettingInventory {
    param(
        [Parameter(Mandatory)]
        [object[]]$Settings,

        [Parameter(Mandatory)]
        [string]$WorkspaceResourceId,

        [Parameter(Mandatory)]
        [string]$ProposedExportSettingId
    )

    Write-Host ""
    Write-Host "Current Defender XDR Streaming API entries ($($Settings.Count)/5):"
    if ($Settings.Count -eq 0) {
        Write-Host "  <none>"
    }

    foreach ($setting in @($Settings)) {
        $settingWorkspaceResourceId = Get-SettingWorkspaceResourceId -Setting $setting
        $workspaceText = if ([string]::IsNullOrWhiteSpace($settingWorkspaceResourceId)) { "<not a Log Analytics workspace target>" } else { $settingWorkspaceResourceId }
        $isWorkspaceTarget = Test-SettingTargetsWorkspace -Setting $setting -WorkspaceResourceId $WorkspaceResourceId
        $prefix = if ($setting.id -eq $ProposedExportSettingId) { "  *** " } else { "  - " }
        $suffix = if ($setting.id -eq $ProposedExportSettingId) { " ***" } else { "" }
        $color = if ($isWorkspaceTarget) { "Green" } else { "DarkGray" }
        Write-Host "$prefix$($setting.id)$suffix -> $workspaceText" -ForegroundColor $color
    }

    if (-not (@($Settings | Where-Object { $_.id -eq $ProposedExportSettingId }).Count -gt 0)) {
        Write-Host "  *** NEW: $ProposedExportSettingId -> $WorkspaceResourceId ***" -ForegroundColor Cyan
    }
}

function Select-WorkspaceExportSetting {
    param(
        [Parameter(Mandatory)]
        [object[]]$Settings,

        [Parameter(Mandatory)]
        [string]$WorkspaceResourceId,

        [Parameter(Mandatory)]
        [string]$ProposedExportSettingId,

        [Parameter()]
        [string]$RequestedExportSettingId
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedExportSettingId)) {
        $requestedSetting = $Settings | Where-Object { $_.id -eq $RequestedExportSettingId } | Select-Object -First 1
        if ($requestedSetting -and -not (Test-SettingTargetsWorkspace -Setting $requestedSetting -WorkspaceResourceId $WorkspaceResourceId)) {
            throw "Streaming API entry $RequestedExportSettingId exists, but it is not mapped to $WorkspaceResourceId. Choose or create an entry mapped to the target Log Analytics workspace."
        }

        return [pscustomobject]@{
            Id = $RequestedExportSettingId
            Setting = $requestedSetting
            CreateNew = -not $requestedSetting
        }
    }

    $workspaceSettings = @($Settings | Where-Object { Test-SettingTargetsWorkspace -Setting $PSItem -WorkspaceResourceId $WorkspaceResourceId })
    Write-Host ""
    Write-Host "Selectable entries mapped to the target Log Analytics workspace:"
    for ($index = 0; $index -lt $workspaceSettings.Count; $index++) {
        Write-Host "  [$($index + 1)] $($workspaceSettings[$index].id)"
    }

    $proposedExistingSetting = $workspaceSettings | Where-Object { $_.id -eq $ProposedExportSettingId } | Select-Object -First 1
    $newOptionAvailable = -not $proposedExistingSetting
    if ($newOptionAvailable) {
        Write-Host "  [N] Create *** $ProposedExportSettingId ***" -ForegroundColor Cyan
    }

    if ($workspaceSettings.Count -eq 0 -and -not $newOptionAvailable) {
        throw "No selectable Streaming API entries are mapped to $WorkspaceResourceId."
    }

    $defaultSelection = if ($proposedExistingSetting) { [string]([array]::IndexOf($workspaceSettings, $proposedExistingSetting) + 1) } elseif ($newOptionAvailable) { "N" } else { "1" }
    $selection = Read-Host "Select an entry number, N for the new entry, or Q to quit [default: $defaultSelection]"
    if ([string]::IsNullOrWhiteSpace($selection)) {
        $selection = $defaultSelection
    }

    if ($selection -match '^[Qq]$') {
        throw "No Streaming API entry selected."
    }

    if ($selection -match '^[Nn]$') {
        if (-not $newOptionAvailable) {
            return [pscustomobject]@{ Id = $ProposedExportSettingId; Setting = $proposedExistingSetting; CreateNew = $false }
        }

        return [pscustomobject]@{ Id = $ProposedExportSettingId; Setting = $null; CreateNew = $true }
    }

    $selectedIndex = 0
    if (-not [int]::TryParse($selection, [ref]$selectedIndex) -or $selectedIndex -lt 1 -or $selectedIndex -gt $workspaceSettings.Count) {
        throw "Invalid Streaming API selection: $selection"
    }

    $selectedSetting = $workspaceSettings[$selectedIndex - 1]
    return [pscustomobject]@{ Id = $selectedSetting.id; Setting = $selectedSetting; CreateNew = $false }
}

function Assert-GroupSwitchesValid {
    param(
        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [bool]$Enable,

        [Parameter(Mandatory)]
        [bool]$Disable
    )

    if ($Enable -and $Disable) {
        throw "Choose either -Enable$GroupName or -Disable$GroupName, not both."
    }
}

function Set-CategoryStates {
    param(
        [Parameter(Mandatory)]
        [hashtable]$CategoryStates,

        [Parameter(Mandatory)]
        [string[]]$Categories,

        [Parameter(Mandatory)]
        [bool]$Enabled
    )

    foreach ($category in @($Categories)) {
        $CategoryStates[$category] = $Enabled
    }
}

function Write-RequestedChangeSummary {
    param(
        [Parameter()]
        [string[]]$EnabledGroups,

        [Parameter()]
        [string[]]$DisabledGroups,

        [Parameter()]
        [string[]]$SkippedGroups,

        [Parameter(Mandatory)]
        [hashtable]$CategoryStates,

        [Parameter()]
        [string[]]$PortalOnlyCategoriesClearedOnDisable
    )

    Write-Host ""
    Write-Host "Requested table group changes:"
    if ($EnabledGroups.Count -eq 0 -and $DisabledGroups.Count -eq 0 -and $SkippedGroups.Count -eq 0) {
        Write-Host "  No MDE, MDI, or MDO enable/disable flags were provided. No tables will be enabled automatically."
        return
    }

    foreach ($group in @($EnabledGroups)) {
        Write-Host "  Enable $group" -ForegroundColor Green
    }

    foreach ($group in @($DisabledGroups)) {
        Write-Host "  Disable $group" -ForegroundColor Yellow
    }

    foreach ($group in @($SkippedGroups)) {
        Write-Warning "$group was requested, but those categories are not writable through this Defender API path and will not be forced on."
    }

    if ($CategoryStates.Count -gt 0) {
        Write-Host "API-writable category changes:"
        foreach ($category in ($CategoryStates.Keys | Sort-Object)) {
            Write-Host "  - $category = $($CategoryStates[$category])"
        }
    }

    if ($DisabledGroups -contains "MDO") {
        Write-Host "Portal-only MDO categories expected to be cleared on disable:"
        foreach ($category in @($PortalOnlyCategoriesClearedOnDisable | Where-Object { $MdoPortalOnlyCategories -contains $PSItem })) {
            Write-Host "  - $category"
        }
    }
}

function Write-CategoryChangeSummary {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Enable", "Disable")]
        [string]$Verb,

        [Parameter(Mandatory)]
        [string[]]$DeviceTables,

        [Parameter(Mandatory)]
        [string[]]$AdditionalApiWritableCategories,

        [Parameter(Mandatory)]
        [string[]]$PortalOnlyCategoriesClearedOnDisable,

        [Parameter(Mandatory)]
        [bool]$Preview
    )

    $action = if ($Preview) { "Would $($Verb.ToLowerInvariant())" } else { $Verb }
    Write-Host ""
    Write-Host "$action these script-managed Defender XDR Streaming API categories:"
    Write-Host "Device tables:"
    foreach ($deviceTable in $DeviceTables) {
        Write-Host "  - $deviceTable"
    }

    Write-Host "Additional API-writable categories:"
    foreach ($category in $AdditionalApiWritableCategories) {
        Write-Host "  - $category"
    }

    if ($Verb -eq "Disable" -and $PortalOnlyCategoriesClearedOnDisable.Count -gt 0) {
        Write-Host "Portal-only categories expected to be cleared on disable:"
        foreach ($category in $PortalOnlyCategoriesClearedOnDisable) {
            Write-Host "  - $category"
        }
    }
}

function New-ExportSettingBody {
    param(
        [Parameter(Mandatory)]
        [object]$Setting,

        [Parameter(Mandatory)]
        [hashtable]$CategoryStates,

        [Parameter()]
        [string[]]$ClearUnsupportedCategories = @()
    )

    $clearUnsupportedCategorySet = @{}
    foreach ($category in @($ClearUnsupportedCategories)) {
        if (-not [string]::IsNullOrWhiteSpace($category)) {
            $clearUnsupportedCategorySet[$category] = $true
        }
    }

    $logs = [System.Collections.ArrayList]::new()
    foreach ($log in @($Setting.logs)) {
        if ($UnsupportedWriteCategories -contains $log.category) {
            continue
        }

        [void]$logs.Add([pscustomobject]@{
            category = [string]$log.category
            enabled = [bool]$log.enabled
        })
    }

    foreach ($unsupportedCategory in $UnsupportedWriteCategories) {
        if ($clearUnsupportedCategorySet.ContainsKey($unsupportedCategory)) {
            continue
        }

        if ($CategoryWriteAliasMap.ContainsKey($unsupportedCategory)) {
            $aliasCategory = $CategoryWriteAliasMap[$unsupportedCategory]
            if (-not $CategoryStates.ContainsKey($aliasCategory) -and (Get-LogCategoryState -Logs @($Setting.logs) -Category $unsupportedCategory)) {
                Set-LogCategoryState -Logs $logs -Category $aliasCategory -Enabled $true
            }
        }
    }

    foreach ($category in $CategoryStates.Keys) {
        Set-LogCategoryState -Logs $logs -Category $category -Enabled ([bool]$CategoryStates[$category])
    }

    return [ordered]@{
        id = $Setting.id
        designatedTenantId = $Setting.designatedTenantId
        eventHubProperties = $Setting.eventHubProperties
        storageAccountProperties = $Setting.storageAccountProperties
        workspaceProperties = $Setting.workspaceProperties
        logs = @($logs)
    }
}

function New-WorkspaceExportSetting {
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [string]$WorkspaceResourceId,

        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$WorkspaceName
    )

    return [pscustomobject]@{
        id = $Id
        designatedTenantId = $null
        eventHubProperties = $null
        storageAccountProperties = $null
        workspaceProperties = [pscustomobject]@{
            workspaceResourceId = $WorkspaceResourceId
            subscriptionId = $SubscriptionId
            resourceGroup = $ResourceGroupName
            name = $WorkspaceName
        }
        logs = @()
    }
}

if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
    throw "Az.Accounts is required. Install/import Az and run Connect-AzAccount first."
}

$context = Get-AzContext
if (-not $context) {
    throw "No Azure context found. Run Connect-AzAccount first."
}

Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
$context = Get-AzContext

if (-not $TenantId) {
    $TenantId = $context.Tenant.Id
}

if ($context.Tenant.Id -ne $TenantId) {
    throw "Active Azure context tenant $($context.Tenant.Id) does not match requested tenant $TenantId. Connect to the target tenant first."
}

Assert-ProviderRegistered -ProviderNamespace "Microsoft.Insights"
Assert-ProviderRegistered -ProviderNamespace "Microsoft.OperationalInsights"
Assert-ProviderRegistered -ProviderNamespace "Microsoft.SecurityInsights"
Assert-SecurityAdministratorRole

$workspace = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.OperationalInsights/workspaces" -Name $WorkspaceName -ExpandProperties
if (-not $workspace) {
    throw "Log Analytics workspace $WorkspaceName was not found in resource group $ResourceGroupName."
}

$workspaceResourceId = $workspace.ResourceId
Assert-WorkspacePermissions -WorkspaceResourceId $workspaceResourceId

$connectorListPath = "$workspaceResourceId/providers/Microsoft.SecurityInsights/dataConnectors?api-version=$SentinelDataConnectorApiVersion"
$connectors = (Invoke-AzRestMethod -Method GET -Path $connectorListPath).Content | ConvertFrom-Json
$mtpConnector = $connectors.value | Where-Object { $_.kind -eq "MicrosoftThreatProtection" } | Select-Object -First 1
if (-not $mtpConnector) {
    Write-Warning "No MicrosoftThreatProtection Sentinel connector was found through ARM. The Defender DataExportSettings call can still create the workspace export setting if Defender XDR is licensed and available."
}

$defenderToken = Get-PlainAccessToken -ResourceUrl $DefenderTokenResource
$defenderHeaders = @{ Authorization = "Bearer $defenderToken" }
$settingsUri = "$DefenderApiBaseUri/api/dataExportSettings"
$settings = Invoke-JsonRequest -Method GET -Uri $settingsUri -Headers $defenderHeaders
$allSettings = @($settings.value)

$proposedExportSettingId = if ([string]::IsNullOrWhiteSpace($NewExportSettingId)) { "SentinelExportSettings-$WorkspaceName-Managed" } else { $NewExportSettingId }

$proposedExistingSetting = $allSettings | Where-Object { $_.id -eq $proposedExportSettingId } | Select-Object -First 1
if ($proposedExistingSetting -and -not (Test-SettingTargetsWorkspace -Setting $proposedExistingSetting -WorkspaceResourceId $workspaceResourceId)) {
    throw "The proposed Streaming API entry name $proposedExportSettingId already exists, but it is not mapped to $workspaceResourceId. Use -NewExportSettingId with a unique name."
}

Write-ExportSettingInventory -Settings $allSettings -WorkspaceResourceId $workspaceResourceId -ProposedExportSettingId $proposedExportSettingId

if (-not $proposedExistingSetting -and [string]::IsNullOrWhiteSpace($ExportSettingId) -and $allSettings.Count -ge 5) {
    throw "Defender XDR already has 5 Streaming API entries, which is the tenant limit. Cannot create the independent entry $proposedExportSettingId until an existing entry is deleted."
}

$enableMdeRequested = [bool]$EnableMDE
$enableMdiRequested = [bool]$EnableMDI
$enableMdoRequested = [bool]$EnableMDO
$disableMdeRequested = [bool]$DisableMDE -or [bool]$DisableDeviceTables
$disableMdiRequested = [bool]$DisableMDI -or [bool]$DisableDeviceTables
$disableMdoRequested = [bool]$DisableMDO -or [bool]$DisableDeviceTables

if ($DisableDeviceTables) {
    Write-Warning "-DisableDeviceTables is retained as a compatibility alias for -DisableMDE -DisableMDI -DisableMDO. Prefer the explicit group flags."
}

Assert-GroupSwitchesValid -GroupName "MDE" -Enable $enableMdeRequested -Disable $disableMdeRequested
Assert-GroupSwitchesValid -GroupName "MDI" -Enable $enableMdiRequested -Disable $disableMdiRequested
Assert-GroupSwitchesValid -GroupName "MDO" -Enable $enableMdoRequested -Disable $disableMdoRequested

$hasGroupAction = $enableMdeRequested -or $enableMdiRequested -or $enableMdoRequested -or $disableMdeRequested -or $disableMdiRequested -or $disableMdoRequested
if ($DeleteExportSetting -and $hasGroupAction) {
    throw "Use -DeleteExportSetting by itself. Enable and disable flags cannot be combined with deletion."
}

$categoryStates = @{}
$verifyCategoryStates = @{}
$clearUnsupportedCategories = @()
$enabledGroups = @()
$disabledGroups = @()
$skippedGroups = @()

if ($enableMdeRequested) {
    $enabledGroups += "MDE"
    Set-CategoryStates -CategoryStates $categoryStates -Categories $DeviceCategories -Enabled $true
    Set-CategoryStates -CategoryStates $verifyCategoryStates -Categories $DeviceCategories -Enabled $true
}
elseif ($disableMdeRequested) {
    $disabledGroups += "MDE"
    Set-CategoryStates -CategoryStates $categoryStates -Categories $DeviceCategories -Enabled $false
    Set-CategoryStates -CategoryStates $verifyCategoryStates -Categories $DeviceCategories -Enabled $false
}

if ($enableMdiRequested) {
    $enabledGroups += "MDI"
    Set-CategoryStates -CategoryStates $categoryStates -Categories $MdiApiWritableCategories -Enabled $true
    Set-CategoryStates -CategoryStates $verifyCategoryStates -Categories $MdiApiWritableCategories -Enabled $true
}
elseif ($disableMdiRequested) {
    $disabledGroups += "MDI"
    Set-CategoryStates -CategoryStates $categoryStates -Categories $MdiApiWritableCategories -Enabled $false
    Set-CategoryStates -CategoryStates $verifyCategoryStates -Categories $MdiApiWritableCategories -Enabled $false
    $clearUnsupportedCategories += $CategoryWriteAliasMap.Keys
    Set-CategoryStates -CategoryStates $verifyCategoryStates -Categories @($CategoryWriteAliasMap.Keys) -Enabled $false
}

if ($enableMdoRequested) {
    $skippedGroups += "MDO"
}
elseif ($disableMdoRequested) {
    $disabledGroups += "MDO"
    $clearUnsupportedCategories += $MdoPortalOnlyCategories
    Set-CategoryStates -CategoryStates $verifyCategoryStates -Categories $MdoPortalOnlyCategories -Enabled $false
}

$clearUnsupportedCategories = @($clearUnsupportedCategories | Select-Object -Unique)

if ($DeleteExportSetting) {
    Write-Host ""
    Write-Host "Requested operation: delete the selected Streaming API entry." -ForegroundColor Yellow
}
else {
    Write-RequestedChangeSummary -EnabledGroups $enabledGroups -DisabledGroups $disabledGroups -SkippedGroups $skippedGroups -CategoryStates $categoryStates -PortalOnlyCategoriesClearedOnDisable $clearUnsupportedCategories
}

$selection = Select-WorkspaceExportSetting -Settings $allSettings -WorkspaceResourceId $workspaceResourceId -ProposedExportSettingId $proposedExportSettingId -RequestedExportSettingId $ExportSettingId
if ($selection.CreateNew -and $allSettings.Count -ge 5) {
    throw "Defender XDR already has 5 Streaming API entries, which is the tenant limit. Cannot create $($selection.Id) until an existing entry is deleted."
}

if ($DeleteExportSetting) {
    if ($selection.CreateNew) {
        throw "Cannot delete $($selection.Id) because it does not exist."
    }

    if ($PSCmdlet.ShouldProcess($selection.Id, "Delete Defender XDR Streaming API entry mapped to $workspaceResourceId")) {
        $deleteUri = "$settingsUri/$([System.Uri]::EscapeDataString($selection.Id))"
        Invoke-JsonRequest -Method DELETE -Uri $deleteUri -Headers $defenderHeaders | Out-Null
        [pscustomobject]@{
            ExportSettingId = $selection.Id
            WorkspaceResourceId = $workspaceResourceId
            Deleted = $true
        }
    }

    return
}

$setting = if ($selection.CreateNew) {
    New-WorkspaceExportSetting -Id $selection.Id -WorkspaceResourceId $workspaceResourceId -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
}
else {
    $selection.Setting
}

if (-not (Test-SettingTargetsWorkspace -Setting $setting -WorkspaceResourceId $workspaceResourceId)) {
    throw "Selected Streaming API entry $($selection.Id) is not mapped to $workspaceResourceId."
}

if (-not $selection.CreateNew -and -not $hasGroupAction) {
    Write-Host "No table group flags were provided and the selected Streaming API entry already exists. No changes were posted."
    [pscustomobject]@{
        ExportSettingId = $selection.Id
        WorkspaceResourceId = $workspaceResourceId
        Changed = $false
    }
    return
}

$body = New-ExportSettingBody -Setting $setting -CategoryStates $categoryStates -ClearUnsupportedCategories $clearUnsupportedCategories
$operationVerb = if ($selection.CreateNew) { "Create" } else { "Update" }

if ($PSCmdlet.ShouldProcess($setting.id, "$operationVerb Defender XDR Streaming API entry for $workspaceResourceId")) {
    $updatedSetting = $null
    $maxPostAttempts = 10
    for ($postAttempt = 1; $postAttempt -le $maxPostAttempts; $postAttempt++) {
        try {
            $updatedSetting = Invoke-JsonRequest -Method POST -Uri $settingsUri -Headers $defenderHeaders -Body $body
            break
        }
        catch {
            $unsupportedCategories = @(Get-UnsupportedCategoriesFromErrorMessage -ErrorMessage $PSItem.Exception.Message)
            if ($unsupportedCategories.Count -eq 0) {
                throw
            }

            $removedCategories = @(Remove-LogCategories -Body $body -Categories $unsupportedCategories)
            if ($removedCategories.Count -eq 0) {
                throw
            }

            foreach ($removedCategory in $removedCategories) {
                if ($verifyCategoryStates.ContainsKey($removedCategory)) {
                    $verifyCategoryStates.Remove($removedCategory)
                }
            }

            if ($postAttempt -eq $maxPostAttempts) {
                throw "Defender API continued to reject unsupported categories after $maxPostAttempts attempts. Last removed categories: $($removedCategories -join ', ')"
            }

            Write-Warning "Defender API rejected unsupported categories; retrying without: $($removedCategories -join ', ')"
        }
    }

    if (-not $updatedSetting) {
        $updatedSettings = Invoke-JsonRequest -Method GET -Uri $settingsUri -Headers $defenderHeaders
        $updatedSetting = $updatedSettings.value | Where-Object { $_.id -eq $setting.id } | Select-Object -First 1
        if (-not $updatedSetting) {
            throw "POST completed, but export setting $($setting.id) was not returned by POST or GET."
        }
    }

    $notInTargetState = @()
    foreach ($categoryToVerify in $verifyCategoryStates.Keys) {
        if ((Get-LogCategoryState -Logs @($updatedSetting.logs) -Category $categoryToVerify) -ne [bool]$verifyCategoryStates[$categoryToVerify]) {
            $notInTargetState += $categoryToVerify
        }
    }

    if ($notInTargetState.Count -gt 0) {
        throw "The following categories were not set to their requested state: $($notInTargetState -join ', ')"
    }

    [pscustomobject]@{
        ExportSettingId = $updatedSetting.id
        WorkspaceResourceId = $workspaceResourceId
        Created = [bool]$selection.CreateNew
        EnabledGroups = $enabledGroups
        DisabledGroups = $disabledGroups
        SkippedGroups = $skippedGroups
        ApiWritableCategoryStates = $categoryStates
        ClearedPortalOnlyCategories = $clearUnsupportedCategories
    }
}