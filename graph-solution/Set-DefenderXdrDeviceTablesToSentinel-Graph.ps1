<#
.SYNOPSIS
Configures Microsoft Defender XDR Streaming API exports to Microsoft Sentinel without Az PowerShell.

.DESCRIPTION
This no-Az variant uses interactive Microsoft Entra device-code sign-in to obtain user tokens for three API audiences:
Microsoft Graph for the Entra role check, Azure Resource Manager for workspace validation, and Microsoft Defender XDR for
the Streaming API export setting. Microsoft Graph does not own the Sentinel workspace or Defender export setting APIs;
those operations are performed through ARM REST and Defender REST.

The script can create, update, or delete an independent Defender XDR Streaming API entry mapped to a Log Analytics
workspace. It manages the same MDE device table categories and API-writable MDI categories as the Az-based scripts.

.PARAMETER SubscriptionId
Azure subscription that contains the Microsoft Sentinel Log Analytics workspace.

.PARAMETER ResourceGroupName
Resource group that contains the Log Analytics workspace.

.PARAMETER WorkspaceName
Name of the Log Analytics workspace.

.PARAMETER Cloud
Defender XDR cloud endpoint to use. Commercial targets api.security.microsoft.com. GCC targets api-gcc.securitycenter.microsoft.us.
GCC High and DoD are not covered by this script.

.PARAMETER AzureEnvironment
Azure Resource Manager cloud for the Log Analytics workspace. Use AzureCloud for public Azure or AzureUSGovernment for Azure Government.

.PARAMETER ExportSettingId
Optional existing Defender XDR Streaming API entry to select non-interactively. The entry must be mapped to the target workspace.

.PARAMETER NewExportSettingId
Optional proposed independent entry name. Defaults to SentinelExportSettings-{WorkspaceName}-Managed.

.PARAMETER TenantId
Optional tenant ID. If omitted, the script signs in through the organizations endpoint and reads the tenant ID from the token.

.PARAMETER PublicClientId
Public client application ID used for device-code sign-in. Defaults to the Microsoft Azure PowerShell public client ID so ARM and
Defender resource tokens can be requested without installing Az PowerShell.

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
Registers missing Azure resource providers through ARM REST before continuing.

.EXAMPLE
.\Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1 `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -ResourceGroupName "rg-sentinel" `
  -WorkspaceName "law-sentinel" `
  -EnableMDE `
  -EnableMDI `
  -WhatIf

.EXAMPLE
.\Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1 `
  -Cloud GCC `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -ResourceGroupName "rg-sentinel" `
  -WorkspaceName "law-sentinel" `
  -EnableMDE `
  -Confirm:$false

.NOTES
No Az cmdlets are used. The signed-in user still needs Entra/Defender authority plus Azure RBAC on the target workspace.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [Parameter()]
    [ValidateSet("Commercial", "GCC")]
    [string]$Cloud = "Commercial",

    [Parameter()]
    [ValidateSet("AzureCloud", "AzureUSGovernment")]
    [string]$AzureEnvironment = "AzureCloud",

    [Parameter()]
    [string]$ExportSettingId,

    [Parameter()]
    [string]$NewExportSettingId,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$PublicClientId = "1950a258-227b-4e31-a9cf-717495945fc2",

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

function Resolve-EndpointSettings {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Commercial", "GCC")]
        [string]$Cloud,

        [Parameter(Mandatory)]
        [ValidateSet("AzureCloud", "AzureUSGovernment")]
        [string]$AzureEnvironment
    )

    $defenderApiBaseUri = if ($Cloud -eq "GCC") { "https://api-gcc.securitycenter.microsoft.us" } else { "https://api.security.microsoft.com" }
    $defenderTokenResource = if ($Cloud -eq "GCC") { "https://api-gcc.securitycenter.microsoft.us" } else { "https://api.securitycenter.microsoft.com" }
    $armResource = if ($AzureEnvironment -eq "AzureUSGovernment") { "https://management.usgovcloudapi.net/" } else { "https://management.azure.com/" }
    $armBaseUri = $armResource.TrimEnd("/")

    return [pscustomobject]@{
        AuthorityHost = "https://login.microsoftonline.com"
        GraphResource = "https://graph.microsoft.com"
        ArmResource = $armResource
        ArmBaseUri = $armBaseUri
        DefenderApiBaseUri = $defenderApiBaseUri
        DefenderTokenResource = $defenderTokenResource
    }
}

function Invoke-FormRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [hashtable]$Body
    )

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $request = $null
    $response = $null

    try {
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
        $formPairs = [System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string, string]]]::new()
        foreach ($key in $Body.Keys) {
            [void]$formPairs.Add([System.Collections.Generic.KeyValuePair[string, string]]::new([string]$key, [string]$Body[$key]))
        }

        $request.Content = [System.Net.Http.FormUrlEncodedContent]::new($formPairs)
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $responseBody = if ($response.Content) { $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() } else { $null }
        $bodyObject = if ([string]::IsNullOrWhiteSpace($responseBody)) { $null } else { $responseBody | ConvertFrom-Json }

        return [pscustomobject]@{
            Success = [bool]$response.IsSuccessStatusCode
            StatusCode = [int]$response.StatusCode
            Body = $bodyObject
            RawBody = $responseBody
        }
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

function Get-TokenErrorMessage {
    param(
        [Parameter(Mandatory)]
        [object]$TokenResponse
    )

    if ($TokenResponse.Body -and ($TokenResponse.Body.PSObject.Properties.Name -contains "error_description")) {
        return [string]$TokenResponse.Body.error_description
    }

    if ($TokenResponse.Body -and ($TokenResponse.Body.PSObject.Properties.Name -contains "error")) {
        return [string]$TokenResponse.Body.error
    }

    return [string]$TokenResponse.RawBody
}

function Get-DeviceCodeToken {
    param(
        [Parameter(Mandatory)]
        [string]$AuthorityHost,

        [Parameter(Mandatory)]
        [string]$Tenant,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$ResourceUrl,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    $deviceCodeUri = "$AuthorityHost/$Tenant/oauth2/devicecode"
    $tokenUri = "$AuthorityHost/$Tenant/oauth2/token"
    $deviceCodeResponse = Invoke-FormRequest -Uri $deviceCodeUri -Body @{
        client_id = $ClientId
        resource = $ResourceUrl
    }

    if (-not $deviceCodeResponse.Success) {
        throw "Could not start device-code sign-in for $Purpose. Details: $(Get-TokenErrorMessage -TokenResponse $deviceCodeResponse)"
    }

    Write-Host ""
    Write-Host "Interactive sign-in required for $Purpose." -ForegroundColor Cyan
    Write-Host $deviceCodeResponse.Body.message -ForegroundColor Cyan

    $intervalSeconds = if ($deviceCodeResponse.Body.interval) { [int]$deviceCodeResponse.Body.interval } else { 5 }
    $expiresAt = (Get-Date).AddSeconds([int]$deviceCodeResponse.Body.expires_in)

    do {
        Start-Sleep -Seconds $intervalSeconds
        $tokenResponse = Invoke-FormRequest -Uri $tokenUri -Body @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            client_id = $ClientId
            code = $deviceCodeResponse.Body.device_code
        }

        if ($tokenResponse.Success) {
            return $tokenResponse.Body
        }

        $errorCode = if ($tokenResponse.Body -and ($tokenResponse.Body.PSObject.Properties.Name -contains "error")) { [string]$tokenResponse.Body.error } else { "unknown_error" }
        if ($errorCode -eq "authorization_pending") {
            continue
        }

        if ($errorCode -eq "slow_down") {
            $intervalSeconds += 5
            continue
        }

        throw "Device-code sign-in for $Purpose failed. Details: $(Get-TokenErrorMessage -TokenResponse $tokenResponse)"
    } while ((Get-Date) -lt $expiresAt)

    throw "Device-code sign-in for $Purpose timed out before authorization completed."
}

function Get-RefreshTokenAccessToken {
    param(
        [Parameter(Mandatory)]
        [string]$AuthorityHost,

        [Parameter(Mandatory)]
        [string]$Tenant,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$RefreshToken,

        [Parameter(Mandatory)]
        [string]$ResourceUrl,

        [Parameter(Mandatory)]
        [string]$Purpose
    )

    $tokenUri = "$AuthorityHost/$Tenant/oauth2/token"
    $tokenResponse = Invoke-FormRequest -Uri $tokenUri -Body @{
        grant_type = "refresh_token"
        client_id = $ClientId
        refresh_token = $RefreshToken
        resource = $ResourceUrl
    }

    if ($tokenResponse.Success) {
        return $tokenResponse.Body
    }

    throw "Could not exchange refresh token for $Purpose. Details: $(Get-TokenErrorMessage -TokenResponse $tokenResponse)"
}

function ConvertFrom-Base64UrlString {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $base64 = $Value.Replace("-", "+").Replace("_", "/")
    switch ($base64.Length % 4) {
        2 { $base64 += "==" }
        3 { $base64 += "=" }
    }

    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
}

function Get-JwtPayload {
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $parts = $AccessToken.Split(".")
    if ($parts.Count -lt 2) {
        throw "Access token was not a JWT."
    }

    return (ConvertFrom-Base64UrlString -Value $parts[1]) | ConvertFrom-Json
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
        [string]$ProviderNamespace,

        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [string]$ArmBaseUri,

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [bool]$RegisterMissing
    )

    $providerUri = "$ArmBaseUri/subscriptions/$SubscriptionId/providers/$ProviderNamespace`?api-version=2021-04-01"
    $provider = Invoke-JsonRequest -Method GET -Uri $providerUri -Headers $Headers
    $registrationState = [string]$provider.registrationState

    if ($registrationState -eq "Registered") {
        return
    }

    if ($RegisterMissing) {
        Write-Host "Registering resource provider $ProviderNamespace..."
        $registerUri = "$ArmBaseUri/subscriptions/$SubscriptionId/providers/$ProviderNamespace/register`?api-version=2021-04-01"
        Invoke-JsonRequest -Method POST -Uri $registerUri -Headers $Headers | Out-Null
        do {
            Start-Sleep -Seconds 5
            $provider = Invoke-JsonRequest -Method GET -Uri $providerUri -Headers $Headers
            $registrationState = [string]$provider.registrationState
        } until ($registrationState -eq "Registered")

        return
    }

    throw "Resource provider $ProviderNamespace is $registrationState, not Registered. Rerun with -RegisterMissingProvider or register it before continuing."
}

function Assert-SecurityAdministratorRole {
    param(
        [Parameter(Mandatory)]
        [string]$GraphResource,

        [Parameter(Mandatory)]
        [string]$GraphAccessToken
    )

    if ($SkipSecurityAdministratorCheck) {
        Write-Warning "Skipping Microsoft Entra Security Administrator role check."
        return
    }

    $headers = @{ Authorization = "Bearer $GraphAccessToken" }
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
        [string]$WorkspaceResourceId,

        [Parameter(Mandatory)]
        [string]$ArmBaseUri,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $permissionsUri = "$ArmBaseUri$WorkspaceResourceId/providers/Microsoft.Authorization/permissions`?api-version=2022-04-01"
    $permissions = Invoke-JsonRequest -Method GET -Uri $permissionsUri -Headers $Headers
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

$endpointSettings = Resolve-EndpointSettings -Cloud $Cloud -AzureEnvironment $AzureEnvironment
$tokenTenant = if ([string]::IsNullOrWhiteSpace($TenantId)) { "organizations" } else { $TenantId }

$graphToken = Get-DeviceCodeToken -AuthorityHost $endpointSettings.AuthorityHost -Tenant $tokenTenant -ClientId $PublicClientId -ResourceUrl $endpointSettings.GraphResource -Purpose "Microsoft Graph role validation"
if ([string]::IsNullOrWhiteSpace($TenantId)) {
    $jwtPayload = Get-JwtPayload -AccessToken $graphToken.access_token
    $TenantId = [string]$jwtPayload.tid
    Write-Host "Using tenant ID from signed-in token: $TenantId"
}

Assert-SecurityAdministratorRole -GraphResource $endpointSettings.GraphResource -GraphAccessToken $graphToken.access_token

if (-not ($graphToken.PSObject.Properties.Name -contains "refresh_token") -or [string]::IsNullOrWhiteSpace([string]$graphToken.refresh_token)) {
    throw "The sign-in response did not include a refresh token. Cannot request ARM and Defender tokens without another interactive sign-in."
}

$armToken = Get-RefreshTokenAccessToken -AuthorityHost $endpointSettings.AuthorityHost -Tenant $TenantId -ClientId $PublicClientId -RefreshToken $graphToken.refresh_token -ResourceUrl $endpointSettings.ArmResource -Purpose "Azure Resource Manager"
$defenderToken = Get-RefreshTokenAccessToken -AuthorityHost $endpointSettings.AuthorityHost -Tenant $TenantId -ClientId $PublicClientId -RefreshToken $graphToken.refresh_token -ResourceUrl $endpointSettings.DefenderTokenResource -Purpose "Microsoft Defender XDR Streaming API"

$armHeaders = @{ Authorization = "Bearer $($armToken.access_token)" }
$defenderHeaders = @{ Authorization = "Bearer $($defenderToken.access_token)" }

Assert-ProviderRegistered -ProviderNamespace "Microsoft.Insights" -SubscriptionId $SubscriptionId -ArmBaseUri $endpointSettings.ArmBaseUri -Headers $armHeaders -RegisterMissing ([bool]$RegisterMissingProvider)
Assert-ProviderRegistered -ProviderNamespace "Microsoft.OperationalInsights" -SubscriptionId $SubscriptionId -ArmBaseUri $endpointSettings.ArmBaseUri -Headers $armHeaders -RegisterMissing ([bool]$RegisterMissingProvider)
Assert-ProviderRegistered -ProviderNamespace "Microsoft.SecurityInsights" -SubscriptionId $SubscriptionId -ArmBaseUri $endpointSettings.ArmBaseUri -Headers $armHeaders -RegisterMissing ([bool]$RegisterMissingProvider)

$workspaceResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$workspaceUri = "$($endpointSettings.ArmBaseUri)$workspaceResourceId`?api-version=2022-10-01"
try {
    $workspace = Invoke-JsonRequest -Method GET -Uri $workspaceUri -Headers $armHeaders
}
catch {
    throw "Log Analytics workspace $WorkspaceName was not found in resource group $ResourceGroupName, or the signed-in user cannot read it. Details: $PSItem"
}

if (-not $workspace) {
    throw "Log Analytics workspace $WorkspaceName was not found in resource group $ResourceGroupName."
}

Assert-WorkspacePermissions -WorkspaceResourceId $workspaceResourceId -ArmBaseUri $endpointSettings.ArmBaseUri -Headers $armHeaders

$connectorListUri = "$($endpointSettings.ArmBaseUri)$workspaceResourceId/providers/Microsoft.SecurityInsights/dataConnectors`?api-version=$SentinelDataConnectorApiVersion"
$connectors = Invoke-JsonRequest -Method GET -Uri $connectorListUri -Headers $armHeaders
$mtpConnector = $connectors.value | Where-Object { $_.kind -eq "MicrosoftThreatProtection" } | Select-Object -First 1
if (-not $mtpConnector) {
    Write-Warning "No MicrosoftThreatProtection Sentinel connector was found through ARM. The Defender DataExportSettings call can still create the workspace export setting if Defender XDR is licensed and available."
}

$settingsUri = "$($endpointSettings.DefenderApiBaseUri)/api/dataExportSettings"
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
