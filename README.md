# Sentinel XDR Unified Streaming API

PowerShell tooling for creating and managing an independent Microsoft Defender XDR Streaming API entry that streams selected advanced hunting tables into a Microsoft Sentinel Log Analytics workspace.

The scripts only change table groups when you request them with explicit flags. They can enable or disable the Defender for Endpoint Device table set, the API-writable Cloud Apps and Identity categories that Defender accepts through `POST /api/dataExportSettings`, and can clear portal-only Microsoft Defender for Office categories on disable. They intentionally do not force Alert tables.

Use the single Az script and choose the tenant cloud with `-Cloud`:

| Environment | Script | Cloud value | Defender API endpoint |
| --- | --- | --- | --- |
| Commercial | `Set-DefenderXdrDeviceTablesToSentinel.ps1` | `Commercial` | `https://api.security.microsoft.com` |
| IL2 / GCC | `Set-DefenderXdrDeviceTablesToSentinel.ps1` | `GCC` | `https://api-gcc.securitycenter.microsoft.us` |

The `-Cloud GCC` option is for Microsoft 365 GCC / IL2. It is not for GCC High or DoD. GCC High and DoD use different endpoints and should get their own variant.

## No-Az / Graph-Friendly Option

If a customer cannot install Az PowerShell, use the no-Az variant in `graph-solution/`:

```powershell
cd .\graph-solution
.\Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -WhatIf
```

That script does not use Az cmdlets. It still is not a Microsoft Graph-only implementation: Graph is used for the Entra role check, Azure Resource Manager REST is used for workspace and Sentinel connector validation, and the Defender XDR Streaming API is used for `dataExportSettings`. See `graph-solution/README.md` for the exact token audiences, scopes, and permissions.

## Before You Start

You need:

- Windows PowerShell 5.1 or PowerShell 7+.
- The Az PowerShell module for the root scripts, or the no-Az script in `graph-solution/` when Az cannot be installed.
- A Microsoft Defender XDR-eligible license in the target tenant.
- A Microsoft Sentinel-enabled Log Analytics workspace in the same tenant.
- An interactive user sign-in. The Defender Streaming API endpoint rejects application and service-principal tokens for this workflow.

Install Az if needed:

```powershell
Install-Module Az -Scope CurrentUser -Repository PSGallery -Force
```

The signed-in user needs both:

- Entra ID role: Security Administrator or Global Administrator in the target tenant.
- Azure RBAC on the target workspace or resource group that grants:
  - `Microsoft.OperationalInsights/workspaces/read`
  - `Microsoft.SecurityInsights/dataConnectors/read`
  - `Microsoft.SecurityInsights/dataConnectors/write`

Built-in Azure roles that satisfy the workspace actions include Microsoft Sentinel Contributor, Contributor, and Owner at the workspace resource group or a higher scope.

## Independent Streaming API Entry Workflow

Each run retrieves the current Defender XDR Streaming API entries, prints the tenant inventory, and highlights the proposed independent entry name with `***` and color. The default proposed name is:

```text
SentinelExportSettings-{workspaceName}-Managed
```

Use `-NewExportSettingId` to choose a different proposed name. If the proposed entry already exists and is mapped to the target Log Analytics workspace, the script can reuse it. If it does not exist, the script can create it as a new entry mapped to that workspace. If five Streaming API entries already exist and the independent entry is not present, the script stops because Defender XDR has a five-entry tenant limit.

By default, the script prompts you to select which workspace-mapped Streaming API entry to modify. Use `-ExportSettingId` when you need a non-interactive run against a known existing entry. The selected entry must be mapped to the target Log Analytics workspace; the script stops if the selected entry points somewhere else.

The script no longer enables tables automatically. Use `-EnableMDE`, `-EnableMDI`, or `-EnableMDO` to request group enables, and `-DisableMDE`, `-DisableMDI`, or `-DisableMDO` to request group disables. `-DeleteExportSetting` deletes the selected workspace-mapped Streaming API entry. `-DisableDeviceTables` remains as a compatibility alias for `-DisableMDE -DisableMDI -DisableMDO`.

## What This Does

When `-EnableMDE` is used, the scripts turn on these Defender XDR Device table exports for the target Log Analytics workspace:

- `DeviceInfo`
- `DeviceNetworkInfo`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceLogonEvents`
- `DeviceImageLoadEvents`
- `DeviceEvents`
- `DeviceFileCertificateInfo`

In the Defender export API these appear as `AdvancedHunting-*` categories, for example `AdvancedHunting-DeviceInfo`.

When `-EnableMDI` or `-DisableMDI` is used, the scripts manage these API-writable Cloud Apps and Identity categories:

- `CloudAppEvents`
- `IdentityDirectoryEvents`
- `IdentityLogonEvents`
- `IdentityQueryEvents`

These are the Defender API category names that can be safely written. Some related portal checkboxes are displayed as `AdvancedHunting-*` names, but the API rejects those names on write.

The scripts preserve these categories instead of intentionally changing them:

- `Alert`
- `AdvancedHunting-AlertEvidence`
- `AdvancedHunting-AlertInfo`
- `AdvancedHunting-BehaviorEntities`
- `AdvancedHunting-BehaviorInfo`

Microsoft Defender for Office email/URL categories, such as `AdvancedHunting-EmailEvents`, `AdvancedHunting-EmailUrlInfo`, and `AdvancedHunting-UrlClickEvents`, are not forced on during `-EnableMDO` because the Defender API rejects both the portal `AdvancedHunting-*` names and the short aliases in this workflow. During `-DisableMDO`, those portal-only categories are expected to clear because the script posts the API-safe replacement setting without unsupported category names.

## Why This Is Not Just an ARM Data Connector PUT

The Microsoft Sentinel ARM data connector resource is still useful for discovery:

```text
Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/dataConnectors/{connectorId}
```

For the Microsoft Defender XDR connector, ARM exposes `kind: MicrosoftThreatProtection`. That connector mostly represents incidents and alerts.

The raw advanced hunting table export toggles, including the Device tables, are controlled by the Defender XDR export setting instead:

```http
GET  /api/dataExportSettings
POST /api/dataExportSettings
```

The portal-created setting that points to Log Analytics often looks like this:

```text
SentinelExportSettings-{workspaceName}
```

For a workspace named `my-sentinel-ws`, a historical portal-managed entry might be:

```text
SentinelExportSettings-my-sentinel-ws
```

The script-managed independent entry defaults to a different name so it can be created, modified, and deleted without relying on the portal-created entry:

```text
SentinelExportSettings-my-sentinel-ws-Managed
```

When a workspace is managed as the primary workspace through the Defender portal, trying to update the Sentinel `MicrosoftThreatProtection` ARM connector can fail with this message:

```text
The workspace is enabled through the Microsoft Threat Protection Portal.
Changes to the connector in Microsoft Sentinel are disabled.
```

That message is the clue: for a Defender-primary workspace, use Defender `DataExportSettings` for the table export toggles.

## What the Script Checks First

Before changing anything, each script checks:

- You are signed in with `Az.Accounts`.
- The active Azure context is in the expected tenant and subscription.
- The Log Analytics workspace exists.
- Resource providers are registered:
  - `Microsoft.Insights`
  - `Microsoft.OperationalInsights`
  - `Microsoft.SecurityInsights`
- Your Azure identity has workspace-level permissions for the Sentinel connector read/write path.
- Your Entra identity has `Security Administrator` or `Global Administrator`, unless you explicitly use `-SkipSecurityAdministratorCheck`.
- The Defender XDR Streaming API inventory is below the five-entry limit when a new independent entry must be created.
- The selected Defender XDR export setting is mapped to the target workspace, or a new workspace export setting can be built.

The `Microsoft.Insights` provider check is included because the workspace export path depends on Log Analytics/Azure Monitor plumbing, and missing provider registration can make this fail in confusing ways.

## Commercial Usage

Sign in to the commercial tenant and subscription:

```powershell
Connect-AzAccount
Set-AzContext -SubscriptionId "<subscription-id>"
```

Dry run first:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -WhatIf
```

The `-WhatIf` preview prints the current Streaming API entries, the proposed independent entry name, the selected entry, and the exact categories that would be enabled or disabled. For disable, it also prints the portal-only categories expected to be cleared. It then skips the final POST or DELETE.

Enable MDE and MDI table exports on the selected independent entry:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -Confirm:$false
```

Disable MDE, MDI, and MDO-managed categories again:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -DisableMDE `
  -DisableMDI `
  -DisableMDO `
  -Confirm:$false
```

Delete the selected independent entry:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -DeleteExportSetting `
  -Confirm:$false
```

## IL2 / GCC Usage

For Microsoft 365 GCC / IL2, use the same script with `-Cloud GCC`:

```powershell
Connect-AzAccount
Set-AzContext -SubscriptionId "<subscription-id>"
```

Dry run first:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud GCC `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -WhatIf
```

Enable MDE and MDI table exports:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud GCC `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -Confirm:$false
```

If your Azure resources are in Azure Government rather than public Azure, sign in with the appropriate Azure environment first:

```powershell
Connect-AzAccount -Environment AzureUSGovernment
```

That Azure cloud choice is separate from the Defender API endpoint selected by `-Cloud GCC`.

## Useful Parameters

| Parameter | Purpose |
| --- | --- |
| `-SubscriptionId` | Azure subscription that contains the Log Analytics workspace. |
| `-ResourceGroupName` | Resource group containing the workspace. |
| `-WorkspaceName` | Log Analytics workspace name. |
| `-Cloud` | Required Defender XDR cloud endpoint. Use `Commercial` for public commercial tenants or `GCC` for Microsoft 365 GCC / IL2. |
| `-TenantId` | Optional guardrail. If omitted, the active Az tenant is used. |
| `-ExportSettingId` | Optional non-interactive selection of an existing Streaming API entry. The entry must be mapped to the target workspace. If omitted, the script lists entries and prompts for a selection. |
| `-NewExportSettingId` | Proposed independent entry name to create or reuse. Defaults to `SentinelExportSettings-{WorkspaceName}-Managed`. |
| `-EnableMDE` / `-DisableMDE` | Enables or disables Defender for Endpoint Device categories. |
| `-EnableMDI` / `-DisableMDI` | Enables or disables API-writable Cloud Apps and Identity categories. |
| `-EnableMDO` / `-DisableMDO` | `-EnableMDO` is reported but not forced because MDO email/URL categories are not writable through this API path. `-DisableMDO` clears known portal-only MDO categories by posting the API-safe replacement setting. |
| `-DeleteExportSetting` | Deletes the selected workspace-mapped Streaming API entry. Cannot be combined with enable/disable flags. |
| `-DisableDeviceTables` | Compatibility alias for `-DisableMDE -DisableMDI -DisableMDO`. Alert/Behavior categories are preserved. |
| `-RegisterMissingProvider` | Registers missing Azure resource providers before continuing. |
| `-SkipSecurityAdministratorCheck` | Skips the Microsoft Graph role check if you verified the role manually. |
| `-WhatIf` | Shows the inventory, selected/proposed entry, and intended category changes without posting or deleting. |

## Verifying Data Flow

After enabling the export, give the pipeline time to produce events. Then run this KQL in the target Log Analytics workspace for the Device tables:

```kusto
union isfuzzy=true
    DeviceInfo,
    DeviceNetworkInfo,
    DeviceProcessEvents,
    DeviceNetworkEvents,
    DeviceFileEvents,
    DeviceRegistryEvents,
    DeviceLogonEvents,
    DeviceImageLoadEvents,
    DeviceEvents,
    DeviceFileCertificateInfo
| summarize Count = count() by Type, bin(TimeGenerated, 1h)
| sort by TimeGenerated desc
```

For the additional API-writable categories, query the tables separately because activity depends on tenant licensing and event volume:

```kusto
union isfuzzy=true
  CloudAppEvents,
  IdentityDirectoryEvents,
  IdentityLogonEvents,
  IdentityQueryEvents
| summarize Count = count() by Type, bin(TimeGenerated, 1h)
| sort by TimeGenerated desc
```

You can also inspect the Defender export setting directly:

```powershell
$token = (Get-AzAccessToken -ResourceUrl "https://api.securitycenter.microsoft.com").Token
if ($token -is [securestring]) {
  $token = [System.Net.NetworkCredential]::new("", $token).Password
}

Invoke-WebRequest `
  -Uri "https://api.security.microsoft.com/api/dataExportSettings" `
  -Headers @{ Authorization = "Bearer $token" } `
  -UseBasicParsing
```

For IL2/GCC, use the GCC endpoint and token resource instead:

```powershell
$token = (Get-AzAccessToken -ResourceUrl "https://api-gcc.securitycenter.microsoft.us").Token
if ($token -is [securestring]) {
  $token = [System.Net.NetworkCredential]::new("", $token).Password
}

Invoke-WebRequest `
  -Uri "https://api-gcc.securitycenter.microsoft.us/api/dataExportSettings" `
  -Headers @{ Authorization = "Bearer $token" } `
  -UseBasicParsing
```

## Defender API Category Quirks

The Defender API can return categories from `GET /api/dataExportSettings` that it rejects when sent back in `POST /api/dataExportSettings`. Examples seen in this tenant include:

```text
AdvancedHunting-CloudAppEvents
AdvancedHunting-EmailAttachmentInfo
AdvancedHunting-EmailEvents
AdvancedHunting-EmailPostDeliveryEvents
AdvancedHunting-EmailUrlInfo
AdvancedHunting-IdentityDirectoryEvents
AdvancedHunting-IdentityLogonEvents
AdvancedHunting-IdentityQueryEvents
AdvancedHunting-SentinelBehaviorInfo
AdvancedHunting-SentinelBehaviorEntities
AdvancedHunting-UrlClickEvents
```

The scripts filter those unsupported write names before posting. Where Defender accepts a writable alias, the scripts use the alias when `-EnableMDI` or `-DisableMDI` is requested:

```text
AdvancedHunting-CloudAppEvents -> CloudAppEvents
AdvancedHunting-IdentityDirectoryEvents -> IdentityDirectoryEvents
AdvancedHunting-IdentityLogonEvents -> IdentityLogonEvents
AdvancedHunting-IdentityQueryEvents -> IdentityQueryEvents
```

The scripts also include a bounded retry that removes any additional unsupported categories reported by the Defender API. This keeps the automation inside the safe API surface instead of trying to force portal-only categories. On disable, the known portal-only MDO/MDI/Cloud categories are printed in the preview as expected-to-clear categories. Alert and Behavior categories are not intentionally enabled, disabled, or deleted.

## What The Scripts Do Not Do

- They do not create the Log Analytics workspace or enable Sentinel.
- They do not create or configure the Microsoft Defender XDR Sentinel incidents and alerts connector.
- They do not intentionally modify Alert or Behavior categories.
- They do not force MDO email/URL categories on through `-EnableMDO` because the Defender API rejects those category names in this workflow.
- They do not modify workspace retention, table plans, data collection rules, or analytics rules.

## Operational Constraints

- Defender XDR allows up to five Streaming API export targets per tenant.
- The Defender API endpoint used here requires interactive user context.
- Log Analytics retention is governed by the workspace or table retention policy, not Defender Advanced Hunting retention.
- Sentinel ingestion costs apply to advanced hunting tables streamed into the workspace. Plan for Device, Identity, Cloud Apps, and any MDO data enabled elsewhere.
- If events arrive in Log Analytics more than 48 hours after occurrence, `TimeGenerated` can reflect ingestion time. Use source event columns such as `Timestamp` when writing detections that need occurrence time.

## Cleanup And Rollback

To turn script-managed categories off without deleting the entry:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -DisableMDE `
  -DisableMDI `
  -DisableMDO `
  -Confirm:$false
```

To delete the entry entirely, use `-DeleteExportSetting` after confirming the selected entry with `-WhatIf`.

## Support Notes

The scripts call Azure Resource Manager and the Defender XDR Streaming API endpoint used by the Defender portal for export settings. Test in a non-production tenant or workspace before using in production.

## Troubleshooting

If the role check fails, confirm the account has `Security Administrator` or higher in the Defender tenant. Use `-SkipSecurityAdministratorCheck` only after checking that manually.

If provider registration fails, rerun with `-RegisterMissingProvider` or register the providers ahead of time.

If the Defender API returns `403`, the account likely lacks Defender API access, Defender XDR licensing, or the right tenant context.

If the Defender API returns `404`, check that you are using the correct script for the cloud: commercial versus IL2/GCC.

If ARM returns the `primaryWorkspace` message, that is expected for Defender-primary workspaces. The scripts intentionally use Defender `DataExportSettings` for the actual API-writable table toggles.
