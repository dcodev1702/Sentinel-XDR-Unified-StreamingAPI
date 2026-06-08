# Graph / No-Az Solution

This folder contains a no-Az PowerShell variant for customers who cannot install the Az PowerShell module.

The important boundary is this: Microsoft Graph does not expose the Microsoft Sentinel workspace ARM resources or the Microsoft Defender XDR Streaming API export setting. This solution uses Microsoft Graph only for the Entra role check, then uses REST calls for the two APIs that actually own the work:

- Microsoft Graph: validates that the signed-in user has Security Administrator or Global Administrator.
- Azure Resource Manager: validates the Log Analytics workspace, Sentinel connector, provider registration, and effective workspace permissions.
- Microsoft Defender XDR Streaming API: reads, creates, updates, or deletes `/api/dataExportSettings`.

No Az cmdlets are used.

## Files

| File | Purpose |
| --- | --- |
| `Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1` | No-Az script for Commercial and IL2/GCC tenants. |

## Sign-In Model

The script uses interactive Microsoft Entra device-code sign-in. By default, it uses the Microsoft Azure PowerShell public client application ID:

```text
1950a258-227b-4e31-a9cf-717495945fc2
```

That default is intentional: it can request user tokens for Azure Resource Manager and Microsoft Defender XDR without requiring the Az module to be installed locally.

You can override it with `-PublicClientId` if the customer has a different approved public client application.

## Required User Roles And Permissions

The signed-in user needs all of the same authority required by the Az-based scripts:

- Microsoft Entra role: Security Administrator or Global Administrator in the Defender tenant.
- Azure RBAC on the target workspace, resource group, or subscription that grants:
  - `Microsoft.OperationalInsights/workspaces/read`
  - `Microsoft.SecurityInsights/dataConnectors/read`
  - `Microsoft.SecurityInsights/dataConnectors/write`
- A Microsoft Defender XDR-eligible license in the target tenant.
- The Sentinel Log Analytics workspace must exist in the same tenant context.

Built-in Azure roles that normally satisfy the workspace actions include Microsoft Sentinel Contributor, Contributor, and Owner.

## Required Token Audiences And Scopes

This workflow needs tokens for three different audiences. These are not interchangeable.

| API plane | Token audience / resource | Why it is needed |
| --- | --- | --- |
| Microsoft Graph | `https://graph.microsoft.com` | Reads `/me/transitiveMemberOf/microsoft.graph.directoryRole` to verify Security Administrator or Global Administrator. |
| Azure Resource Manager, public Azure | `https://management.azure.com/` | Reads the workspace, provider registration state, Sentinel connector list, and effective permissions. |
| Azure Resource Manager, Azure Government | `https://management.usgovcloudapi.net/` | Same ARM checks when the workspace is in Azure Government. |
| Defender XDR, Commercial | `https://api.securitycenter.microsoft.com` | Gets a user token accepted by the commercial Defender XDR Streaming API. |
| Defender XDR, IL2/GCC | `https://api-gcc.securitycenter.microsoft.us` | Gets a user token accepted by the GCC Defender XDR Streaming API. |

For Microsoft Graph consent, the role check typically requires delegated directory-read capability such as `RoleManagement.Read.Directory` or `Directory.Read.All`; `User.Read` alone may not be enough to return directory role display names. If the tenant blocks that read, run the script with `-SkipSecurityAdministratorCheck` only after manually confirming the user has Security Administrator or Global Administrator.

For Azure Resource Manager, the delegated permission is the normal ARM `user_impersonation` permission behind the management endpoint. The effective authorization is still Azure RBAC on the workspace.

For Defender XDR, there is no Microsoft Graph scope that replaces this API. The token audience must be the Defender XDR resource above, and authorization is governed by Defender licensing, tenant context, and the signed-in user's Defender/Entra role.

## Commercial Usage

Dry run first:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -WhatIf
```

Enable MDE and MDI exports:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1 `
  -Cloud Commercial `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -Confirm:$false
```

## IL2 / GCC Usage

For Microsoft 365 GCC / IL2, use `-Cloud GCC`:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1 `
  -Cloud GCC `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -EnableMDI `
  -WhatIf
```

If the Log Analytics workspace is in Azure Government, add `-AzureEnvironment AzureUSGovernment`:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel-Graph.ps1 `
  -Cloud GCC `
  -AzureEnvironment AzureUSGovernment `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -WhatIf
```

The IL2/GCC path in this folder is for Microsoft 365 GCC. GCC High and DoD use different endpoints and should get their own tested variant.

## Supported Operations

The no-Az script supports the same table group switches as the root scripts:

| Switch | Behavior |
| --- | --- |
| `-Cloud` | Required cloud selector. Use `Commercial` or `GCC`. |
| `-EnableMDE` / `-DisableMDE` | Enables or disables Defender for Endpoint Device categories. |
| `-EnableMDI` / `-DisableMDI` | Enables or disables API-writable Cloud Apps and Identity categories. |
| `-EnableMDO` / `-DisableMDO` | `-EnableMDO` is reported but not forced because the API rejects those categories. `-DisableMDO` clears known portal-only MDO categories through an API-safe replacement post. |
| `-DeleteExportSetting` | Deletes the selected workspace-mapped Streaming API entry. |
| `-RegisterMissingProvider` | Registers missing Azure resource providers through ARM REST. |
| `-SkipSecurityAdministratorCheck` | Skips the Graph role check after manual role validation. |

## Troubleshooting

If Graph role validation fails, confirm the user has Security Administrator or Global Administrator and that the sign-in client is allowed to read directory role membership. Use `-SkipSecurityAdministratorCheck` only after manual validation.

If ARM calls fail, check Azure RBAC on the workspace or resource group. Security Administrator and Global Administrator do not grant Azure RBAC by themselves.

If Defender calls fail with `403`, check Defender licensing, tenant context, and the user's Defender-side authority.

If Defender calls fail with `404`, verify `-Cloud Commercial` versus `-Cloud GCC`.
