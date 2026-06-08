# Microsoft Defender XDR Data Connector Permission Guide

This guide explains why a user can be a Security Administrator or Global Administrator and still see `No Permission` or disabled controls when trying to enable Microsoft Defender XDR tables in Microsoft Sentinel.

The key point is that the Defender XDR Data Connector crosses two permission planes:

- Microsoft Defender XDR / Microsoft Entra permissions
- Azure RBAC permissions on the Microsoft Sentinel Log Analytics workspace

Having one side does not automatically grant the other.

## Common Scenario

A customer wants to enable Microsoft Defender for Endpoint (MDE) advanced hunting tables through the Microsoft Defender XDR Data Connector for a Microsoft Sentinel workspace.

The user is:

- A member of the Microsoft Entra tenant.
- Security Administrator, and possibly Global Administrator.
- PIM-activated for the required Entra role.
- Using legacy Defender XDR RBAC, not Microsoft Defender unified RBAC.
- Working with a Log Analytics workspace joined to Sentinel in the Defender portal / Unified SecOps experience.
- In IL2 / GCC, where Sentinel Data Lake does not exist.

If the user still sees `No Permission`, the most likely missing piece is Azure RBAC on the Sentinel workspace, not the Defender administrator role.

## Permission Model

Microsoft's requirements for the Defender XDR connector include all of these gates:

1. A valid Microsoft Defender XDR-eligible license.
2. Security Administrator, or equivalent, on the tenant streaming the logs.
3. Read and write permissions on the Microsoft Sentinel workspace.
4. The account applying connector changes must be a member of the same Microsoft Entra tenant associated with the Sentinel workspace.

Security Administrator or Global Administrator satisfies the Defender / Entra side, but it does not automatically grant Azure resource permissions on the Log Analytics workspace.

```text
Security Administrator / Global Administrator != Log Analytics workspace write access
```

## Required Workspace Permissions

For the Sentinel workspace side, the user typically needs one of these Azure RBAC roles on the workspace, resource group, or subscription:

- Microsoft Sentinel Contributor
- Contributor
- Owner

At minimum, the user needs permissions that cover:

```text
Microsoft.OperationalInsights/workspaces/read
Microsoft.SecurityInsights/dataConnectors/read
Microsoft.SecurityInsights/dataConnectors/write
```

Depending on the exact portal or API path, broader workspace write permissions can also be checked.

## Why Global Administrator Is Not Enough

Global Administrator is an Entra ID role. It is powerful for tenant-level administration, but it does not automatically grant Azure RBAC permissions over Azure resources.

A Global Administrator can sometimes elevate access to manage Azure resources, but that requires a separate tenant-level access management action. Until that happens, the account might still have no write permission on:

```text
/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>
```

So a Global Administrator can still fail to modify the Sentinel data connector if they do not have workspace-scoped Azure RBAC.

## Why Security Administrator Is Not Enough

Security Administrator is required for the Defender side of the connector experience, but it is not an Azure resource role.

It does not grant:

- Log Analytics workspace write access
- Sentinel data connector write access
- Resource group Contributor permissions
- Subscription Contributor permissions

That is why a Security Administrator can pass Defender-side checks and still get blocked when the portal tries to update the Sentinel connector or workspace export configuration.

## Legacy Defender XDR RBAC Versus Unified RBAC

If the customer is using legacy Defender XDR RBAC, Microsoft Defender unified RBAC is probably not the immediate cause.

In legacy mode, think of the model as two separate gates:

| Plane | What It Controls | Common Required Role |
| --- | --- | --- |
| Defender / Entra | Ability to manage Defender XDR connector settings and Defender-side integration | Security Administrator or equivalent |
| Azure / Sentinel | Ability to write connector configuration against the Log Analytics workspace | Microsoft Sentinel Contributor, Contributor, or Owner |

Unified RBAC matters only if it has been activated for the relevant workloads or Sentinel workspace.

If unified RBAC is enabled, Sentinel access can be managed or synchronized through Defender RBAC. Microsoft also notes that Global Administrator does not automatically grant workspace permissions in that model. But if the tenant is truly using legacy Defender XDR RBAC, verify Azure RBAC first.

## Unified SecOps / Defender Portal Onboarding

When a Sentinel workspace is onboarded to the Defender portal / Unified Security Operations experience, some connector controls in the Azure portal can be disabled by design.

For example, the portal can show a message like:

```text
One or more of your workspaces are onboarded to Unified Security Operations Platform. Incidents and alerts configuration is disabled.
```

That message usually applies to the `Connect incidents & alerts` section. It does not necessarily mean the user lacks permission. It means incidents and alerts are controlled by the Defender portal / Unified SecOps integration rather than the old Azure Sentinel connector toggle.

For enabling raw MDE advanced hunting tables, focus on the `Connect events` / Defender Streaming API behavior rather than the disabled incidents and alerts section.

## IL2 / GCC Notes

In IL2 / GCC, Sentinel Data Lake might not exist. That should not by itself block streaming MDE advanced hunting tables to a Log Analytics workspace.

Sentinel Data Lake is a separate capability. The MDE table streaming path uses Defender XDR export settings that point to the Log Analytics workspace.

For IL2 / GCC API automation, use the GCC Defender API endpoint:

```text
https://api-gcc.securitycenter.microsoft.us
```

The absence of Sentinel Data Lake is expected in IL2 and should not be treated as the root cause for `No Permission` when enabling MDE tables.

## Most Likely Root Cause

Given this scenario:

- User is a tenant member.
- Security Administrator or Global Administrator is active.
- Tenant is using legacy Defender XDR RBAC.
- They only want to enable MDE tables via the XDR Data Connector.
- The LAW is joined to Sentinel in Unified XDR.
- Sentinel Data Lake is unavailable in IL2.

The most likely root cause is:

```text
The user has Defender-side authority, but does not have Azure RBAC write authority on the Sentinel workspace.
```

Assign Microsoft Sentinel Contributor, Contributor, or Owner at the workspace, resource group, or subscription scope, then retry with a fresh portal session.

## Triage Checklist

Use this checklist with the customer.

### 1. Confirm Tenant Membership

Verify the user is a member, not just a B2B guest, in the Microsoft Entra tenant associated with the Sentinel workspace.

### 2. Confirm Entra Role Activation

Verify PIM activation for Security Administrator or Global Administrator is active before opening the connector page.

### 3. Confirm Workspace Azure RBAC

In the Azure portal:

```text
Log Analytics workspace -> Access control (IAM) -> Check access
```

Check the exact user account and confirm one of these roles exists at workspace, resource group, or subscription scope:

- Microsoft Sentinel Contributor
- Contributor
- Owner

If missing, assign Microsoft Sentinel Contributor at the resource group or workspace scope.

### 4. Confirm Same Account And Tenant Context

Make sure the customer is not signed into one tenant in Azure portal and another tenant in Defender portal.

Use a fresh browser profile or InPrivate session after role activation or assignment changes.

### 5. Confirm Legacy Versus Unified RBAC

If they are using legacy Defender XDR RBAC, Azure RBAC is the primary workspace permission source to check.

If Microsoft Defender unified RBAC has been activated for Sentinel or the workspace, then check Defender RBAC assignments and scopes in addition to Azure RBAC.

### 6. Confirm The Disabled UI Section

If the disabled section is `Connect incidents & alerts`, and the workspace is onboarded to Unified SecOps, that disabled state is expected.

If the issue is enabling raw MDE tables under `Connect events`, verify workspace write permissions and Defender XDR permissions.

### 7. Validate With API Or Script

If the portal remains ambiguous, validate the permission boundary with the script in this repository.

For IL2 / GCC:

```powershell
.\Set-DefenderXdrDeviceTablesToSentinel.ps1 `
  -Cloud GCC `
  -SubscriptionId "<subscription-id>" `
  -ResourceGroupName "<resource-group>" `
  -WorkspaceName "<workspace-name>" `
  -EnableMDE `
  -WhatIf
```

Expected outcomes:

- Failure during workspace permission checks points to Azure RBAC.
- Failure during Defender API calls points to Defender role, licensing, endpoint, or tenant context.
- A successful `-WhatIf` means the script can build the intended Defender export setting without posting changes.

## Recommended Customer Message

Use wording like this:

```text
Security Administrator or Global Administrator is required for the Defender XDR side of the connector, but it does not automatically grant write access to the Sentinel Log Analytics workspace. To enable MDE advanced hunting tables through the XDR Data Connector, the same user also needs Azure RBAC write permissions on the Sentinel workspace, typically Microsoft Sentinel Contributor, Contributor, or Owner. Because this tenant is using legacy XDR RBAC, Unified RBAC is unlikely to be the immediate cause unless it has been activated for Sentinel. The absence of Sentinel Data Lake in IL2 should not block streaming MDE tables to the LAW.
```

## Fastest Fix To Try

Assign the user Microsoft Sentinel Contributor at the workspace resource group scope, have them sign out and back in, then retry enabling MDE tables.

If that still fails, capture the exact error and test the same operation with the IL2/GCC script using `-WhatIf` to identify whether the failure is Azure RBAC or Defender API authorization.
