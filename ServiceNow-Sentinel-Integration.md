# Integrating ServiceNow With Microsoft Sentinel

This guide describes how to integrate ServiceNow, often abbreviated as SNOW, with Microsoft Sentinel for SOC ticketing, incident response automation, and optional ServiceNow data ingestion into Sentinel.

As of 2026-06-11, the Microsoft Sentinel data connector catalog does not list a first-party Microsoft-managed ServiceNow ingestion connector. The most common production pattern is therefore:

- Use Microsoft Sentinel automation rules and Azure Logic Apps playbooks to create and update ServiceNow incidents from Sentinel incidents.
- Use Azure Monitor Logs Ingestion API, a Logic App, or an Azure Function when ServiceNow records must be ingested into Sentinel as custom tables.
- Use a bidirectional sync workflow only when ServiceNow is the operational system of record and Sentinel still needs status, owner, or closure updates.

If your tenant has a vendor-supported ServiceNow solution available in Microsoft Sentinel Content hub or Azure Marketplace, use that connector's deployment blade for ingestion. The RBAC, identity, ServiceNow dependency, and endpoint guidance below still applies to the surrounding deployment and operational controls.

## Recommended Architecture

![Sentinel and ServiceNow integration architecture: primary flow from a Sentinel incident through an automation rule to an Azure Logic Apps playbook and into a ServiceNow record; optional reverse path from changed ServiceNow records through the Logs Ingestion API or Sentinel Incidents REST API into a custom table or updated incident.](./images/sentinel-servicenow-architecture.svg)

Use three separate flows unless there is a strong reason to combine them:

| Flow | Purpose | Recommended technology |
| --- | --- | --- |
| Sentinel to ServiceNow | Create or update ServiceNow tickets when Sentinel incidents are created or changed. | Microsoft Sentinel automation rule plus Logic Apps playbook. |
| ServiceNow to Sentinel logs | Ingest ServiceNow records, CMDB context, change records, or security operations data into Sentinel for hunting and analytics. | Azure Monitor Logs Ingestion API with a DCR-backed custom table. |
| Bidirectional state sync | Keep ServiceNow state, owner, priority, and closure reason aligned with Sentinel. | Timer-based Logic App or Azure Function using correlation IDs and watermarks. |

## Deployment Scope

This solution assumes:

- A Microsoft Sentinel-enabled Log Analytics workspace already exists.
- ServiceNow ITSM, SecOps, or ITOM records are available through ServiceNow REST APIs.
- Azure resources can reach the ServiceNow instance over HTTPS 443.
- The SOC wants ServiceNow records to contain a durable reference back to the Sentinel incident.
- The implementation follows least privilege and avoids using ServiceNow `admin` accounts for automation.

## Microsoft RBAC Requirements

There are three Microsoft permission planes: the human deployer, the runtime workflow identity, and the Microsoft Sentinel service account that is allowed to run playbooks.

### Human Deployment And Operations Roles

| Scope | Role | Why it is needed |
| --- | --- | --- |
| Sentinel workspace, resource group, or subscription | Microsoft Sentinel Contributor | Create automation rules, attach playbooks, and manage Sentinel incident automation. |
| Sentinel workspace | Microsoft Sentinel Responder | Manually run playbooks on incidents and update incidents during testing. |
| Playbook resource group | Logic App Contributor for Consumption, or Logic Apps Standard Contributor/Developer for Standard | Create and edit Logic Apps playbooks. |
| Playbook resource group | Microsoft Sentinel Playbook Operator | Run playbooks manually from Sentinel incidents. |
| Playbook resource group | Owner or User Access Administrator | Grant the Microsoft Sentinel service account permission to run playbooks in the resource group. |
| Log Analytics workspace | Log Analytics Contributor | Create custom tables if ingesting ServiceNow data. |
| Data collection rule resource group | Monitoring Contributor or Contributor | Create data collection rules and optional data collection endpoints. |
| Key Vault | Key Vault Administrator or Key Vault Secrets Officer | Store and rotate ServiceNow secrets or certificates during deployment. |

For read-only SOC users, Microsoft Sentinel Reader and Log Analytics Reader are usually enough to view incidents and query the resulting ServiceNow custom tables.

### Runtime Azure Identities

| Runtime identity | Required role | Scope | Notes |
| --- | --- | --- | --- |
| Logic App system-assigned or user-assigned managed identity | Microsoft Sentinel Responder | Sentinel workspace | Lets the playbook read and update incidents, add comments, and change status/owner as designed. Use Microsoft Sentinel Contributor only if the workflow must manage Sentinel configuration. |
| Logic App managed identity | Key Vault Secrets User | Key Vault | Needed only when ServiceNow credentials, OAuth client secrets, or certificates are read from Key Vault. |
| Azure Function or custom sync managed identity | Microsoft Sentinel Responder | Sentinel workspace | Needed if custom code updates Sentinel incidents through the SecurityInsights Incidents REST API. |
| Azure Function or external ingestion app identity | Monitoring Metrics Publisher | Data collection rule | Required to send ServiceNow data to the Azure Monitor Logs Ingestion API. |
| Azure Function or custom sync managed identity | Log Analytics Reader | Log Analytics workspace | Needed only when the sync code queries existing Sentinel or custom log data. |

### Microsoft Sentinel Service Account

Microsoft Sentinel uses a service account to run incident-triggered playbooks manually or from automation rules. Grant this service account the Microsoft Sentinel Automation Contributor role on the resource group that contains the playbooks.

The simplest path is:

```text
Microsoft Sentinel -> Settings -> Settings -> Playbook permissions -> Configure permissions
```

Select the resource group that contains the ServiceNow playbooks and apply the permission. If the playbook appears grayed out in an automation rule, this permission is usually missing.

For multitenant or Azure Lighthouse deployments, grant the same role to the Azure Security Insights enterprise application in the tenant where the playbook resource group exists. The Microsoft Sentinel Automation Contributor role definition ID is:

```text
f4c81013-99ee-4d62-a7ee-b3f1f648599a
```

## Identity Design

Use separate identities for each trust boundary.

| Identity | Platform | Recommended design |
| --- | --- | --- |
| Deployment administrator | Microsoft Entra ID user or privileged group | PIM-activated Microsoft Sentinel Contributor plus Logic App Contributor; Owner or User Access Administrator only when assigning roles. |
| Sentinel playbook identity | Azure managed identity | System-assigned managed identity for a single playbook, or user-assigned managed identity for a shared integration identity. |
| ServiceNow integration identity | ServiceNow user, OAuth client, or Entra-backed OIDC system user | Web service access only, custom least-privilege ServiceNow role, no interactive admin account. |
| Logs ingestion identity | Azure managed identity or Entra app registration | Grant Monitoring Metrics Publisher on the DCR. Prefer managed identity for Azure-hosted code; use certificate-based app auth for external runners. |
| Secret storage identity | Azure managed identity | Grant Key Vault Secrets User to read only the ServiceNow connection material required at runtime. |

Do not reuse a human ServiceNow account for automation. Use a named integration identity such as `svc_sentinel_snow` so records, journal entries, and audit logs clearly show the source of changes.

## ServiceNow Dependencies

ServiceNow capabilities vary by licensed product and installed plugins. Confirm these items with the ServiceNow platform owner before building the workflow.

| Dependency | Required for | Notes |
| --- | --- | --- |
| ServiceNow instance URL | All flows | Usually `https://{instance}.service-now.com`. The Microsoft ServiceNow connector has known limitations with non-`service-now.com` domains. |
| Table API | Create, read, update, and query records | Core endpoint family under `/api/now/table/{table}`. |
| OAuth Application Registry | OAuth-based API access | Preferred over basic authentication for custom HTTP integrations. |
| ServiceNow integration user | All ServiceNow API calls | Set `Web service access only` where possible. Assign only the roles and ACLs required for target tables. |
| Incident Management / ITSM | Ticket creation | Required when writing to the `incident` table. |
| Security Incident Response, if licensed | Security case creation | Required when writing to SecOps tables such as `sn_si_incident`. Table names and roles vary by ServiceNow release and application scope. |
| CMDB | Asset enrichment and CI mapping | Required when reading or populating `cmdb_ci` references. |
| ITOM Event Management, if used | Event ingestion or event creation | Required when reading or writing Event Management tables such as `em_event`. |
| Import Set API, optional | Bulk ingestion into ServiceNow | Useful when creating a staging table and transform map rather than writing directly to production tables. |
| Knowledge API plugin `sn_km_api`, optional | Knowledge enrichment | Required only when the workflow queries ServiceNow knowledge articles. |
| Custom fields on ServiceNow tables | Durable correlation | Strongly recommended for idempotency and bidirectional sync. |
| Network allowlist and TLS | All flows | Allow Azure outbound IPs, Logic Apps connector traffic, API Management, or Function outbound IPs as appropriate. Require TLS 1.2 or later. |

### Recommended ServiceNow Custom Fields

Add these fields to the target ServiceNow table, usually `incident` or `sn_si_incident`, to prevent duplicate tickets and support updates.

| Field | Type | Purpose |
| --- | --- | --- |
| `u_sentinel_incident_arm_id` | String | Full Sentinel incident ARM resource ID. Best primary correlation value. |
| `u_sentinel_incident_guid` | String | Sentinel incident name or GUID. Useful for searches and short references. |
| `u_sentinel_workspace` | String | Workspace name or workspace resource ID. |
| `u_sentinel_incident_url` | URL or String | Direct link to the incident in Sentinel or the Defender portal. |
| `u_sentinel_last_sync_time` | Date/time | Last successful update from Sentinel. |
| `u_sentinel_sync_source` | String | Prevents update loops, for example `Sentinel`, `ServiceNow`, or `Manual`. |

If custom fields are not allowed, use the ServiceNow `correlation_id` field for the Sentinel incident ARM ID and `correlation_display` for a human-readable Sentinel incident number or title.

### Least-Privilege ServiceNow Access

Avoid assigning the ServiceNow `admin` role to the integration identity. Create a custom role and ACLs that cover only the required tables and fields.

| ServiceNow table or capability | Minimum access pattern |
| --- | --- |
| `incident` | Create, read, and write selected fields used by the playbook. |
| `sn_si_incident`, if using SecOps | Create, read, and write selected fields, subject to SecOps application roles and ACLs. |
| `sys_user` | Read only, for caller, assignment, and owner mapping. |
| `sys_user_group` | Read only, for assignment group mapping. |
| `cmdb_ci` and related CI tables | Read only, when mapping Sentinel entities to configuration items. |
| `sys_journal_field` or journal fields | Create/read comments or work notes if the workflow writes activity history. |
| `sys_attachment` | Create/read only if the workflow attaches alert evidence or investigation exports. |
| `em_event`, if using Event Management | Read or create according to whether ServiceNow events are ingested into Sentinel or created from Sentinel. |

The built-in `itil` role is often enough for basic incident create/update scenarios, but it can be broader than necessary. Prefer a custom integration role where the ServiceNow governance model supports it.

## Authentication Options

| Option | Where it fits | Pros | Cautions |
| --- | --- | --- | --- |
| ServiceNow OAuth 2.0 client credentials | Custom HTTP actions, Azure Functions, API Management | Good for non-human automation and secret/certificate rotation. | Requires OAuth app registration and ServiceNow-side role/ACL design. |
| Microsoft Entra ID OAuth using certificate | Power Platform and Logic Apps ServiceNow connector scenarios | Shareable connection model and certificate-backed auth. | Requires Entra app registrations, ServiceNow OIDC provider configuration, and user/claim mapping. |
| Microsoft Entra ID OAuth user login | Analyst-owned Power Platform or connector testing | Familiar sign-in experience. | Not ideal for unattended SOC automation because the connection follows a user context. |
| Basic authentication | Simple proof of concept or constrained environments | Fast to test and often works where OAuth setup is blocked. | Use only with a web-service-only integration account, store secrets in Key Vault or managed connector connection storage, and rotate regularly. |

For unattended production playbooks, prefer either the Microsoft ServiceNow connector with a controlled OAuth connection or direct HTTP actions using a ServiceNow OAuth client. Use a managed identity for all Microsoft-side calls.

## API Endpoints

### ServiceNow Endpoints

Replace `{instance}` with the ServiceNow instance name.

| Purpose | Method and endpoint |
| --- | --- |
| OAuth token | `POST https://{instance}.service-now.com/oauth_token.do` |
| Query records | `GET https://{instance}.service-now.com/api/now/table/{table}?sysparm_query={query}&sysparm_limit={limit}&sysparm_fields={fields}` |
| Create incident | `POST https://{instance}.service-now.com/api/now/table/incident` |
| Update incident | `PATCH https://{instance}.service-now.com/api/now/table/incident/{sys_id}` |
| Read users | `GET https://{instance}.service-now.com/api/now/table/sys_user?sysparm_query={query}` |
| Read groups | `GET https://{instance}.service-now.com/api/now/table/sys_user_group?sysparm_query={query}` |
| Read CMDB CIs | `GET https://{instance}.service-now.com/api/now/table/cmdb_ci?sysparm_query={query}` |
| Create attachment | `POST https://{instance}.service-now.com/api/now/attachment/file?table_name={table}&table_sys_id={sys_id}&file_name={fileName}` |
| Query attachments | `GET https://{instance}.service-now.com/api/now/attachment?sysparm_query=table_name={table}^table_sys_id={sys_id}` |
| Import set, optional | `POST https://{instance}.service-now.com/api/now/import/{staging_table}` |

Common ServiceNow query parameters:

| Parameter | Purpose |
| --- | --- |
| `sysparm_query` | Encoded ServiceNow query, for example `correlation_id={urlEncodedIncidentId}` or `sys_updated_on>{watermark}`. |
| `sysparm_fields` | Comma-separated list of fields to return. Use this to reduce payload size. |
| `sysparm_limit` | Maximum records returned. Use paging for large syncs. |
| `sysparm_offset` | Offset for paging. |
| `sysparm_display_value` | Returns display values for references when needed. |
| `sysparm_exclude_reference_link` | Removes reference links from response payloads. |

### Microsoft Sentinel And Azure Endpoints

| Purpose | Method and endpoint |
| --- | --- |
| List Sentinel incidents | `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents?api-version=2025-09-01` |
| Get or update a Sentinel incident | `GET` or `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}?api-version=2025-09-01` |
| List incident alerts | `POST https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}/alerts?api-version=2025-09-01` |
| List incident entities | `POST https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}/entities?api-version=2025-09-01` |
| Add incident comment | `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents/{incidentId}/comments/{commentId}?api-version=2025-09-01` |
| Manage data connectors | `GET` or `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/dataConnectors/{connectorId}?api-version=2025-09-01` |
| Manage automation rules | `GET` or `PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/automationRules/{automationRuleId}?api-version=2025-09-01` |
| Logs Ingestion API | `POST {dcrOrDceEndpoint}/dataCollectionRules/{dcrImmutableId}/streams/{streamName}?api-version=2023-01-01` |
| Log Analytics query API, optional | `POST https://api.loganalytics.io/v1/workspaces/{workspaceId}/query` |

Token audiences for Microsoft endpoints:

| Cloud | ARM and Sentinel scope | Logs ingestion scope |
| --- | --- | --- |
| Azure public | `https://management.azure.com/.default` | `https://monitor.azure.com/.default` |
| Azure Government | `https://management.usgovcloudapi.net/.default` | `https://monitor.azure.us/.default` |
| Azure China | `https://management.chinacloudapi.cn/.default` | `https://monitor.azure.cn/.default` |

## Sentinel To ServiceNow Ticketing Workflow

This is the primary integration most SOCs need.

### 1. Prepare ServiceNow

1. Create a dedicated integration user such as `svc_sentinel_snow`.
2. Mark the account as web-service-only if your ServiceNow policy supports it.
3. Assign a custom integration role or a tightly scoped role set for the target table.
4. Configure OAuth in ServiceNow Application Registry, or prepare the connector authentication method selected for Logic Apps.
5. Add custom correlation fields to the target table, or approve use of `correlation_id`.
6. Confirm the target table: `incident`, `sn_si_incident`, or another table chosen by the ServiceNow process owner.
7. Confirm assignment group, category, subcategory, impact, urgency, and priority mappings.

### 2. Prepare Azure And Sentinel

1. Create a resource group for Sentinel playbooks.
2. Create the Logic App playbook. Use Consumption for simple workflows, or Standard when you need VNET integration, private endpoints, deployment slots, or multiple workflows in one app.
3. Enable a managed identity on the Logic App.
4. Grant the Logic App managed identity Microsoft Sentinel Responder on the Sentinel workspace.
5. Grant Key Vault Secrets User to the Logic App identity if secrets are read from Key Vault.
6. Configure the ServiceNow connector connection or direct HTTP OAuth flow.
7. Grant Microsoft Sentinel Automation Contributor to the Sentinel service account on the playbook resource group.

Example role assignments:

```powershell
$workspaceScope = "/subscriptions/<subscription-id>/resourceGroups/<sentinel-rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"
$dcrScope = "/subscriptions/<subscription-id>/resourceGroups/<monitor-rg>/providers/Microsoft.Insights/dataCollectionRules/<dcr-name>"
$keyVaultScope = "/subscriptions/<subscription-id>/resourceGroups/<security-rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"

New-AzRoleAssignment `
  -ObjectId "<logic-app-managed-identity-principal-id>" `
  -RoleDefinitionName "Microsoft Sentinel Responder" `
  -Scope $workspaceScope

New-AzRoleAssignment `
  -ObjectId "<logic-app-managed-identity-principal-id>" `
  -RoleDefinitionName "Key Vault Secrets User" `
  -Scope $keyVaultScope

New-AzRoleAssignment `
  -ObjectId "<ingestion-managed-identity-or-app-principal-id>" `
  -RoleDefinitionName "Monitoring Metrics Publisher" `
  -Scope $dcrScope
```

Assign the Microsoft Sentinel Automation Contributor role to the Sentinel service account from the Sentinel playbook permissions blade unless you are automating that step through Azure Lighthouse or ARM.

### 3. Build The Playbook

Use this control flow:

1. Trigger: Microsoft Sentinel incident created or updated.
2. Initialize a correlation key with the Sentinel incident ARM ID.
3. Query ServiceNow for an existing record by custom field or `correlation_id`.
4. If no matching record exists, create a ServiceNow record.
5. If a matching record exists, update only the fields owned by Sentinel.
6. Add a Sentinel incident comment with the ServiceNow number, `sys_id`, and URL.
7. Optionally add a Sentinel label such as `ServiceNow` and `SNOW:<number>`.
8. Stop if the update originated from ServiceNow to prevent sync loops.

ServiceNow lookup example:

```http
GET https://{instance}.service-now.com/api/now/table/incident?sysparm_query=correlation_id={urlEncodedSentinelIncidentArmId}&sysparm_fields=sys_id,number,state,priority,correlation_id,sys_updated_on&sysparm_limit=1
Authorization: Bearer <servicenow-token>
Accept: application/json
```

ServiceNow create example:

```http
POST https://{instance}.service-now.com/api/now/table/incident
Authorization: Bearer <servicenow-token>
Content-Type: application/json

{
  "short_description": "Sentinel: <incident title>",
  "description": "Created from Microsoft Sentinel incident <incident ARM ID>\n\n<summary>",
  "category": "Security",
  "subcategory": "SIEM",
  "impact": "2",
  "urgency": "2",
  "assignment_group": "<serviceNow assignment group sys_id>",
  "correlation_id": "<sentinel incident ARM ID>",
  "correlation_display": "Microsoft Sentinel",
  "u_sentinel_incident_arm_id": "<sentinel incident ARM ID>",
  "u_sentinel_incident_url": "<sentinel incident URL>",
  "u_sentinel_workspace": "<workspace name>"
}
```

ServiceNow update example:

```http
PATCH https://{instance}.service-now.com/api/now/table/incident/{sys_id}
Authorization: Bearer <servicenow-token>
Content-Type: application/json

{
  "work_notes": "Microsoft Sentinel updated severity to High. Incident: <incident URL>",
  "impact": "1",
  "urgency": "2",
  "u_sentinel_last_sync_time": "<utc timestamp>",
  "u_sentinel_sync_source": "Sentinel"
}
```

### 4. Map Severity And Priority

ServiceNow state, impact, urgency, and priority values are configurable. Validate the exact numeric choices in your instance before production use.

| Sentinel severity | Suggested ServiceNow impact | Suggested ServiceNow urgency | Suggested priority |
| --- | --- | --- | --- |
| High | 1 | 1 or 2 | P1 or P2 |
| Medium | 2 | 2 | P3 |
| Low | 3 | 2 or 3 | P4 |
| Informational | 3 | 3 | P5 |

Use assignment group routing rules in ServiceNow when possible instead of hardcoding every destination group in the playbook.

### 5. Map Status And Closure

| Sentinel status | ServiceNow state pattern | Notes |
| --- | --- | --- |
| New | New | Create ticket or reopen only if ServiceNow policy allows it. |
| Active | In Progress | Add work notes rather than overwriting analyst-owned fields. |
| Closed | Resolved or Closed | Require a classification and closure reason mapping. |

For closure, decide which system wins:

- Sentinel-owned closure: closing the Sentinel incident resolves the ServiceNow incident.
- ServiceNow-owned closure: resolving the ServiceNow ticket closes the Sentinel incident.
- Dual approval: one system adds a comment and a queue asks an analyst to confirm closure in the other system.

## ServiceNow To Sentinel Log Ingestion

Use this path when Sentinel needs ServiceNow data for analytics, enrichment, or hunting. Do not write custom data into Sentinel system tables such as `SecurityIncident`. Use custom tables with the `_CL` suffix or supported Azure Monitor tables.

### 1. Create Custom Tables

Common table names:

| Table | Purpose |
| --- | --- |
| `ServiceNowIncident_CL` | ServiceNow incident ticket state, assignment, priority, and correlation data. |
| `ServiceNowSecurityIncident_CL` | ServiceNow SecOps security incident records, if licensed. |
| `ServiceNowChange_CL` | Change records for change-risk correlation with alerts. |
| `ServiceNowCmdbCi_CL` | CMDB asset context used for entity enrichment. |
| `ServiceNowEvent_CL` | ITOM event records, if Event Management is in scope. |

Recommended base columns:

| Column | Type | Notes |
| --- | --- | --- |
| `TimeGenerated` | datetime | Use ServiceNow `sys_updated_on` or event timestamp. |
| `SysId` | string | ServiceNow `sys_id`. |
| `Number` | string | Human-readable ticket number. |
| `TableName` | string | Source table, for example `incident`. |
| `State` | string | State display value or normalized state. |
| `Priority` | string | Priority display value. |
| `AssignmentGroup` | string | Display value or `sys_id`. |
| `AssignedTo` | string | Display value or `sys_id`. |
| `CorrelationId` | string | Sentinel incident ARM ID or external correlation value. |
| `ShortDescription` | string | Short description. |
| `RawRecord` | dynamic | Original ServiceNow JSON for troubleshooting and future parsing. |

### 2. Create A DCR And Assign Ingestion Permission

Create a Data Collection Rule with `kind: Direct`, a stream such as `Custom-ServiceNowIncident`, and a destination table such as `ServiceNowIncident_CL`. Then grant the ingestion identity Monitoring Metrics Publisher on the DCR.

Logs Ingestion API request format:

```http
POST {dcrOrDceEndpoint}/dataCollectionRules/{dcrImmutableId}/streams/Custom-ServiceNowIncident?api-version=2023-01-01
Authorization: Bearer <monitor-token>
Content-Type: application/json

[
  {
    "TimeGenerated": "2026-06-11T15:30:00Z",
    "SysId": "<servicenow sys_id>",
    "Number": "INC0012345",
    "TableName": "incident",
    "State": "In Progress",
    "Priority": "2 - High",
    "AssignmentGroup": "Security Operations",
    "AssignedTo": "Analyst Name",
    "CorrelationId": "<sentinel incident ARM ID>",
    "ShortDescription": "Example ServiceNow ticket",
    "RawRecord": { "source": "original ServiceNow JSON" }
  }
]
```

A successful Logs Ingestion API write commonly returns HTTP `204 No Content`.

### 3. Pull ServiceNow Changes With A Watermark

Query only records changed since the last successful run:

```http
GET https://{instance}.service-now.com/api/now/table/incident?sysparm_query=sys_updated_on>{watermark}^ORDERBYsys_updated_on&sysparm_fields=sys_id,number,state,priority,assignment_group,assigned_to,correlation_id,short_description,sys_updated_on&sysparm_limit=1000
Authorization: Bearer <servicenow-token>
Accept: application/json
```

Store the watermark outside the workflow run state, for example in Azure Table Storage, Key Vault, Blob Storage, or a durable Function state store. Update the watermark only after the records are successfully ingested.

### 4. Verify Ingestion In Sentinel

```kusto
ServiceNowIncident_CL
| summarize Count = count(), Latest = max(TimeGenerated) by State, Priority
| order by Latest desc
```

Find ServiceNow-linked Sentinel incidents:

```kusto
SecurityIncident
| where Labels has "ServiceNow" or AdditionalData has "ServiceNow"
| project TimeGenerated, IncidentNumber, Title, Severity, Status, Owner, Labels
| order by TimeGenerated desc
```

## Bidirectional Sync Pattern

Bidirectional sync is useful, but it adds complexity. Build it only after the one-way Sentinel-to-ServiceNow workflow is stable.

Required controls:

- A durable correlation ID in both systems.
- A sync source marker, such as `u_sentinel_sync_source`, to prevent loops.
- A last-successful-watermark store.
- Field ownership rules that say which system controls each field.
- Conflict behavior for simultaneous analyst edits.
- A retry and dead-letter strategy.

Recommended field ownership:

| Field | Owning system | Behavior |
| --- | --- | --- |
| Ticket number and `sys_id` | ServiceNow | Write back to Sentinel comment or label. |
| Sentinel incident ARM ID | Sentinel | Write once to ServiceNow correlation field. |
| Severity | Sentinel | Map to ServiceNow impact/urgency unless ServiceNow process owns priority. |
| Assignment group | ServiceNow | Let ServiceNow routing own the ticket assignment group. |
| Incident status | Decide explicitly | Avoid two-way closure until both teams agree on closure policy. |
| Work notes/comments | Shared | Prefix comments with source system and avoid reimporting the same note. |

## Network And Cloud Considerations

| Area | Guidance |
| --- | --- |
| Public Azure | Logic Apps, Azure Functions, ServiceNow connector, ARM, and Logs Ingestion API are the standard path. |
| Azure Government | Use Azure Government ARM and Monitor token audiences. Validate Logic Apps connector availability and ServiceNow domain constraints. |
| DoD | The Microsoft ServiceNow managed connector is not available in Logic Apps DoD regions. Use direct HTTPS from an approved Azure service if permitted. |
| Private networking | Use Logic Apps Standard with VNET integration or Azure Functions Premium when outbound network control is required. |
| IP allowlisting | Allow the outbound IPs of the Logic App or Function, or place API Management/NAT Gateway in front of outbound calls where architecture allows. |
| Custom ServiceNow domains | The Microsoft ServiceNow connector has known limitations with non-`service-now.com` instance URLs. Direct HTTP integration may be required. |
| TLS | Require TLS 1.2 or later for ServiceNow and Azure Monitor ingestion. |

## Security Controls

- Use managed identities for Microsoft-side authentication.
- Store ServiceNow client secrets, certificates, and basic-auth passwords in Key Vault or managed connector secure storage.
- Prefer OAuth or certificate-based authentication over basic authentication.
- Restrict the ServiceNow integration user to required tables and fields.
- Use ServiceNow ACLs and web-service-only accounts.
- Do not place ServiceNow credentials in Logic App run history, comments, or Sentinel incident fields.
- Set Logic App secure inputs and secure outputs on actions that handle tokens or secrets.
- Enable diagnostic logs for Logic Apps and send them to Log Analytics.
- Add retry policies for HTTP `429`, `500`, `502`, `503`, and `504` responses.
- Use idempotency keys and correlation IDs to avoid duplicate tickets.
- Review data classification before ingesting ServiceNow descriptions, comments, or attachments into Sentinel because they can contain personal data or sensitive investigation details.

## Validation Checklist

### ServiceNow Validation

- Confirm the integration identity can authenticate without interactive login.
- Use ServiceNow REST API Explorer or an approved API client to query the target table.
- Confirm the integration identity can create and update only the intended fields.
- Confirm custom fields are visible through the Table API.
- Confirm the `correlation_id` or custom Sentinel correlation field is searchable.
- Confirm any IP allowlist includes the workflow outbound path.

### Azure And Sentinel Validation

- Confirm the Logic App managed identity has Microsoft Sentinel Responder on the workspace.
- Confirm the Sentinel service account has Microsoft Sentinel Automation Contributor on the playbook resource group.
- Confirm the analyst testing manual runs has Microsoft Sentinel Playbook Operator on the playbook resource group.
- Confirm the ServiceNow connection works from Logic Apps.
- Trigger a test Sentinel incident and verify one ServiceNow ticket is created.
- Trigger the same incident update twice and verify the playbook updates the existing ticket instead of creating duplicates.
- If using Logs Ingestion API, confirm the ingestion identity has Monitoring Metrics Publisher on the DCR.
- Confirm ServiceNow records appear in the custom table with expected schema and timestamps.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Playbook is grayed out in Sentinel automation rule | Sentinel service account lacks Microsoft Sentinel Automation Contributor on the playbook resource group. | Configure playbook permissions from Sentinel settings. |
| User cannot manually run playbook | Missing Microsoft Sentinel Playbook Operator on the playbook resource group or Microsoft Sentinel Responder on the incident. | Assign the missing operator/responder roles. |
| Logic App cannot update Sentinel incident | Logic App managed identity lacks Microsoft Sentinel Responder on the workspace. | Assign Microsoft Sentinel Responder to the managed identity. |
| ServiceNow returns `401` | Bad token, expired secret, wrong auth type, or OAuth app mismatch. | Recreate token, rotate secret/certificate, validate OAuth app registry. |
| ServiceNow returns `403` | Integration user lacks table/field ACLs or required role. | Review ACLs and role grants for target table and fields. |
| ServiceNow returns `404` or invalid table | Table name is wrong or licensed plugin is not active. | Confirm target table and plugin with ServiceNow admin. |
| ServiceNow connector fails with custom domain | Managed connector limitation with non-`service-now.com` domains. | Use basic auth where supported or direct HTTP integration through the approved domain. |
| Duplicate ServiceNow tickets | Missing or inconsistent correlation key. | Search by Sentinel incident ARM ID before create; write correlation field on first create. |
| Logs Ingestion API returns `403` | Ingestion identity lacks Monitoring Metrics Publisher on DCR. | Assign Monitoring Metrics Publisher at the DCR scope. |
| Logs do not appear in Sentinel | DCR stream/table mismatch, transformation error, or timestamp/schema issue. | Check DCR stream name, output table, transform KQL, and ingestion response. |
| Updates loop between systems | No sync source marker or watermark. | Add `u_sentinel_sync_source`, track processed notes/updates, and ignore self-originated changes. |

## Production Readiness Checklist

- Document field mappings and ownership rules.
- Document ServiceNow table ACLs and roles assigned to the integration identity.
- Configure Key Vault rotation for ServiceNow secrets or certificates.
- Configure retry, timeout, and dead-letter behavior.
- Enable Logic App diagnostics and alert on failed runs.
- Create a rollback plan to disable automation rules without deleting playbooks.
- Create a test incident procedure for monthly validation.
- Validate ServiceNow API rate limits and the Microsoft connector limit before bulk sync.
- Confirm Sentinel ingestion cost and retention for ServiceNow custom tables.
- Confirm the integration path for Azure Government, DoD, or custom ServiceNow domain requirements.

## References

- [Microsoft Sentinel data connectors reference](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference)
- [Create and manage Microsoft Sentinel playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automation/create-playbooks)
- [Automate and run Microsoft Sentinel playbooks](https://learn.microsoft.com/en-us/azure/sentinel/automation/run-playbooks)
- [Microsoft Sentinel Incidents REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents)
- [Microsoft Sentinel Data Connectors REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/data-connectors)
- [Azure Monitor Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [ServiceNow connector reference for Logic Apps and Power Platform](https://learn.microsoft.com/en-us/connectors/service-now/)
