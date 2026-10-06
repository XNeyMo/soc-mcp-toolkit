# Required permissions

Each server authenticates with its **own** least-privilege credential, so a secret leaked or
misused in one domain does not grant access to the others. This page lists the exact permissions
each server needs. Grant only what you will use — if you disable some tools, you can drop the
permissions that back them.

- **Microsoft 365 servers** (`mcp-defender`, `mcp-identity`, `mcp-exchange`, `mcp-intune`,
  `mcp-audit`): each has its own **app registration** in Entra ID with application permissions,
  consented by an administrator. The `User.Read` *delegated* permission is only there so the app
  registration has a sign-in owner; the servers run app-only.
- **`mcp-cortex`**: a Cortex XDR **Advanced API Key** with assigned roles — no Entra permissions.
- **`mcp-banner`**: an OAuth2 **client_credentials** client against the ETHOS/ORDS token endpoint —
  no Entra/Graph permissions.
- **`mcp-vault`, `mcp-pentesting`**: **SSH** only — no API permissions at all.

Legend: **App** = Application permission, **Del** = Delegated. All Application permissions below
require admin consent.

---

## mcp-defender — Microsoft Defender XDR / MDE

This server talks to four different resources/audiences (see the per-audience note in
`mcp-defender/server.py`), so the permissions span three APIs.

**Microsoft Graph**
| Permission | Type | Used for |
|---|---|---|
| `SecurityIncident.ReadWrite.All` | App | `update_incident` resolving comment |
| `SecurityAlert.ReadWrite.All` | App | alerts via `/security/alerts_v2`, alert comments |
| `User.Read` | Del | app-registration sign-in owner |

**Microsoft Threat Protection**
| Permission | Type | Used for |
|---|---|---|
| `AdvancedHunting.Read.All` | App | advanced hunting (KQL) |
| `Incident.ReadWrite.All` | App | incidents |

**WindowsDefenderATP**
| Permission | Type | Used for |
|---|---|---|
| `AdvancedQuery.Read.All` | App | advanced query fallback |
| `Alert.ReadWrite.All` | App | MDE-native alerts |
| `File.Read.All` | App | file / hash profiles |
| `Ip.Read.All` | App | IP profiles |
| `Machine.CollectForensics` | App | collect investigation package |
| `Machine.Isolate` | App | isolate / unisolate device |
| `Machine.Read.All` | App | device info |
| `Machine.Scan` | App | antivirus scan |
| `Machine.StopAndQuarantine` | App | stop & quarantine file |
| `Ti.ReadWrite.All` | App | IOC indicators |
| `Url.Read.All` | App | URL profiles |
| `User.Read.All` | App | MDE user view |

---

## mcp-identity — Microsoft Entra ID

**Microsoft Graph**
| Permission | Type | Used for |
|---|---|---|
| `AuditLog.Read.All` | App | sign-in & audit history |
| `Device.Read.All` | App | user devices |
| `Directory.Read.All` | App | directory reads (users, groups, roles) |
| `GroupMember.ReadWrite.All` | App | group membership changes (e.g. MFA enforcement group) |
| `IdentityRiskEvent.Read.All` | App | Identity Protection risk detections |
| `IdentityRiskyUser.ReadWrite.All` | App | risky users (read / dismiss) |
| `LicenseAssignment.ReadWrite.All` | App | license assign / remove |
| `Policy.Read.All` | App | Conditional Access / auth method policy reads |
| `Policy.ReadWrite.AuthenticationMethod` | App | authentication method policy changes |
| `RoleManagement.ReadWrite.Directory` | App | directory roles / PIM |
| `User.ReadWrite.All` | App | user investigation, block / unblock, reset password |
| `User.RevokeSessions.All` | App | revoke sign-in sessions |
| `UserAuthenticationMethod.ReadWrite.All` | App | MFA methods (read / remove / reset) |
| `User.Read` | Del | app-registration sign-in owner |

---

## mcp-exchange — Exchange Online

**Microsoft Graph**
| Permission | Type | Used for |
|---|---|---|
| `Mail.ReadWrite` | App | read / move / delete mail in all mailboxes |
| `MailboxSettings.ReadWrite` | App | forwarding, auto-reply, mailbox rules |
| `ThreatHunting.Read.All` | App | email hunting queries |
| `User.ReadBasic.All` | App | resolve mailbox users |
| `AuditLogsQuery.Read.All` | App | unified audit log queries *(optional; only if enabled)* |
| `Reports.Read.All` | App | email activity reports *(optional)* |
| `User.Read` | Del | app-registration sign-in owner |

**Office 365 Exchange Online**
| Permission | Type | Used for |
|---|---|---|
| `Exchange.ManageAsApp` | App | app-only Exchange management (transport rules, connectors, mailbox rules) |
| `ReportingWebService.Read.All` | App | legacy reporting *(optional; retired tenant-wide by Microsoft in many tenants)* |

> **Quarantine note:** the quarantine cmdlets run against a different host
> (`ps.compliance.protection.outlook.com`) and additionally require an **Exchange Application
> RBAC** role assignment on the app's service principal — the `Transport Hygiene` role — which is
> *not* an Entra permission and is assigned via PowerShell
> (`New-ManagementRoleAssignment -Role "Transport Hygiene" -App <appId>`). Without it the host
> returns `500 Could not find the organization container`.

---

## mcp-audit — Microsoft Purview / Audit (read-only)

**Microsoft Graph**
| Permission | Type | Used for |
|---|---|---|
| `AuditLog.Read.All` | App | unified audit log |
| `Directory.Read.All` | App | directory reads |
| `eDiscovery.Read.All` | App | eDiscovery cases |
| `InformationProtectionPolicy.Read.All` | App | sensitivity labels & policies |
| `User.Read` | Del | app-registration sign-in owner |

---

## mcp-intune — Microsoft Intune

**Microsoft Graph**
| Permission | Type | Used for |
|---|---|---|
| `DeviceManagementManagedDevices.Read.All` | App | managed-device inventory and posture |

*(Read-only. Add it to the app registration the same way as the other Graph servers.)*

---

## mcp-cortex — Palo Alto Cortex XDR

No Entra permissions. Authentication is a **Cortex XDR Advanced API Key** (security level:
**Advanced**, the nonce + timestamp + SHA-256 scheme). The key is shared by the team and carries
these assigned roles:

| Role | Why |
|---|---|
| `Investigation Admin` | manage incidents / alerts, run response actions |
| `Responder` | endpoint isolation, file quarantine, scans |
| `Viewer` | read incidents, alerts, endpoints |

Create it under **Settings → Configurations → API Keys**; `CORTEX_FQDN` and `CORTEX_REGION` are
shown in the example URL at creation time.

---

## mcp-banner — Ellucian Banner (ETHOS Integration)

No Entra/Graph permissions. Authentication is **OAuth2 client_credentials** (client id/secret sent
as a Basic Auth header to `BANNER_TOKEN_URL`, no scope — the standard Oracle ORDS scheme). The data
the client can read is governed by whatever your ETHOS/ORDS integration authorizes for that client;
this server only performs read calls.

---

## mcp-vault — team audit vault (SSH)

No API permissions. Each analyst has their own SSH key, pinned in the vault account's
`authorized_keys` to a **forced command** that fixes their identity server-side (see
[ARCHITECTURE.md](ARCHITECTURE.md)). Authorization is simply "your key is accepted by the vault
host." The vault git repo and audit log are written by the server-side agent, not the client.

---

## mcp-pentesting — authorized testing lab (SSH)

No API permissions. Authentication is an SSH key to the Kali host (`PENTEST_SSH_HOST`,
`PENTEST_SSH_USER`, `PENTEST_SSH_KEY`). The meaningful authorization boundary is **your own
written authorization to test the target** — the server enforces none of its own.
