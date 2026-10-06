# Bulk helper scripts (`scripts/`)

Besides the MCP tools (synchronous: one call → one response), two servers ship a `scripts/` folder
of standalone **PowerShell** helpers for **bulk / CSV operations** that a single MCP call can't do
well — scanning the whole tenant, or remediating/purging a long list of accounts or emails. Those
run for minutes to hours, so doing them one MCP call at a time would be impractical and would block
the conversation.

## How the agent uses them (important)

These scripts are **not MCP tools** and are **not** invoked over the MCP protocol. The AI agent
runs them **out-of-band, via the shell, in the background**, and reports back when they finish —
never synchronously. Each script:

- authenticates with the **same app registration and environment variables** as its server
  (`AZURE_TENANT_ID` + `IDENTITY_CLIENT_ID/_SECRET` or `EXCHANGE_CLIENT_ID/_SECRET`) — no separate
  or embedded credentials;
- has its own **preview-first safety flow** (`-WhatIf` / no `-Execute`): it changes nothing until
  you pass the explicit execute flag, and the destructive ones also require a typed confirmation;
- prints incremental progress meant for a terminal, not a one-shot MCP response.

The same "preview → explicit human confirmation → execute" rule the MCP servers enforce applies
here too, even when the script runs in the background.

## `mcp-identity/scripts/`

| Script | Type | What it does |
|---|---|---|
| `get_mfa_group_status.ps1` | read-only | Reports each user's **actual** MFA methods (email / phone / Authenticator device), scoped by an Entra group or a CSV email column. |
| `get_signin_activity_status.ps1` | read-only | Latest sign-in attempts per user (group or CSV), with real status detail from `/auditLogs/signIns`. |
| `get_signin_errors_status.ps1` | read-only | Counts and details non-successful sign-ins per user over the last *N* days (failures + interruptions). |
| `get_users_11_digits.ps1` | read-only | Finds users whose MFA phone number has an anomalous local length (a data-quality check). |
| `Revoke-BulkUserSessions.ps1` | **destructive** | Revokes sign-in sessions (refresh tokens) for a bulk list of accounts from a CSV. Preview by default; needs `-Execute` **and** a typed confirmation. |
| `remediate-users.ps1` | **destructive** | Full remediation of compromised sender accounts from a CSV: reset password (force change), revoke sessions, force MFA re-registration, and enforce MFA via the Conditional Access group (`SG-MFA-Enforced`). Preview by default. |

## `mcp-exchange/scripts/`

| Script | Type | What it does |
|---|---|---|
| `get-emails-2.ps1` | read-only | Runs an Advanced Hunting query for an **exact** subject, classifies sender/recipient as internal/external, and exports the result to CSV (the input for the purge below). |
| `delete-emails-parallel.ps1` | **destructive / irreversible** | Parallel hard-delete (`permanentDelete`) of the internal emails listed in the CSV from `get-emails-2.ps1`. Simulation (`-WhatIf $true`) by default; internal mailboxes only. Requires PowerShell 7+. |

## Typical incident workflow

```
get-emails-2.ps1   ──►  review the CSV  ──►  delete-emails-parallel.ps1 (-WhatIf first, then execute)
(hunt the campaign)      (human decision)     (purge, after explicit confirmation)
```

## Permissions

The scripts use the **same** application permissions as their server — see
[PERMISSIONS.md](PERMISSIONS.md) for `mcp-identity` and `mcp-exchange`. No script requires or
embeds any additional or standalone secret.
