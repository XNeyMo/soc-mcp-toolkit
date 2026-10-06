# Security Policy

## Scope and intended use

The SOC MCP Toolkit is a **defensive security operations** toolkit plus an **authorized**
security-testing module (`mcp-pentesting`). It is intended to be run by a security team against:

- cloud tenants and systems **your organization owns**, and
- targets you are **explicitly authorized, in writing, to test**.

You are solely responsible for operating it lawfully and within the bounds of your authorization.
The offensive-testing module places no target restrictions of its own — that control is yours.

## No secrets in this repository

This project ships with **placeholder** hosts, domains, tenant IDs, group IDs, and example
accounts only. All credentials (app registration client IDs/secrets, API keys, SSH keys) must be
supplied at runtime via environment variables. Never commit real secrets.

If you fork or deploy this toolkit, double-check that your own configuration (`.env`, host MCP
config, SSH keys) stays out of version control. A `.gitignore` is provided as a starting point.

## Reporting a vulnerability

If you find a security issue in this code, please open a private security advisory on the
repository (or email the maintainers listed there) rather than filing a public issue. Provide steps
to reproduce and the affected server/file. We aim to acknowledge reports promptly.

## Hardening notes

- Each MCP server runs locally and authenticates with least-privilege app registrations — grant
  only the API permissions each server documents in its `REQUIRED PERMISSIONS` block.
- State-changing tools are gated behind an explicit two-step confirmation and are audited.
- The `require_vault` audit gate is **enabled by default**: no tool on any operational server runs
  unless the team audit vault (`claudian`) is reachable and writable first, so nothing happens
  without an audit trail. Keep it on in production; only disable it (comment out `@require_vault`)
  for a vault-less lab. See the README "Audit gate" section.
