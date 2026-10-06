# Roadmap & wanted connectors

The vision: **one AI agent that can reach every tool a SOC uses and correlate an incident across
all of them.** The toolkit already covers Microsoft 365, Cortex XDR, an SIS/HR source, a testing
lab and an audit vault — but a SOC's stack is much bigger. This is where the community comes in.

If you run one of the platforms below (or any other security tool with an API), **building its
connector is the single most valuable thing you can contribute.** Each one is a small, self-
contained MCP server — see [ADDING-A-CONNECTOR.md](ADDING-A-CONNECTOR.md).

## Priority — committed direction

- [ ] **Check Point Harmony Endpoint** — EDR correlation alongside Defender and Cortex (device,
  process, and detection lookups; isolate/scan actions).
- [ ] **Check Point Harmony Email & Collaboration** — email-security signal correlation alongside
  Exchange Online (detections, quarantine, click-time protection events).

## Wanted connectors (great contributions)

**Endpoint / XDR**
- [ ] CrowdStrike Falcon
- [ ] SentinelOne
- [ ] Trellix / Tanium

**SIEM / SOAR / log**
- [ ] Microsoft Sentinel (Log Analytics / incidents)
- [ ] Splunk
- [ ] Elastic Security
- [ ] Google SecOps (Chronicle)

**Identity / access**
- [ ] Okta
- [ ] Google Workspace (admin + alert center)
- [ ] Duo / Ping

**Cloud**
- [ ] AWS (GuardDuty, CloudTrail, IAM)
- [ ] Google Cloud (SCC)
- [ ] Azure (Defender for Cloud, Resource Graph)

**Network / firewall**
- [ ] Palo Alto NGFW / Panorama (incl. the EDL step `mcp-cortex` can't automate today)
- [ ] Fortinet FortiGate
- [ ] Cisco (Umbrella / Secure)

**Threat intelligence**
- [ ] VirusTotal
- [ ] AbuseIPDB
- [ ] Shodan / Censys
- [ ] MISP
- [ ] AlienVault OTX

**Ticketing / collaboration / notification**
- [ ] Jira / ServiceNow (case sync)
- [ ] Slack / Microsoft Teams (notify, escalate)
- [ ] PagerDuty / Opsgenie

**Email / web**
- [ ] Proofpoint
- [ ] Mimecast
- [ ] Cloudflare / Zscaler

## Other ways to help

- **Harden existing servers** — add tests, improve error handling, tighten input validation.
- **Improve correlation** — contribute a `docs/` playbook showing how to chain servers for a
  specific incident type (BEC, ransomware, impossible-travel, token theft).
- **Docs & onboarding** — clarify setup, permissions, or this very roadmap.
- **Shared library** — new reusable auth/HTTP patterns in `shared/` that many connectors can use.

## Good first issues

- Add a read-only `get_*` tool to an existing server for an endpoint it doesn't cover yet.
- Add a missing permission mapping to [PERMISSIONS.md](PERMISSIONS.md).
- Wire a new connector's env-var prompts into the installer.

## How to claim something

Open an issue (use the **New connector proposal** template) saying which platform you're taking,
or comment on an existing one. Small, focused PRs merge fastest. See
[CONTRIBUTING.md](../CONTRIBUTING.md).

> Boxes above are **wishlist**, not commitments. Anyone can pick up anything.
