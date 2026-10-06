<!-- Thanks for contributing! Keep PRs scoped to one connector/concern. -->

## What this changes
<!-- New connector? Extended server? Fix? One or two sentences. -->

## Type
- [ ] New connector (new `mcp-<domain>` server)
- [ ] New tool on an existing server
- [ ] Fix / hardening
- [ ] Docs

## Checklist
- [ ] No secrets or internal identifiers committed (ran a repo-wide search; it's clean)
- [ ] All values are placeholders; credentials read from environment variables
- [ ] State-changing tools use the two-step `confirmed` → preview → execute pattern
- [ ] Handler wrapped with `@audited(...)` (and `@require_vault` unless justified below)
- [ ] `python -m py_compile` passes
- [ ] Updated the README server table and `docs/PERMISSIONS.md` (if permissions changed)
- [ ] Registered env vars + `.claude.json` entry in the installer (new connector)

## Tested against
<!-- What environment did you verify this on? DO NOT paste real data, tenant IDs, or secrets. -->

## Notes for reviewers
<!-- Anything unusual? If you skipped @require_vault, explain why here. -->
