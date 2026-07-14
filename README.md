# CVE Fix Automation (LLM-assisted)

A human-in-the-loop toolkit that drives ODP component CVEs (tracked as OSV Jira
tickets) to a correct, defensible resolution — **FIX** (bump the vulnerable
library, build, raise a PR), **CLOSE** (already fixed upstream/on-branch), or
**EXCEPTION REQUEST** (shaded/transitive/no-fix/breaking-major/environment/policy).

It combines an Anthropic-API agent with a set of deterministic Python scripts as
tools, scoped strictly per release, with a human approval gate on every write.

## Components

| File | Purpose |
|------|---------|
| `cve_agent.py` | Anthropic Messages API agent; exposes Jira/GitHub/shell tools with session persistence. |
| `cve_analyser.py` | Jira API layer — query tickets, transition status, set exception reason / transition details. |
| `cve_fixer.py` | Maven-based fixer — clone/patch pom, build, commit, push, open PR. Includes the rule engine (exception / close / shaded-bundle / environment R9). |
| `cve_profiles.py` | Per-component profiles (repo, branch, build cmd, JDK, rules) + `profile_env()`. |
| `cve_reclassify.py` | Reusable CLI to reclassify OSV tickets for a CVE across components. |
| `audit_versions.py` | Reads configured library versions across component branches. |
| `fix_*.py` | Per-component fix drivers. |
| `docs/` | CVE remediation automation write-up + per-component library inventories. |

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env && $EDITOR .env && source .env   # fill in real values
```

Credentials are **never** hardcoded. `cve_analyser.py` reads Jira credentials
from `CVE_JIRA_EMAIL` / `CVE_JIRA_API_TOKEN` (or a git-ignored
`~/.config/cve_fix/jira.env`). GitHub operations use your local git credential
helper. `cve_agent.py` needs `ANTHROPIC_API_KEY`.

## Usage

```bash
# Preview only (no Jira/GitHub writes)
CVE_DRY_RUN=1 CVE_PROFILE=spark2 python3 cve_fixer.py

# Agent (natural-language driver; every write is approved by a human)
CVE_AGENT_MODEL=claude-opus-4-8 python3 cve_agent.py "Address sqoop CVEs for 3.2.3.6"
```

See `USAGE_GUIDE.md` for the full workflow and `docs/` for the design write-up.

## Security

- No secrets in the repo. Set credentials via env vars / git-ignored files.
- If a token was ever exposed locally, rotate it.
- Every state-changing operation is gated behind human approval / `CVE_DRY_RUN`.
