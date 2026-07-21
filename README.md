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
| `cve_agent.py` | Anthropic Messages API agent; exposes Jira/GitHub/OSV/shell tools with hybrid model routing, pre-fix upstream analysis, and session persistence. Also: `--full-analysis`, `--version-audit`, `--address`. |
| `cve_cost_tracker.py` | Per-component / per-phase token & cost ledger (`reports/component_costs.json`); shown after `--address` and via `--cost-report`. |
| `cve_analyser.py` | Jira API layer — query tickets, transition status, set exception reason / transition details. |
| `cve_fixer.py` | Maven-based fixer — clone/patch pom, build, commit, push, open PR. Includes the rule engine (exception / close / shaded-bundle / environment R9). |
| `cve_profiles.py` | Per-component profiles (repo, branch, build cmd, JDK, rules) + `profile_env()`. Empty rule lists filled from catalog. |
| `cve_remediation_catalog.py` | **Unified** `fix_targets` + `exception_rules` per component (next-release source of truth). |
| `cve_catalog_sync.py` | Sync catalog/`fix_targets` from `--full-analysis` JSON (new release fix versions). |
| `cve_reclassify.py` | Reusable CLI to reclassify OSV tickets for a CVE across components. |
| `audit_versions.py` | Reads configured library versions across component branches. |
| `cve_version_audit.py` | GitHub pinned lib versions vs `--full-analysis` FIX targets + common bump suggestions. |
| `check_env.py` | Portable env check (JDK / credentials / workdir) for any Linux or macOS host. |
| `fix_*.py` | Per-component fix drivers. |
| `docs/` | CVE remediation automation write-up + per-component library inventories. |

## Layout (portable)

```
cve_fix_llm/                 # this repo (same on laptop or 10.101.11.82)
  cve_agent.py / cve_*.py
  check_env.py
  docs/
  .env                         # git-ignored credentials (or use env vars)
~/cve_fix_workdir/            # CVE_WORKDIR — component git checkouts (not in repo)
  hadoop/  hive/  spark/  …
~/.config/cve_fix/jira.env    # optional Jira credentials file
```

Paths are **not** machine-specific. Set `CVE_WORKDIR`, `CVE_JAVA_HOME_8`, and
`CVE_JAVA_HOME_11` on each host (see `.env.example`).

**JDK by release baseline:** `3.2.3.*` → JDK 8, `3.3.6.*` → JDK 11 (via
`CVE_RELEASE`, `CVE_ADDRESS_RELEASE`, or each profile's `release` field).

## Setup

```bash
# any Linux or macOS host
git clone <this-repo> && cd cve_fix_llm
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && $EDITOR .env
# .env is loaded automatically by cve_agent.py / check_env.py (or: source .env)
python3 check_env.py            # verify JDK / creds / workdir
```

Credentials are **never** hardcoded. `cve_analyser.py` reads Jira credentials
from `CVE_JIRA_EMAIL` / `CVE_JIRA_API_TOKEN` (or a git-ignored
`~/.config/cve_fix/jira.env`). GitHub operations use `GITHUB_TOKEN` / `GH_TOKEN`
if set, otherwise your local git credential helper. `cve_agent.py` needs
`ANTHROPIC_API_KEY`.

## Usage

```bash
# Preview only (no Jira/GitHub writes)
CVE_DRY_RUN=1 CVE_PROFILE=spark2 python3 cve_fixer.py

# Agent (natural-language driver; every write is approved by a human)
python3 cve_agent.py "Address sqoop CVEs for 3.2.3.6"

# Full release analysis (deterministic — no LLM tokens):
# FIX vs EXCEPTION counts, per-component lib/current->target list,
# and cross-component common-version suggestions (e.g. netty 4.1.135 for all).
python3 cve_agent.py --full-analysis 3.3.6.4
# equivalent: python3 cve_full_analysis.py 3.3.6.4 --components hadoop hive

# After a NEW release scan: refresh fix_targets from the analysis report
# (bumps catalog target versions; writes cve_catalog_overrides.json)
python3 cve_agent.py --sync-catalog 3.3.6.5            # dry-run
python3 cve_agent.py --sync-catalog 3.3.6.5 --apply
# Ambari-only example (Jira release 3.0.0.2, repo sehajsandhu/ambari):
python3 cve_agent.py --full-analysis 3.0.0.2 --components ambari
python3 cve_agent.py --sync-catalog 3.0.0.2 --components ambari --apply

# Version audit: read pinned libs from GitHub, compare with analysis report
python3 cve_agent.py --version-audit 3.3.6.4 --branch nightly/3.3.6.5
# run --full-analysis first; output: reports/version_audit_3.3.6.4.json

# Address one component end-to-end (agent packs the full triage→PR→Jira flow)
python3 cve_agent.py --address zookeeper
python3 cve_agent.py --address zookeeper --release 3.3.6.4 \
    --branch nightly/3.3.6.5 --pr-base nightly/3.3.6.5
python3 cve_agent.py --list-components                    # static catalog
python3 cve_agent.py --list-components --release 3.3.6.4  # + OSV Jira (needs creds)

# After addressing components — lifetime token/cost by component + phase
python3 cve_agent.py --cost-report
```

### Hybrid model routing

`cve_agent.py` routes work across three model tiers to balance cost and
capability, and meters token usage per model so the cost estimate is accurate:

| Tier | Env var | Default | Used for |
|------|---------|---------|----------|
| triage | `CVE_MODEL_TRIAGE` | `claude-haiku-4-5` | cheap bulk triage / extraction |
| orch | `CVE_MODEL_ORCH` | `claude-sonnet-5` | orchestration + normal fixes (default start) |
| fix | `CVE_MODEL_FIX` | `claude-opus-4-8` | hard remediation / escalation target |

The run starts on `CVE_AGENT_TIER` (default `orch`) and **auto-escalates
one-way** to the FIX tier when a build/compile fails or the model emits an
`[ESCALATE]` marker (disable with `CVE_AGENT_AUTO_ESCALATE=0`). Pin everything
to a single model with `CVE_AGENT_MODEL=<model>` (single-model mode).

```bash
# Start cheap for a big triage pass, escalate to Opus automatically on hard cases
CVE_AGENT_TIER=triage python3 cve_agent.py "Triage all trino CVEs for 3.2.3.6"

# Pin one model (old behaviour)
CVE_AGENT_MODEL=claude-opus-4-8 python3 cve_agent.py "Fix sqoop jetty CVE"
```

### Pre-fix upstream analysis

Before proposing a fix, the agent calls the `analyse_upstream` tool to gather
insight so you know what you're getting into:

- **Does upstream have a fix?** Looks up the CVE on [OSV.dev](https://osv.dev)
  (which aggregates GitHub Security Advisories) and reports the fixed ecosystem
  version(s) — falling back to the `GHSA-*` alias record for the released Maven/
  npm/PyPI version when the CVE record only carries git commits.
- **Version bump or code changes?** Compares the version pinned in our branch
  against the recommended fixed version: a **patch/minor** bump is usually a
  drop-in dependency change (`LIKELY_VERSION_BUMP`), while a **major** jump
  usually means API breaks and real code work (`LIKELY_CODE_CHANGES`, and often
  an R9 JDK/runtime concern). If there's no released fix it flags
  `UPSTREAM_FIX_IS_SOURCE_PATCH` (cherry-pick) or `NO_UPSTREAM_FIX` (exception).
- **What does upstream ship now?** Optionally reads the upstream OSS repo's
  `main`/`master` build file (e.g. `apache/hadoop` + `hadoop-project/pom.xml`)
  and reports the version currently on the default branch.

```bash
python3 cve_agent.py "For CVE-2022-42003 in hadoop 3.2.3.6, analyse upstream and \
tell me if it's a version bump or code change before fixing"
```

See `docs/CVE_Remediation_Automation.md` for the design write-up.

## Security

- No secrets in the repo. Set credentials via env vars / git-ignored files.
- If a token was ever exposed locally, rotate it.
- Every state-changing operation is gated behind human approval / `CVE_DRY_RUN`.
