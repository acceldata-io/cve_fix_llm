"""
cve_agent.py — a human-in-the-loop CVE remediation agent.

Design (as agreed): Anthropic Messages API + the existing local scripts as
tools. The deterministic heavy lifting (fetching tickets, parsing poms, applying
patches, building, transitioning Jira) stays in cve_analyser / cve_fixer /
cve_reclassify — the model only reasons and decides. Writes are gated behind a
human approval prompt, and token usage / cost is metered.

Hybrid model routing: the run starts on a mid tier (Sonnet) for orchestration
and normal fixes, uses a cheap tier (Haiku) when pinned for bulk triage, and
auto-escalates (one-way) to a top tier (Opus) when a build/compile fails or the
model emits an [ESCALATE] marker. Per-model token usage is metered so hybrid
cost is accurate.

Deterministic full-analysis mode (no LLM):
    python3 cve_agent.py --full-analysis 3.3.6.4
    python3 cve_full_analysis.py 3.3.6.4 --components hadoop hive

Version audit (GitHub pinned libs vs --full-analysis FIX targets, no LLM):
    python3 cve_agent.py --version-audit 3.3.6.4
    python3 cve_agent.py --version-audit 3.3.6.4 --branch nightly/3.3.6.5

Address one component end-to-end (agent-driven, approval-gated writes):
    python3 cve_agent.py --address zookeeper
    python3 cve_agent.py --address zookeeper --release 3.3.6.4 \\
        --branch nightly/3.3.6.5 --pr-base nightly/3.3.6.5
    python3 cve_agent.py --list-components

Run:
    export ANTHROPIC_API_KEY=sk-ant-...
    # optional overrides (hybrid tiers):
    export CVE_MODEL_TRIAGE=claude-haiku-4-5             # cheap bulk triage
    export CVE_MODEL_ORCH=claude-sonnet-5               # orchestration + fixes
    export CVE_MODEL_FIX=claude-opus-4-8                # hard remediation / escalate
    export CVE_AGENT_TIER=orch                          # triage|orch|fix (start tier)
    export CVE_AGENT_AUTO_ESCALATE=1                    # 0 = never escalate
    # single-model mode (pins ALL tiers to one model):
    export CVE_AGENT_MODEL=claude-3-5-sonnet-latest
    export CVE_AGENT_AUTOAPPROVE=0                        # 1 = skip the gate (careful)
    python3 cve_agent.py "Analyse the flink component and propose a plan"
    python3 cve_agent.py                                  # interactive

The agent NEVER writes to Jira/GitHub without a y/N confirmation, unless
CVE_AGENT_AUTOAPPROVE=1 is set.
"""

from __future__ import annotations
import json
import os
import re
import subprocess
import sys
import urllib.parse
from typing import Dict, List

import cve_env

cve_env.load_repo_env()

import anthropic

import cve_analyser as ca
import cve_profiles
import cve_reclassify

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# --- Hybrid model tiers -----------------------------------------------------
# Route by task difficulty: a cheap model for bulk triage/extraction, a mid
# model for orchestration + normal fixes, and a top model for hard remediation
# / escalation. Setting the legacy CVE_AGENT_MODEL pins ALL tiers to one model
# (single-model mode), preserving old behaviour.
_LEGACY_MODEL = os.environ.get("CVE_AGENT_MODEL", "").strip()
MODEL_TRIAGE = _LEGACY_MODEL or os.environ.get("CVE_MODEL_TRIAGE", "claude-haiku-4-5")
MODEL_ORCH = _LEGACY_MODEL or os.environ.get("CVE_MODEL_ORCH", "claude-sonnet-5")
MODEL_FIX = _LEGACY_MODEL or os.environ.get("CVE_MODEL_FIX", "claude-opus-4-8")
TIER_MODELS = {"triage": MODEL_TRIAGE, "orch": MODEL_ORCH, "fix": MODEL_FIX}

# Which tier a run starts on (default the orchestration/Sonnet tier).
START_TIER = os.environ.get("CVE_AGENT_TIER", "orch").lower()
if START_TIER not in TIER_MODELS:
    START_TIER = "orch"
# Auto-escalate to the FIX tier (Opus) when a build/compile fails or the model
# emits an [ESCALATE] marker. One-way — a run never de-escalates.
AUTO_ESCALATE = os.environ.get("CVE_AGENT_AUTO_ESCALATE", "1") not in ("", "0", "false", "False")

# Primary model for display / session metadata; the actual per-call model may
# escalate during a run.
MODEL = TIER_MODELS[START_TIER]

MAX_TOKENS = int(os.environ.get("CVE_AGENT_MAX_TOKENS", "4096"))
MAX_ITERS = int(os.environ.get("CVE_AGENT_MAX_ITERS", "40"))
AUTO_APPROVE = os.environ.get("CVE_AGENT_AUTOAPPROVE", "") not in ("", "0", "false", "False")
HERE = os.path.dirname(os.path.abspath(__file__))

# Cost estimate rates (USD per 1M tokens). Per-model defaults below; the legacy
# CVE_AGENT_RATE_* env vars act as a global fallback for unknown models.
RATE_IN = float(os.environ.get("CVE_AGENT_RATE_IN", "3.0"))
RATE_OUT = float(os.environ.get("CVE_AGENT_RATE_OUT", "15.0"))
RATE_CACHE_WRITE = float(os.environ.get("CVE_AGENT_RATE_CACHE_W", "3.75"))
RATE_CACHE_READ = float(os.environ.get("CVE_AGENT_RATE_CACHE_R", "0.30"))

# (input, output, cache-write, cache-read) USD per 1M tokens — July 2026 list.
_DEFAULT_RATES = {
    "claude-haiku-4-5": (1.0, 5.0, 1.25, 0.10),
    "claude-sonnet-5": (3.0, 15.0, 3.75, 0.30),
    "claude-opus-4-8": (5.0, 25.0, 6.25, 0.50),
    "claude-fable-5": (10.0, 50.0, 12.5, 1.0),
}


def _rates_for(model: str):
    """Return (in, out, cache_w, cache_r) rates for a model name."""
    if model in _DEFAULT_RATES:
        return _DEFAULT_RATES[model]
    m = (model or "").lower()
    if "haiku" in m:
        return _DEFAULT_RATES["claude-haiku-4-5"]
    if "fable" in m or "mythos" in m:
        return _DEFAULT_RATES["claude-fable-5"]
    if "opus" in m:
        return _DEFAULT_RATES["claude-opus-4-8"]
    if "sonnet" in m:
        return _DEFAULT_RATES["claude-sonnet-5"]
    return (RATE_IN, RATE_OUT, RATE_CACHE_WRITE, RATE_CACHE_READ)

MAX_TOOL_OUTPUT = 16000  # chars returned to the model from a tool

SYSTEM_PROMPT = """You are a CVE remediation agent for the ODP (Acceldata) platform.
You drive local scripts (cve_analyser, cve_fixer, cve_reclassify) via tools to
triage and fix CVEs across components on the nightly/ODP-3.2.3.7-2 baseline.

Operating rules:
- RELEASE SCOPING IS CRITICAL. The SAME CVE has separate OSV tickets per release
  (3.2.3.4, 3.2.3.6, 3.3.6.3, 3.3.6.4, ...). When the user scopes a request to a
  release, you MUST pass that release to query_cve and reclassify_cve so tickets
  from OTHER releases are never touched. Never reclassify by repo+status alone
  when a release was specified — always include release (or include_keys). If a
  CVE has tickets in multiple releases and the user named one, act only on that
  release's ticket(s).
- For "how many CVEs in release X, broken down by component" questions, use the
  query_release tool (it runs the release/severity/repo JQL and aggregates by
  component). Release filters are independent of the configured profiles, so any
  release string (e.g. 3.3.6.4) works.
- Read/analyse first. Use query_cve and check_repo_version to establish facts
  (affected library, current version in the branch, whether a fixed version
  exists) BEFORE deciding anything.
- For cross-component version planning, use audit_component_versions: it reads
  the pinned versions of the standard ODP libraries (netty, jackson, guava, …)
  from each component's GitHub branch, compares them with the --full-analysis
  report's FIX targets, and recommends the highest common bump version that
  covers the most CVEs. Run --full-analysis <release> first if the report is
  missing.
- For every CVE you intend to FIX, call analyse_upstream FIRST to get pre-fix
  insight: (a) does upstream actually have a fix and what fixed version(s)
  exist, (b) is the remediation a drop-in VERSION BUMP or does it LIKELY need
  CODE CHANGES (a patch/minor bump is usually drop-in; a major-version jump
  usually means API breaks + real code work and often an R9 JDK/runtime issue),
  and (c) what version the upstream project's main/master branch currently
  ships. Pass current_version (from check_repo_version / the ticket) plus the
  upstream OSS repo+path (e.g. apache/hadoop + hadoop-project/pom.xml). Report
  this verdict to the human before applying a fix — if there is NO upstream fix,
  do not invent a bump: cherry-pick or route to EXCEPTION.
- Classify each CVE as: FIX (bump a version), EXCEPTION (cannot bump / not
  fixable here), CLOSE (already fixed upstream/platform), or FALSE POSITIVE /
  NOT APPLICABLE. Justify exceptions and closures with concrete reasons.
- Prefer the smallest safe change. Respect known constraints: libthrift cannot
  go to 0.23 (breaks Hive); protobuf 2.5.0 pinned for Hadoop wire-format; jetty
  9.4.x fix only in 11/12 (jakarta); zookeeper/hadoop are platform-owned forks;
  shaded/fat-jar CVEs are fixed at their owning component, not downstream.
- Environment/compatibility check (R9) BEFORE proposing any FIX: a patched
  version is only a valid fix if it runs on the component's actual runtime.
  Check the profile's java_home/JDK (many components are pinned to JDK 8, e.g.
  nifi/ranger/oozie), the Python interpreter for python components (airflow,
  hue, jupyterhub), and whether the finding is OS/base-image-owned (Go-stdlib,
  glibc, OpenSSL -> fixed by a base-image refresh, not an app bump). If the only
  patched version needs a newer JDK/Python or would break same-component ABI,
  do NOT bump: route to EXCEPTION (environment/compatibility constraint). Use
  cve_profiles.profile_env(profile) to read {jdk, python, build_tool}; fix_targets
  and exception_rules may carry requires_jdk / requires_python so cve_fixer gates
  this automatically.
- Any WRITE (reclassify_cve with dry_run=false, or apply_component) will be
  shown to a human for approval. Always run a dry-run / propose step first and
  summarise it before requesting a write.
- Moving a ticket to "Exception Request" REQUIRES the workflow fields
  CVE-Exception-Reason and CVE-Transition-Details. reclassify_cve sets these
  automatically: pass exception_reason (one of "Deferred", "Not Exploitable",
  "Spark Transitive"; default "Deferred") and transition_details (the detailed
  justification; falls back to comment). Do NOT expect a plain transition to
  Exception Request to succeed without these.
- Be concise. When you have completed the request, give a short final summary
  and stop calling tools.

Onboarding a NEW component / fixing code (this is how you gain parity):
- To "learn the process", read_local_file cve_profiles.py and one or two
  existing fix_*.py drivers to see the exact profile shape and conventions.
- Use list_repo_tree to discover the real repo/branch layout and the build files
  BEFORE assuming a path. Not every component is Maven: sqoop, for example, has
  NO pom.xml — it uses build.gradle + ivy/libraries.properties. apply_component
  only works for pom-based registered profiles.
- For a Maven component: author a profile with write_local_file (append to
  cve_profiles.py), then analyse_component (dry-run) and apply_component.
- For a non-Maven component (Gradle/Ivy/Ant) OR any raw git/build/PR work: use
  run_shell to git clone the repo to /tmp, git checkout the target branch, create
  a fix branch (name it after the OSV key), edit the version in the right build
  file (ivy/libraries.properties, build.gradle, etc.), compile, and if the build
  passes: commit (match the existing commit-message template — inspect prior
  commits with `git log`), push, and open a PR with `gh pr create` (or the API)
  targeting the release branch, assigning the requested reviewer. Then close the
  Jira ticket. Verify facts (current version, build tool, commit convention) with
  read/list tools first; don't guess.
- run_shell, write_local_file, apply_component and reclassify_cve(dry_run=false)
  are all human-approved at execution time, so propose the concrete commands.
"""

client = None  # instantiated in main() after the API key check

# running usage totals
# Token usage is tracked per model so hybrid runs can be costed accurately.
# Shape: {model_name: {"in", "out", "cache_w", "cache_r"}}.
USAGE: Dict[str, Dict[str, int]] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _github_token() -> str:
    # Priority: GITHUB_TOKEN / GH_TOKEN env vars (so a .env works), then the
    # stored token via `git credential fill`.
    tok = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if tok:
        return tok
    p = subprocess.run(
        "printf 'protocol=https\\nhost=github.com\\n\\n' | git credential fill",
        shell=True, capture_output=True, text=True)
    for line in p.stdout.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    return ""


def _clip(s: str) -> str:
    if len(s) <= MAX_TOOL_OUTPUT:
        return s
    return s[:2000] + f"\n...[clipped {len(s)-MAX_TOOL_OUTPUT} chars]...\n" + s[-(MAX_TOOL_OUTPUT-2000):]


def _human_ok(summary: str) -> bool:
    if AUTO_APPROVE:
        print(f"\n[AUTO-APPROVE] {summary}")
        return True
    print("\n" + "#" * 78)
    print("APPROVAL REQUIRED:")
    print(summary)
    print("#" * 78)
    ans = input("Proceed? [y/N] ").strip().lower()
    return ans in ("y", "yes")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def tool_list_profiles(_: Dict) -> str:
    rows = []
    for name, p in sorted(cve_profiles.PROFILES.items()):
        rows.append({"profile": name, "repo": p["repo"], "release": p["release"],
                     "branch": p["target_branch"]})
    return json.dumps(rows, indent=2)


def tool_query_cve(args: Dict) -> str:
    cve = args["cve_id"]
    repo = args.get("repo_substr")
    release = args.get("release")
    jql = f'project = OSV AND text ~ "{cve}"'
    if repo:
        jql += f' AND "cve-repo[short text]" ~ "{repo}"'
    if release:
        jql += f' AND "cve-found-in-release-version[short text]" ~ "{release}"'
    fields = ("key,summary,status,customfield_10127,customfield_10870,"
              "customfield_10875,customfield_10892,customfield_10891,"
              "customfield_10888,customfield_10893")
    url = (f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql?jql={urllib.parse.quote(jql)}"
           f"&maxResults=100&fields={fields}")
    r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                       auth=(ca.EMAIL, ca.API_TOKEN))
    detail = []
    from collections import Counter
    statuses, repos, releases, libs = Counter(), Counter(), Counter(), set()
    if r.status_code == 200:
        for iss in r.json().get("issues", []):
            f = iss["fields"]
            if ca.extract_cve_id(iss["key"], f.get("summary", "") or "",
                                 f.get("customfield_10127", "") or "") != cve:
                continue
            st = (f.get("status") or {}).get("name", "")
            rp = (f.get("customfield_10870") or "")
            rel = (f.get("customfield_10893") or "")
            lib = (f.get("customfield_10875") or "")
            ver = (f.get("customfield_10892") or "")
            fix = ca.extract_fixed_version(f.get("customfield_10891"))
            statuses[st] += 1
            repos[rp] += 1
            releases[rel] += 1
            libs.add((lib, ver, fix))
            detail.append({"key": iss["key"], "status": st, "repo": rp,
                           "release": rel, "lib": lib, "ver": ver, "fix": fix,
                           "path": f.get("customfield_10888", "")})
    summary = {
        "cve": cve, "release_filter": release, "total": len(detail),
        "by_status": dict(statuses), "by_repo": dict(repos),
        "by_release": dict(releases),
        "distinct_lib_ver_fix": sorted(libs),
        "tickets": detail[:60],
    }
    return _clip(json.dumps(summary, indent=2))


def tool_query_release(args: Dict) -> str:
    """Enumerate/aggregate OSV tickets for a release filter (severity, repo,
    assignee, status) and break the counts down by component (cve-repo) and CVE.
    This is the JQL-board query, done programmatically."""
    from collections import Counter, defaultdict

    raw_jql = args.get("raw_jql")
    if raw_jql:
        jql = raw_jql
    else:
        release = args["release"]
        sev = args.get("severities") or ["Critical", "High", "Medium"]
        repo_substr = args.get("repo_substr", "sehajsandhu/")
        parts = [
            "project = OSV",
            f'"cve-found-in-release-version[short text]" ~ "{release}"',
        ]
        if sev:
            parts.append(f'"cve-severity[dropdown]" IN ({", ".join(sev)})')
        if repo_substr:
            parts.append(f'"cve-repo[short text]" ~ "{repo_substr}"')
        assignee = args.get("assignee")
        if assignee == "empty":
            parts.append("assignee = empty")
        elif assignee:
            parts.append(f'assignee = "{assignee}"')
        statuses = args.get("statuses")
        if statuses:
            parts.append("status IN (" + ", ".join(f'"{s}"' for s in statuses) + ")")
        jql = " AND ".join(parts) + " ORDER BY created DESC"

    fields = ("key,status,customfield_10127,customfield_10870,customfield_10126,"
              "customfield_10875,summary")
    total = 0
    by_repo = Counter()
    by_status = Counter()
    by_severity = Counter()
    repo_cves = defaultdict(set)
    all_cves = set()
    tok = None
    while True:
        url = (f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql"
               f"?jql={urllib.parse.quote(jql)}&maxResults=100&fields={fields}")
        if tok:
            url += f"&nextPageToken={urllib.parse.quote(tok)}"
        r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                           auth=(ca.EMAIL, ca.API_TOKEN))
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}: {r.text[:300]}",
                               "jql": jql})
        d = r.json()
        for iss in d.get("issues", []):
            f = iss["fields"]
            total += 1
            repo = (f.get("customfield_10870") or "(none)")
            st = (f.get("status") or {}).get("name", "")
            sv = ca.extract_dropdown(f.get("customfield_10126"))
            cve = ca.extract_cve_id(iss["key"], f.get("summary", "") or "",
                                    f.get("customfield_10127", "") or "")
            by_repo[repo] += 1
            by_status[st] += 1
            by_severity[sv] += 1
            if cve != "UNKNOWN":
                repo_cves[repo].add(cve)
                all_cves.add(cve)
        tok = d.get("nextPageToken")
        if d.get("isLast", True) or not tok:
            break

    # Counts are always exact. CVE lists are only inlined when explicitly
    # requested (they can be huge for a full release) — otherwise drill down
    # per component with repo_substr + include_cves.
    include_cves = bool(args.get("include_cves", False))
    CVE_CAP = 40
    components = []
    for repo, cnt in by_repo.most_common():
        cves = sorted(repo_cves[repo])
        row = {
            "component": repo.split("/")[-1] if "/" in repo else repo,
            "repo": repo,
            "tickets": cnt,
            "distinct_cves": len(cves),
        }
        if include_cves:
            row["cves"] = cves[:CVE_CAP]
            if len(cves) > CVE_CAP:
                row["cves_truncated"] = len(cves) - CVE_CAP
        components.append(row)
    summary = {
        "jql": jql,
        "total_tickets": total,
        "distinct_cves_total": len(all_cves),
        "component_count": len(by_repo),
        "by_component": components,
        "by_status": dict(by_status),
        "by_severity": dict(by_severity),
    }
    return _clip(json.dumps(summary, indent=2))


def tool_audit_component_versions(args: Dict) -> str:
    """GitHub version matrix + comparison with --full-analysis FIX targets."""
    import cve_version_audit as va
    release = args.get("release") or os.environ.get("CVE_RELEASE", "3.3.6.4")
    branch = args.get("branch", "")
    components = args.get("components")
    analysis_path = args.get("analysis_report", "")
    report = va.run_audit(release, branch=branch,
                          components=components or None,
                          analysis_path=analysis_path)
    # Compact payload for the model — full matrix can be large.
    payload = {
        "release": report["release"],
        "github_branch": report["github_branch"],
        "analysis_loaded": report["analysis_loaded"],
        "analysis_report": report["analysis_report"],
        "report_path": report["report_path"],
        "recommendations": report["recommendations"],
        "current_versions": report["current_versions"],
    }
    return _clip(json.dumps(payload, indent=2))


def tool_check_repo_version(args: Dict) -> str:
    repo = args["repo"]           # e.g. acceldata-io/hadoop
    branch = args["branch"]       # e.g. nightly/ODP-3.2.3.7-2
    path = args["path"]           # e.g. hadoop-project/pom.xml
    pattern = args.get("pattern", "version")
    token = _github_token()
    raw = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    r = ca.SESSION.get(raw, headers={"Authorization": f"token {token}"} if token else {})
    if r.status_code != 200:
        return json.dumps({"error": f"HTTP {r.status_code} fetching {raw}"})
    matches = []
    for i, line in enumerate(r.text.splitlines(), 1):
        if re.search(pattern, line, re.IGNORECASE):
            matches.append({"line": i, "text": line.strip()})
    return _clip(json.dumps({"url": raw, "pattern": pattern,
                             "match_count": len(matches),
                             "matches": matches[:80]}, indent=2))


def _ver_tuple(v: str):
    """Best-effort numeric (major, minor, patch) from a version string.
    Handles tails like '9.4.57.v20241219', '2.14.3', '1.5.4'."""
    if not v:
        return None
    nums = re.findall(r"\d+", str(v))
    if not nums:
        return None
    return tuple(int(x) for x in nums[:3])


def _bump_kind(current: str, fixed: str) -> str:
    """Classify current->fixed as patch/minor/major (or none/unknown).
    A patch/minor bump is usually drop-in; a major bump usually implies API
    breaks and real code changes in the consuming component."""
    a, b = _ver_tuple(current), _ver_tuple(fixed)
    if not a or not b:
        return "unknown"
    a = a + (0,) * (3 - len(a))
    b = b + (0,) * (3 - len(b))
    if b <= a:
        return "none"          # already at/above the fixed version
    if b[0] != a[0]:
        return "major"
    if b[1] != a[1]:
        return "minor"
    return "patch"


def _pick_target(current: str, fixed_list: List[str]) -> str:
    """Smallest fixed version strictly greater than current (else smallest)."""
    cand = [f for f in fixed_list if f]
    if not cand:
        return ""
    cur = _ver_tuple(current)
    keyed = sorted(cand, key=lambda f: (_ver_tuple(f) or (0,)))
    if cur:
        cur = cur + (0,) * (3 - len(cur))
        for f in keyed:
            ft = _ver_tuple(f)
            if ft and (ft + (0,) * (3 - len(ft))) > cur:
                return f
    return keyed[0]


def _osv_lookup(vuln_id: str) -> Dict:
    """Fetch a vulnerability record from OSV.dev (free, no auth). OSV indexes
    CVE / GHSA ids and aggregates GitHub Security Advisories, so it tells us
    whether upstream has a fix and the fixed version(s) per ecosystem."""
    try:
        r = ca.SESSION.get(
            f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vuln_id)}",
            timeout=30)
    except Exception as e:
        return {"error": f"OSV request failed: {e}"}
    if r.status_code != 200:
        return {"error": f"OSV HTTP {r.status_code} for {vuln_id}",
                "hint": r.text[:200]}
    return r.json()


def _collect_fixes(rec: Dict):
    """Split an OSV record's 'fixed' events into released ecosystem versions
    (usable as a bump target) vs GIT commit fixes (a source patch, not a
    released version). Also return affected packages and introduced points."""
    semver, git, pkgs, intro = [], [], [], []
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {})
        if pkg:
            pkgs.append({"ecosystem": pkg.get("ecosystem", ""),
                         "name": pkg.get("name", "")})
        for rng in aff.get("ranges", []):
            rtype = rng.get("type", "")
            for ev in rng.get("events", []):
                if ev.get("fixed"):
                    (git if rtype == "GIT" else semver).append(ev["fixed"])
                if ev.get("introduced") and ev["introduced"] != "0":
                    intro.append(ev["introduced"])
    return semver, git, pkgs, intro


def _fetch_upstream_version(repo: str, path: str, pattern: str,
                            branch: str = "") -> Dict:
    """Read a build file from the UPSTREAM (open-source) repo's default branch
    and grep it, so we can report what version upstream currently ships. Tries
    main then master when no branch is given."""
    token = _github_token()
    hdrs = {"Authorization": f"token {token}"} if token else {}
    branches = [branch] if branch else ["main", "master"]
    for b in branches:
        raw = f"https://raw.githubusercontent.com/{repo}/{b}/{path}"
        try:
            r = ca.SESSION.get(raw, headers=hdrs, timeout=30)
        except Exception as e:
            return {"error": f"request failed: {e}", "url": raw}
        if r.status_code == 200:
            rx = re.compile(pattern or "version", re.IGNORECASE)
            matches = [{"line": i, "text": ln.strip()}
                       for i, ln in enumerate(r.text.splitlines(), 1)
                       if rx.search(ln)]
            return {"repo": repo, "branch": b, "path": path,
                    "pattern": pattern or "version",
                    "match_count": len(matches), "matches": matches[:60]}
    return {"error": f"could not read {path} on {repo} "
            f"(tried branches: {', '.join(branches)})"}


def tool_analyse_upstream(args: Dict) -> str:
    """Pre-fix insight for a fixable CVE: does upstream have a fix, what fixed
    version(s) exist, is remediation a drop-in version bump or likely code
    changes, and what version does upstream main/master currently ship."""
    cve = args.get("cve_id", "")
    current = args.get("current_version", "")
    result: Dict = {"cve": cve, "current_version": current}

    # 1) Upstream fix availability + fixed versions (OSV.dev).
    osv = _osv_lookup(cve) if cve else {"error": "no cve_id provided"}
    fixed_versions: List[str] = []
    fix_commits: List[str] = []
    affected_pkgs: List[Dict] = []
    if "error" in osv:
        result["osv"] = osv
    else:
        fixed_versions, fix_commits, affected_pkgs, intro = _collect_fixes(osv)
        # The CVE-level record often carries only GIT ranges; the released
        # ecosystem versions live in the GHSA advisory. Fall back to aliases.
        if not fixed_versions:
            for alias in osv.get("aliases", []):
                if not alias.startswith("GHSA"):
                    continue
                g = _osv_lookup(alias)
                if "error" not in g:
                    s2, c2, p2, _ = _collect_fixes(g)
                    fixed_versions += s2
                    fix_commits += c2
                    affected_pkgs += p2
                if fixed_versions:
                    break
        fixed_versions = sorted(set(fixed_versions),
                                key=lambda f: (_ver_tuple(f) or (0,)))
        fix_commits = list(dict.fromkeys(fix_commits))
        seen = set()
        uniq_pkgs = []
        for p in affected_pkgs:
            key = (p.get("ecosystem"), p.get("name"))
            if key not in seen:
                seen.add(key)
                uniq_pkgs.append(p)
        result["osv"] = {
            "id": osv.get("id", cve),
            "summary": (osv.get("summary") or "")[:300],
            "aliases": osv.get("aliases", [])[:8],
            "affected_packages": uniq_pkgs[:12],
            "fixed_versions": fixed_versions,
            "fix_commits": fix_commits[:5],
            "introduced": sorted(set(intro))[:8],
            "references": [ref.get("url") for ref in osv.get("references", [])
                           if ref.get("type") in ("FIX", "ADVISORY", "WEB")][:6],
        }

    result["fix_available_upstream"] = bool(fixed_versions or fix_commits)
    target = _pick_target(current, fixed_versions)
    result["recommended_target_version"] = target

    # 2) Bump-vs-code-change assessment.
    if not fixed_versions and fix_commits:
        verdict = "UPSTREAM_FIX_IS_SOURCE_PATCH"
        reason = ("OSV lists fix commit(s) but no released ecosystem version for "
                  "this package. The fix is a source patch — identify the release "
                  "that contains it, or cherry-pick the commit(s), rather than a "
                  "plain version bump.")
        kind = "none"
    elif not fixed_versions:
        verdict = "NO_UPSTREAM_FIX"
        reason = ("OSV lists no fixed version or fix commit. There may be no "
                  "upstream fix yet — route to EXCEPTION (no upstream fix) unless "
                  "you can confirm a patch elsewhere.")
        kind = "none"
    else:
        kind = _bump_kind(current, target) if current else "unknown"
        if kind == "none":
            verdict = "ALREADY_FIXED"
            reason = f"Current {current} >= fixed {target}; likely already patched."
        elif kind in ("patch", "minor"):
            verdict = "LIKELY_VERSION_BUMP"
            reason = (f"{current or '?'} -> {target} is a {kind} bump; usually "
                      "a drop-in dependency version change (verify build).")
        elif kind == "major":
            verdict = "LIKELY_CODE_CHANGES"
            reason = (f"{current or '?'} -> {target} crosses a major version; "
                      "expect API breaks / code changes. Check R9 "
                      "(JDK/runtime) compatibility before bumping.")
        else:
            verdict = "REVIEW"
            reason = ("Fixed version exists but current version unknown — pass "
                      "current_version (or use check_repo_version) to classify.")
    result["bump_kind"] = kind
    result["verdict"] = verdict
    result["reason"] = reason

    # 3) What version upstream main/master currently ships (optional).
    up_repo = args.get("upstream_repo")
    up_path = args.get("upstream_path")
    if up_repo and up_path:
        result["upstream_main"] = _fetch_upstream_version(
            up_repo, up_path, args.get("pattern", ""),
            args.get("upstream_branch", ""))
    else:
        result["upstream_main"] = {"skipped": "pass upstream_repo + upstream_path "
                                   "(+ optional pattern/upstream_branch) to read "
                                   "the version on upstream's default branch"}
    return _clip(json.dumps(result, indent=2))


def _run_script(env_extra: Dict, argv: List[str]) -> str:
    env = dict(os.environ)
    env.update({k: str(v) for k, v in env_extra.items()})
    p = subprocess.run([sys.executable] + argv, cwd=HERE, env=env,
                       capture_output=True, text=True)
    out = (p.stdout or "") + ("\n[STDERR]\n" + p.stderr if p.stderr.strip() else "")
    out = "\n".join(l for l in out.splitlines()
                    if "NotOpenSSL" not in l and "warnings.warn" not in l)
    return f"exit={p.returncode}\n" + _clip(out)


def tool_analyse_component(args: Dict) -> str:
    profile = args["profile"]
    # dry-run: no git, no jira writes -> pure proposal
    return _run_script(
        {"CVE_PROFILE": profile, "CVE_APPLY": "0", "CVE_DRY_RUN": "1"},
        ["cve_fixer.py"])


def tool_reclassify_cve(args: Dict) -> str:
    cve = args["cve_id"]
    to_status = args["to_status"]
    comment = args.get("comment", "")
    dry_run = args.get("dry_run", True)
    kwargs = dict(
        include_repos=args.get("include_repos") or [],
        exclude_repos=args.get("exclude_repos") or [],
        only_statuses=args.get("only_statuses"),
        clear_fields=args.get("clear_fields") or [],
        release=args.get("release"),
        include_keys=args.get("include_keys"),
        exception_reason=args.get("exception_reason", "Deferred"),
        transition_details=args.get("transition_details"),
    )
    if not dry_run:
        # preview first so the human sees the exact scope
        preview = cve_reclassify.reclassify(cve, to_status, comment,
                                            dry_run=True, **kwargs)
        summary = (f"RECLASSIFY {cve} -> {to_status}\n"
                   f"  comment: {comment}\n"
                   f"  release={kwargs['release']}  keys={kwargs['include_keys']}\n"
                   f"  would change {len(preview['selected'])} tickets: "
                   f"{', '.join(preview['selected'][:30])}"
                   f"{' ...' if len(preview['selected'])>30 else ''}\n"
                   f"  clear_fields={kwargs['clear_fields']}  "
                   f"filters: include={kwargs['include_repos']} "
                   f"exclude={kwargs['exclude_repos']} only={kwargs['only_statuses']}")
        if not _human_ok(summary):
            return json.dumps({"aborted": True, "reason": "human declined",
                               "preview_selected": preview["selected"]})
    res = cve_reclassify.reclassify(cve, to_status, comment, dry_run=dry_run, **kwargs)
    return _clip(json.dumps(res, indent=2))


def tool_apply_component(args: Dict) -> str:
    profile = args["profile"]
    only_target = args.get("only_target")
    skip_routing = args.get("skip_routing", False)
    p = cve_profiles.PROFILES.get(profile, {})
    summary = (f"APPLY fixes for component '{profile}'  "
               f"(repo={p.get('repo')} branch={p.get('target_branch')})\n"
               f"  only_target={only_target}  skip_routing={skip_routing}\n"
               f"  This will: edit poms, build, push branch(es), open PR(s), "
               f"and transition Jira tickets.")
    if not _human_ok(summary):
        return json.dumps({"aborted": True, "reason": "human declined"})
    env = {"CVE_PROFILE": profile, "CVE_APPLY": "1", "CVE_DRY_RUN": "0"}
    if only_target:
        env["CVE_ONLY_TARGET"] = only_target
    if skip_routing:
        env["CVE_SKIP_ROUTING"] = "1"
    return _run_script(env, ["cve_fixer.py"])


def tool_list_repo_tree(args: Dict) -> str:
    """List a GitHub repo's file tree on a branch (read-only). Use to discover
    build files (pom.xml / build.gradle / ivy/libraries.properties) and confirm
    the real repo layout before wiring a profile or a fix."""
    repo = args["repo"]
    branch = args["branch"]
    pattern = args.get("pattern")
    token = _github_token()
    u = f"https://api.github.com/repos/{repo}/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1"
    r = ca.SESSION.get(u, headers={"Authorization": f"token {token}"} if token else {})
    if r.status_code != 200:
        return json.dumps({"error": f"HTTP {r.status_code} for {repo}@{branch}",
                           "hint": r.text[:200]})
    paths = [e["path"] for e in r.json().get("tree", []) if e.get("type") == "blob"]
    if pattern:
        rx = re.compile(pattern, re.IGNORECASE)
        paths = [p for p in paths if rx.search(p)]
    truncated = r.json().get("truncated", False)
    return _clip(json.dumps({"repo": repo, "branch": branch, "match_count": len(paths),
                             "truncated": truncated, "paths": paths[:400]}, indent=2))


def _safe_local_path(path: str) -> str:
    """Resolve a path and ensure it stays inside the project workspace."""
    ap = os.path.abspath(os.path.join(HERE, path) if not os.path.isabs(path) else path)
    if not (ap == HERE or ap.startswith(HERE + os.sep)):
        raise ValueError(f"path escapes workspace: {path}")
    return ap


def tool_read_local_file(args: Dict) -> str:
    """Read a file from the project workspace (read-only). Use to LEARN the
    process: study cve_profiles.py and existing fix_*.py scripts to see how
    other components were onboarded before authoring a new profile."""
    ap = _safe_local_path(args["path"])
    if not os.path.exists(ap):
        return json.dumps({"error": f"not found: {args['path']}"})
    with open(ap, "r", errors="replace") as fh:
        return _clip(fh.read())


def tool_write_local_file(args: Dict) -> str:
    """Create/overwrite a file in the project workspace. Approval-gated. Use to
    author a new component profile (e.g. append to cve_profiles.py) or write a
    helper fix script modelled on the existing fix_*.py drivers."""
    ap = _safe_local_path(args["path"])
    content = args["content"]
    mode = args.get("mode", "overwrite")
    action = "APPEND to" if mode == "append" else "WRITE"
    summary = (f"{action} local file: {args['path']}  ({len(content)} chars)\n"
               f"--- first 1500 chars ---\n{content[:1500]}")
    if not _human_ok(summary):
        return json.dumps({"aborted": True, "reason": "human declined"})
    with open(ap, "a" if mode == "append" else "w") as fh:
        fh.write(content)
    return json.dumps({"ok": True, "path": args["path"], "bytes": len(content),
                       "mode": mode})


def tool_run_shell(args: Dict) -> str:
    """Run a shell command (git, gradle/mvn/ant, gh, etc.). Approval-gated.
    This is the general escape hatch that gives the agent parity: clone/checkout,
    create a branch, edit build files, compile, commit, push, open a PR and
    assign reviewers. Prefer a scratch dir under /tmp for repo clones."""
    command = args["command"]
    workdir = args.get("workdir") or HERE
    timeout = int(args.get("timeout", 1800))
    summary = (f"RUN SHELL (cwd={workdir}, timeout={timeout}s):\n  {command}")
    if not _human_ok(summary):
        return json.dumps({"aborted": True, "reason": "human declined"})
    try:
        p = subprocess.run(command, shell=True, cwd=workdir, capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"timeout after {timeout}s", "command": command})
    out = (p.stdout or "") + ("\n[STDERR]\n" + p.stderr if p.stderr.strip() else "")
    out = "\n".join(l for l in out.splitlines()
                    if "NotOpenSSL" not in l and "warnings.warn" not in l)
    return f"exit={p.returncode}\n" + _clip(out)


TOOLS_IMPL = {
    "list_profiles": tool_list_profiles,
    "query_cve": tool_query_cve,
    "query_release": tool_query_release,
    "list_repo_tree": tool_list_repo_tree,
    "read_local_file": tool_read_local_file,
    "write_local_file": tool_write_local_file,
    "run_shell": tool_run_shell,
    "check_repo_version": tool_check_repo_version,
    "audit_component_versions": tool_audit_component_versions,
    "analyse_upstream": tool_analyse_upstream,
    "analyse_component": tool_analyse_component,
    "reclassify_cve": tool_reclassify_cve,
    "apply_component": tool_apply_component,
}

TOOLS = [
    {"name": "list_profiles",
     "description": "List all configured component profiles (repo, release, branch).",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "query_cve",
     "description": "Look up a CVE in OSV Jira: affected library/version, fixed "
                    "version, and per-repo/status breakdown. Use to establish facts.",
     "input_schema": {"type": "object", "properties": {
         "cve_id": {"type": "string"},
         "repo_substr": {"type": "string", "description": "optional cve-repo filter, e.g. hadoop"},
         "release": {"type": "string", "description": "optional release filter, e.g. 3.2.3.6. "
                     "Results always include per-ticket release and a by_release breakdown."}},
         "required": ["cve_id"]}},
    {"name": "query_release",
     "description": "Enumerate and aggregate OSV Jira tickets for a RELEASE filter "
                    "(the JQL-board query). Returns total tickets, distinct CVE "
                    "count, and a per-component (cve-repo) breakdown with each "
                    "component's CVE list, plus by-status and by-severity counts. "
                    "Use this for 'how many CVEs for release X, broken down by "
                    "component' questions. Defaults: severities Critical/High/Medium, "
                    "repo_substr 'sehajsandhu/'. Pass raw_jql to run an exact query.",
     "input_schema": {"type": "object", "properties": {
         "release": {"type": "string", "description": "e.g. 3.3.6.4 (matches cve-found-in-release-version)"},
         "severities": {"type": "array", "items": {"type": "string"},
                        "description": "default [Critical, High, Medium]"},
         "repo_substr": {"type": "string", "description": "cve-repo filter, default 'sehajsandhu/'"},
         "assignee": {"type": "string", "description": "accountId, or 'empty' for unassigned; omit for any"},
         "statuses": {"type": "array", "items": {"type": "string"},
                      "description": "optional status filter, e.g. ['To Do']"},
         "include_cves": {"type": "boolean", "description": "inline per-component CVE "
                          "lists (default false; can be large — use repo_substr to "
                          "drill down into one component)"},
         "raw_jql": {"type": "string", "description": "optional full JQL, overrides all other params"}},
         "required": []}},
    {"name": "check_repo_version",
     "description": "Fetch a file from a GitHub branch and grep it (e.g. read the "
                    "pinned version of a library in a pom).",
     "input_schema": {"type": "object", "properties": {
         "repo": {"type": "string", "description": "owner/repo, e.g. acceldata-io/hadoop"},
         "branch": {"type": "string", "description": "e.g. nightly/ODP-3.2.3.7-2"},
         "path": {"type": "string", "description": "file path in the repo"},
         "pattern": {"type": "string", "description": "regex to grep (default 'version')"}},
         "required": ["repo", "branch", "path"]}},
    {"name": "audit_component_versions",
     "description": "Read pinned versions of the standard ODP libraries (hadoop-"
                    "thirdparty, commons-*, netty, jackson, guava, jetty, log4j, "
                    "etc.) from each component's GitHub branch BEFORE fixing, then "
                    "compare with the --full-analysis report's FIX targets. Returns "
                    "per-component current versions, analysis needed targets, and "
                    "recommended common bump versions (highest version that fixes "
                    "the most CVEs across components). Requires a prior "
                    "--full-analysis <release> run (or pass analysis_report).",
     "input_schema": {"type": "object", "properties": {
         "release": {"type": "string", "description": "OSV release, e.g. 3.3.6.4"},
         "branch": {"type": "string", "description": "GitHub branch to read pinned "
                     "versions from (default nightly/3.3.6.5 for 3.3.6.*)"},
         "components": {"type": "array", "items": {"type": "string"},
                        "description": "optional allow-list; default all known+OSV"},
         "analysis_report": {"type": "string",
                             "description": "optional path to full_analysis JSON"}},
         "required": ["release"]}},
    {"name": "analyse_upstream",
     "description": "Pre-fix insight for a fixable CVE (read-only). Answers: does "
                    "upstream have a fix and what fixed version(s) exist (via "
                    "OSV.dev, which aggregates GitHub Security Advisories); is the "
                    "remediation a drop-in VERSION BUMP or LIKELY CODE CHANGES "
                    "(semver: patch/minor => drop-in, major => API breaks); and what "
                    "version does the upstream project's main/master branch currently "
                    "ship. Call this during triage BEFORE proposing a fix. Pass "
                    "current_version (the version pinned in our branch — get it from "
                    "check_repo_version or the Jira ticket) so the bump can be "
                    "classified, and pass upstream_repo + upstream_path (e.g. "
                    "apache/hadoop + hadoop-project/pom.xml) to read upstream's "
                    "current version.",
     "input_schema": {"type": "object", "properties": {
         "cve_id": {"type": "string"},
         "current_version": {"type": "string", "description": "version pinned in our "
                             "branch, e.g. 9.4.54 — enables the bump classification"},
         "upstream_repo": {"type": "string", "description": "upstream OSS repo, e.g. "
                           "apache/hadoop or eclipse/jetty.project"},
         "upstream_path": {"type": "string", "description": "build-file path in the "
                           "upstream repo, e.g. pom.xml / build.gradle"},
         "upstream_branch": {"type": "string", "description": "optional; defaults to "
                             "trying 'main' then 'master'"},
         "pattern": {"type": "string", "description": "regex to grep in the upstream "
                     "build file (default 'version')"}},
         "required": ["cve_id"]}},
    {"name": "analyse_component",
     "description": "Dry-run cve_fixer for a profile: proposes fix/exception/close "
                    "routing WITHOUT writing to Jira/GitHub. Read-only proposal.",
     "input_schema": {"type": "object", "properties": {
         "profile": {"type": "string"}}, "required": ["profile"]}},
    {"name": "reclassify_cve",
     "description": "Move OSV tickets for a CVE to a target status with a comment "
                    "(and optionally clear fields). dry_run=true previews; "
                    "dry_run=false requires human approval and actually writes. "
                    "IMPORTANT: when the user scoped the request to a release, ALWAYS "
                    "pass release (e.g. '3.2.3.6') so tickets from other releases are "
                    "NOT touched. Use include_keys to pin exact OSV keys for the "
                    "tightest scope.",
     "input_schema": {"type": "object", "properties": {
         "cve_id": {"type": "string"},
         "to_status": {"type": "string", "description": 'e.g. "Closed" or "Exception Request"'},
         "comment": {"type": "string"},
         "exception_reason": {"type": "string", "enum": ["Deferred", "Not Exploitable",
                              "Spark Transitive"], "description": "REQUIRED workflow field "
                              "value when to_status is 'Exception Request' (default Deferred)"},
         "transition_details": {"type": "string", "description": "CVE-Transition-Details "
                                "text for Exception Request (defaults to comment). This "
                                "field is mandatory for the Exception Request transition."},
         "release": {"type": "string", "description": "scope to a release, e.g. 3.2.3.6"},
         "include_keys": {"type": "array", "items": {"type": "string"},
                          "description": "exact OSV key allow-list, e.g. ['OSV-18879']"},
         "include_repos": {"type": "array", "items": {"type": "string"}},
         "exclude_repos": {"type": "array", "items": {"type": "string"}},
         "only_statuses": {"type": "array", "items": {"type": "string"}},
         "clear_fields": {"type": "array", "items": {"type": "string"}},
         "dry_run": {"type": "boolean"}},
         "required": ["cve_id", "to_status"]}},
    {"name": "apply_component",
     "description": "Execute cve_fixer with APPLY=1 for a profile: edits poms, "
                    "builds, pushes branches, opens PRs, closes tickets. Requires "
                    "human approval. ONLY works for Maven pom-based components that "
                    "already have a registered profile.",
     "input_schema": {"type": "object", "properties": {
         "profile": {"type": "string"},
         "only_target": {"type": "string", "description": "optional single fix target name"},
         "skip_routing": {"type": "boolean"}},
         "required": ["profile"]}},
    {"name": "list_repo_tree",
     "description": "List a GitHub repo's files on a branch (read-only). Use to find "
                    "build files (pom.xml, build.gradle, ivy/libraries.properties) and "
                    "confirm the real repo layout. Optional regex 'pattern' filter.",
     "input_schema": {"type": "object", "properties": {
         "repo": {"type": "string", "description": "owner/repo, e.g. acceldata-io/sqoop"},
         "branch": {"type": "string", "description": "e.g. nightly/ODP-3.2.3.7-2"},
         "pattern": {"type": "string", "description": "optional regex to filter paths"}},
         "required": ["repo", "branch"]}},
    {"name": "read_local_file",
     "description": "Read a file from the project workspace (read-only). Use to LEARN "
                    "how existing components were onboarded: read cve_profiles.py and "
                    "the fix_*.py drivers before authoring a new profile/fixer.",
     "input_schema": {"type": "object", "properties": {
         "path": {"type": "string", "description": "workspace-relative path, e.g. cve_profiles.py"}},
         "required": ["path"]}},
    {"name": "write_local_file",
     "description": "Create/overwrite (or append to) a workspace file. Approval-gated. "
                    "Use to author a new component profile or a helper fix script.",
     "input_schema": {"type": "object", "properties": {
         "path": {"type": "string"},
         "content": {"type": "string"},
         "mode": {"type": "string", "enum": ["overwrite", "append"],
                  "description": "default overwrite"}},
         "required": ["path", "content"]}},
    {"name": "run_shell",
     "description": "Run a shell command (git, gradle/mvn/ant, gh, sed, etc.). "
                    "Approval-gated. The general tool for git checkout/branch/commit/"
                    "push, editing build files, compiling, and opening PRs with "
                    "reviewers. Use a /tmp scratch dir for clones. This is how you fix "
                    "non-Maven components (e.g. Gradle/Ivy) that apply_component can't.",
     "input_schema": {"type": "object", "properties": {
         "command": {"type": "string"},
         "workdir": {"type": "string", "description": "cwd (default = project dir)"},
         "timeout": {"type": "integer", "description": "seconds, default 1800"}},
         "required": ["command"]}},
]


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------
def _usage_for(model: str) -> Dict[str, int]:
    return USAGE.setdefault(
        model, {"in": 0, "out": 0, "cache_w": 0, "cache_r": 0})


def _account_usage(u, model: str) -> None:
    d = _usage_for(model)
    d["in"] += getattr(u, "input_tokens", 0) or 0
    d["out"] += getattr(u, "output_tokens", 0) or 0
    d["cache_w"] += getattr(u, "cache_creation_input_tokens", 0) or 0
    d["cache_r"] += getattr(u, "cache_read_input_tokens", 0) or 0


def _usage_totals() -> Dict[str, int]:
    t = {"in": 0, "out": 0, "cache_w": 0, "cache_r": 0}
    for d in USAGE.values():
        for k in t:
            t[k] += d.get(k, 0)
    return t


def _cost() -> float:
    total = 0.0
    for model, d in USAGE.items():
        ri, ro, rcw, rcr = _rates_for(model)
        total += (d.get("in", 0) / 1e6 * ri + d.get("out", 0) / 1e6 * ro
                  + d.get("cache_w", 0) / 1e6 * rcw
                  + d.get("cache_r", 0) / 1e6 * rcr)
    return total


# --- cross-invocation session persistence -------------------------------
# Each `python3 cve_agent.py "..."` is a separate process, so conversation
# state is saved to disk and reloaded, giving the agent memory across runs.
SESSION_NAME = os.environ.get("CVE_AGENT_SESSION", "default")
SESSION_PATH = os.path.join(HERE, f".cve_agent_session_{SESSION_NAME}.json")


def _sanitize_history(messages: List[Dict]) -> List[Dict]:
    """Guarantee the history is valid for the Messages API: every assistant
    `tool_use` block must be immediately followed by a user message that
    contains a matching `tool_result`. Runs that end on stop_reason=max_tokens
    (or are interrupted) can leave a dangling `tool_use`; here we repair it by
    injecting a synthetic tool_result so the session stays resumable instead of
    throwing 'tool_use ids were found without tool_result blocks'."""
    RECOVERED = "[session recovered: tool result was lost / run ended mid-tool]"
    out: List[Dict] = []
    i, n = 0, len(messages)
    while i < n:
        msg = messages[i]
        content = msg.get("content")
        # drop user messages that are ONLY orphan tool_results (no preceding tool_use)
        if (msg.get("role") == "user" and isinstance(content, list)
                and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content)):
            prev_ids = set()
            if out and out[-1].get("role") == "assistant" and isinstance(out[-1].get("content"), list):
                prev_ids = {b.get("id") for b in out[-1]["content"]
                            if isinstance(b, dict) and b.get("type") == "tool_use"}
            kept = [b for b in content
                    if not (isinstance(b, dict) and b.get("type") == "tool_result"
                            and b.get("tool_use_id") not in prev_ids)]
            if not kept:
                i += 1
                continue
            msg = {"role": "user", "content": kept}
            content = kept
        out.append(msg)
        if msg.get("role") == "assistant" and isinstance(content, list):
            tool_ids = [b["id"] for b in content
                        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id")]
            if tool_ids:
                nxt = messages[i + 1] if i + 1 < n else None
                nxt_results = (nxt and nxt.get("role") == "user"
                               and isinstance(nxt.get("content"), list)
                               and any(isinstance(b, dict) and b.get("type") == "tool_result"
                                       for b in nxt["content"]))
                if nxt_results:
                    have = {b.get("tool_use_id") for b in nxt["content"]
                            if isinstance(b, dict) and b.get("type") == "tool_result"}
                    missing = [t for t in tool_ids if t not in have]
                    merged = list(nxt["content"]) + [
                        {"type": "tool_result", "tool_use_id": t, "content": RECOVERED}
                        for t in missing]
                    out.append({"role": "user", "content": merged})
                    i += 2
                    continue
                out.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": t, "content": RECOVERED}
                    for t in tool_ids]})
        i += 1
    return out


def load_session() -> List[Dict]:
    if os.environ.get("CVE_AGENT_NEW", "") in ("1", "true", "True"):
        return []
    if os.path.exists(SESSION_PATH):
        try:
            d = json.load(open(SESSION_PATH))
            raw = d.get("usage", {}) or {}
            USAGE.clear()
            # Old sessions stored a single flat usage dict; migrate it under the
            # session's primary model so historical cost still totals correctly.
            if raw and "in" in raw:
                USAGE[d.get("model", MODEL)] = {
                    "in": raw.get("in", 0), "out": raw.get("out", 0),
                    "cache_w": raw.get("cache_w", 0),
                    "cache_r": raw.get("cache_r", 0)}
            else:
                USAGE.update(raw)
            return _sanitize_history(d.get("messages", []))
        except Exception as e:
            print(f"[warn] could not load session: {e}")
    return []


def save_session(messages: List[Dict]) -> None:
    try:
        clean = _sanitize_history(messages)
        tmp = SESSION_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"messages": clean, "usage": USAGE, "model": MODEL,
                       "tier_models": TIER_MODELS}, fh, indent=1)
        os.replace(tmp, SESSION_PATH)   # atomic: never leave a half-written file
    except Exception as e:
        print(f"[warn] could not save session: {e}")


def _content_to_dicts(content) -> List[Dict]:
    """Serialize SDK response blocks to plain dicts so they can be persisted
    AND replayed back to the API on the next run."""
    out = []
    for b in content:
        if b.type == "text":
            out.append({"type": "text", "text": b.text})
        elif b.type == "tool_use":
            out.append({"type": "tool_use", "id": b.id, "name": b.name,
                        "input": b.input})
    return out


# Signatures in a tool result that mean a build/compile failed and the run
# should escalate to the FIX (Opus) tier for harder reasoning.
_ESCALATE_RE = re.compile(
    r"BUILD FAILURE|BUILD FAILED|COMPILATION ERROR|cannot find symbol|"
    r"FAILURE: Build failed|Traceback \(most recent|package .* does not exist|"
    r"incompatible types",
    re.I)


def _should_escalate(assistant_content, tool_results) -> bool:
    """Escalate if the model asks (emits [ESCALATE]) or a build/compile broke."""
    for b in assistant_content:
        if getattr(b, "type", None) == "text" and "[ESCALATE]" in (b.text or ""):
            return True
    for r in tool_results:
        c = r.get("content", "")
        if isinstance(c, str) and _ESCALATE_RE.search(c):
            return True
    return False


def run_agent(goal: str, messages: List[Dict],
              cost_tracker=None) -> List[Dict]:
    # repair any dangling tool_use left by a prior run before adding the new turn
    messages[:] = _sanitize_history(messages)
    # keep user/assistant alternation valid even if a prior run ended mid-turn
    if messages and messages[-1].get("role") == "user":
        messages.append({"role": "assistant",
                         "content": [{"type": "text", "text": "(continuing)"}]})
    messages.append({"role": "user", "content": goal})

    system = [{"type": "text", "text": SYSTEM_PROMPT,
               "cache_control": {"type": "ephemeral"}}]
    tools = list(TOOLS)
    tools[-1] = dict(tools[-1]); tools[-1]["cache_control"] = {"type": "ephemeral"}

    # Start on the configured tier; escalate (one-way) to the FIX tier on demand.
    current_model = TIER_MODELS[START_TIER]
    print(f"[hybrid] triage={MODEL_TRIAGE}  orch={MODEL_ORCH}  fix={MODEL_FIX}  "
          f"| starting tier={START_TIER} ({current_model})  "
          f"auto_escalate={'on' if AUTO_ESCALATE else 'off'}")

    for step in range(1, MAX_ITERS + 1):
        try:
            resp = client.messages.create(
                model=current_model, max_tokens=MAX_TOKENS, system=system,
                tools=tools, messages=messages,
                extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"})
        except Exception as e:
            # Fallback: retry once without prompt caching (older accounts/models).
            print(f"\n[warn] caching call failed ({e}); retrying without caching")
            try:
                resp = client.messages.create(
                    model=current_model, max_tokens=MAX_TOKENS,
                    system=SYSTEM_PROMPT, tools=TOOLS, messages=messages)
            except Exception as e2:
                print(f"\n[API ERROR] {e2}")
                save_session(messages)
                return messages
        _account_usage(resp.usage, current_model)

        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        phase = None
        if cost_tracker is not None:
            phase = cost_tracker.record_turn_with_cost(
                current_model, resp.usage, tool_uses)

        for block in resp.content:
            if block.type == "text" and block.text.strip():
                print(f"\n[assistant] {block.text.strip()}")

        messages.append({"role": "assistant",
                         "content": _content_to_dicts(resp.content)})

        # Drive tool execution off the PRESENCE of tool_use blocks, not
        # stop_reason: a response can carry a tool_use while stop_reason is
        # "max_tokens", and skipping it would strand a tool_use with no
        # tool_result and corrupt the session on the next resume.
        if not tool_uses:
            if resp.stop_reason == "max_tokens":
                print("\n[warn] response hit max_tokens; consider raising "
                      "MAX_TOKENS or narrowing the request")
            # allow a text-only [ESCALATE] to bump the tier before we stop
            if (AUTO_ESCALATE and current_model != MODEL_FIX
                    and _should_escalate(resp.content, [])):
                current_model = MODEL_FIX
                print(f"\n[hybrid] escalating to FIX tier ({MODEL_FIX})")
                messages.append({"role": "user", "content":
                                 "Continue with the higher-capability model."})
                continue
            break

        results = []
        for block in tool_uses:
            impl = TOOLS_IMPL.get(block.name)
            print(f"\n[tool] {block.name}({json.dumps(block.input)[:160]})")
            try:
                out = impl(block.input) if impl else f"unknown tool {block.name}"
            except Exception as e:
                out = f"TOOL ERROR: {e}"
            results.append({"type": "tool_result", "tool_use_id": block.id,
                            "content": out})
        messages.append({"role": "user", "content": results})
        save_session(messages)   # checkpoint after each tool round

        # One-way escalation to the top model when work gets hard.
        if (AUTO_ESCALATE and current_model != MODEL_FIX
                and _should_escalate(resp.content, results)):
            current_model = MODEL_FIX
            print(f"\n[hybrid] escalating to FIX tier ({MODEL_FIX}) "
                  f"(build/compile failure or [ESCALATE] requested)")

        t = _usage_totals()
        phase_tag = f" phase={phase}" if phase else ""
        print(f"  [usage so far] model={current_model}{phase_tag} "
              f"in={t['in']} out={t['out']} cache_r={t['cache_r']} "
              f"cache_w={t['cache_w']} ~${_cost():.3f}")

    save_session(messages)
    t = _usage_totals()
    print("\n" + "=" * 78)
    print(f"SESSION '{SESSION_NAME}'  ({len(messages)} msgs)  file={SESSION_PATH}")
    print(f"TOKENS (cumulative)  input={t['in']}  output={t['out']}  "
          f"cache_read={t['cache_r']}  cache_write={t['cache_w']}")
    for model, d in USAGE.items():
        print(f"  - {model}: in={d['in']} out={d['out']} "
              f"cache_r={d['cache_r']} cache_w={d['cache_w']}")
    print(f"ESTIMATED COST (cumulative)  ~${_cost():.4f}  "
          f"(hybrid: {MODEL_TRIAGE} / {MODEL_ORCH} / {MODEL_FIX})")
    print("=" * 78)
    return messages


def _reset_session() -> List[Dict]:
    USAGE.clear()
    if os.path.exists(SESSION_PATH):
        os.remove(SESSION_PATH)
    print(f"[session '{SESSION_NAME}' reset]")
    return []


def print_usage() -> None:
    print("""CVE agent — human-in-the-loop OSV remediation

Usage:
  python3 cve_agent.py [goal ...]              interactive agent (needs API key)
  python3 cve_agent.py --full-analysis <rel>   deterministic FIX/EXCEPTION plan
  python3 cve_agent.py --version-audit <rel>   GitHub lib versions vs analysis
  python3 cve_agent.py --address <comp>        address one component end-to-end
  python3 cve_agent.py --list-components       list static component catalog
  python3 cve_agent.py --list-components --release <rel>
                                               list + OSV Jira components
  python3 cve_agent.py --cost-report           per-component token/cost ledger

Environment:
  Credentials are read from the process environment. A repo-local .env file is
  loaded automatically (see .env.example). You can also run: source .env

  ANTHROPIC_API_KEY          required for agent / --address runs
  CVE_JIRA_EMAIL / CVE_JIRA_API_TOKEN   or ~/.config/cve_fix/jira.env
  GITHUB_TOKEN / GH_TOKEN    PR creation

Examples:
  python3 cve_agent.py --full-analysis 3.3.6.4
  python3 cve_agent.py --version-audit 3.3.6.4 --branch nightly/3.3.6.5
  python3 cve_agent.py --address zookeeper --release 3.3.6.4
  python3 check_env.py
""")


def main():
    global client
    # --- CLI flags ----------------------------------------------------------
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print_usage()
        return 0

    if argv and argv[0] in ("--full-analysis", "-F"):
        # python3 cve_agent.py --full-analysis 3.3.6.4 [--components hadoop hive]
        if len(argv) < 2 or argv[1].startswith("-"):
            print("Usage: python3 cve_agent.py --full-analysis <release> "
                  "[--repo-substr sehajsandhu/] [--components COMP ...] "
                  "[--all-statuses]")
            sys.exit(2)
        release = argv[1]
        rest = argv[2:]
        import cve_full_analysis as fa
        return fa.main([release] + rest)

    if argv and argv[0] in ("--version-audit", "-V"):
        if len(argv) < 2 or argv[1].startswith("-"):
            print("Usage: python3 cve_agent.py --version-audit <release> "
                  "[--branch nightly/3.3.6.5] [--components COMP ...] "
                  "[--analysis-report path]")
            sys.exit(2)
        import cve_version_audit as va
        return va.main(argv[1:])

    if argv and argv[0] in ("--address", "-A"):
        # python3 cve_agent.py --address zookeeper [--release 3.3.6.4] ...
        # Resolve / list components before requiring an API key.
        rest = argv[1:]
        import cve_address as addr
        args = addr.parse_address_args(rest)
        if not args.component:
            addr.print_component_list(release=args.release)
            return 0
        name, suggestions = addr.resolve_component(args.component)
        if not name:
            addr.print_component_list(suggestions=suggestions,
                                      query=args.component)
            return 2
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: set ANTHROPIC_API_KEY first."); sys.exit(1)
        client = anthropic.Anthropic()
        messages = load_session()
        if messages:
            print(f"[resumed session '{SESSION_NAME}': {len(messages)} "
                  f"messages, cumulative ~${_cost():.4f}]  "
                  f"(use /reset to clear)")

        def _go(goal: str, cost_tracker=None):
            run_agent(goal, messages, cost_tracker=cost_tracker)

        addr.run_address_cli._rates_for = _rates_for
        return addr.run_address_cli(rest, _go)

    if argv and argv[0] in ("--list-components",):
        import cve_address as addr
        args = addr.parse_list_args(argv[1:])
        addr.print_component_list(release=args.release)
        return 0

    if argv and argv[0] in ("--cost-report", "--costs"):
        import cve_cost_tracker as ct
        ct.print_all_costs()
        return 0

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: set ANTHROPIC_API_KEY first."); sys.exit(1)
    client = anthropic.Anthropic()
    messages = load_session()
    if messages:
        print(f"[resumed session '{SESSION_NAME}': {len(messages)} messages, "
              f"cumulative ~${_cost():.4f}]  (use /reset to clear)")

    goal = " ".join(argv).strip()
    if goal:
        if goal.lower() in ("/reset", "reset"):
            _reset_session()
        else:
            run_agent(goal, messages)
        return 0

    print("CVE agent ready. Commands: /reset, quit.")
    print("  Tips:")
    print("    python3 cve_agent.py --full-analysis 3.3.6.4")
    print("    python3 cve_agent.py --version-audit 3.3.6.4")
    print("    python3 cve_agent.py --address zookeeper")
    print("    python3 cve_agent.py --list-components")
    print("    python3 cve_agent.py --cost-report")
    while True:
        try:
            goal = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if goal.lower() in ("quit", "exit"):
            break
        if goal.lower() in ("/reset", "reset"):
            messages = _reset_session()
            continue
        if goal:
            messages = run_agent(goal, messages)
    return 0


if __name__ == "__main__":
    raise SystemExit(main() or 0)