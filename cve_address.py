"""
cve_address.py — packaged "address this component" workflow for cve_agent.

Usage (via cve_agent CLI):
    python3 cve_agent.py --address zookeeper
    python3 cve_agent.py --address zookeeper --release 3.3.6.4 \\
        --branch nightly/3.3.6.5 --pr-base nightly/3.3.6.5
    python3 cve_agent.py --address            # list components
"""

from __future__ import annotations

import argparse
import difflib
import os
import random
from typing import Dict, List, Optional, Tuple

import cve_profiles as cp

# Reviewers the agent randomly picks from when opening a PR.
DEFAULT_REVIEWERS = [
    "kravii",
    "basapuram-kumar",
    "shubhluck",
    "prabhjyotsingh",
]

# Components that appear in OSV / ODP but may not yet have a full cve_profiles
# entry. Still addressable via run_shell + git conventions.
_EXTRA_COMPONENTS = {
    "hadoop", "hive", "zookeeper", "trino", "sqoop", "spark3",
    "hudi", "iceberg", "atlas", "storm", "solr", "superset",
    "presto", "alluxio", "arrow", "bigtop",
    # 3.3.6.4+ OSV repos (often without full profiles yet)
    "celeborn", "spark4", "spark4-hbase-connectors",
    "livy4", "nifi2", "ozone2",
}

# Common aliases / typos → canonical name
_ALIASES = {
    "zk": "zookeeper",
    "zookeper": "zookeeper",
    "zookeepr": "zookeeper",
    "zoo": "zookeeper",
    "spark": "spark2",
    "livy": "livy2",
    "hbase_connectors": "hbase-connectors",
    "hbaseconnectors": "hbase-connectors",
    "spark4hbase": "spark4-hbase-connectors",
}


def static_components() -> List[str]:
    """Built-in catalog (profiles + known extras). No Jira call."""
    return sorted(set(cp.PROFILES) | _EXTRA_COMPONENTS)


def list_components(release: Optional[str] = None) -> List[str]:
    """Catalog only, or catalog merged with OSV Jira when release is set."""
    static = static_components()
    if not release:
        return static
    try:
        import cve_full_analysis as fa
        osv = fa.discover_osv_components(release)
        return sorted(set(static) | set(osv))
    except Exception:
        return static


def resolve_component(name: str) -> Tuple[Optional[str], List[str]]:
    """Return (canonical_name, suggestions).

    On success suggestions is empty. On failure canonical is None and
    suggestions holds close matches (or the full list if nothing is close).
    """
    raw = (name or "").strip()
    if not raw:
        return None, list_components()
    key = raw.lower().replace(" ", "-").replace("_", "-")
    # allow underscores as hyphens for lookup in aliases / profiles
    key_us = raw.lower().replace(" ", "_")
    comps = list_components()
    comps_l = {c.lower(): c for c in comps}

    if key in _ALIASES:
        return _ALIASES[key], []
    if key_us in _ALIASES:
        return _ALIASES[key_us], []
    if key in comps_l:
        return comps_l[key], []
    if key_us in comps_l:
        return comps_l[key_us], []
    # profile keys may use underscores (livy3_3_5_1)
    if raw.lower() in comps_l:
        return comps_l[raw.lower()], []

    suggestions = difflib.get_close_matches(
        key, [c.lower() for c in comps], n=8, cutoff=0.45)
    # map back to canonical casing
    sug = [comps_l.get(s, s) for s in suggestions]
    if not sug:
        sug = comps[:20]
    return None, sug


def component_meta(name: str, release: str = "") -> Dict:
    """Profile fields when available; otherwise sensible ODP defaults."""
    rel = (release or os.environ.get("CVE_ADDRESS_RELEASE")
           or os.environ.get("CVE_RELEASE") or "")
    jdk = cp.jdk_major_for_release(rel) or 8
    if name in cp.PROFILES:
        p = cp.get_profile(name, release=rel or None)
        return {
            "name": name,
            "repo": p.get("repo") or f"sehajsandhu/{name}",
            "git_url": p.get("git_url") or f"https://github.com/acceldata-io/{name}.git",
            "workdir": p.get("workdir") or f"~/cve_fix_workdir/{name}",
            "pom_path": p.get("pom_path"),
            "build_cmd": p.get("build_cmd"),
            "build_tool": p.get("build_tool", "maven"),
            "java_home": p.get("java_home"),
            "jdk_version": p.get("jdk_version"),
            "effective_release": p.get("effective_release", rel),
            "has_profile": True,
        }
    return {
        "name": name,
        "repo": f"sehajsandhu/{name}",
        "git_url": f"https://github.com/acceldata-io/{name}.git",
        "workdir": f"~/cve_fix_workdir/{name}",
        "pom_path": "pom.xml",
        "build_cmd": ("mvn -DskipTests -Dmaven.test.skip=true "
                      "-Dcheckstyle.skip=true -Drat.skip=true "
                      "-Dmaven.javadoc.skip=true clean install"),
        "build_tool": "maven",
        "java_home": cp.resolve_java_home(jdk),
        "jdk_version": jdk,
        "effective_release": rel,
        "has_profile": False,
    }


def pick_reviewer(reviewers: Optional[List[str]] = None) -> str:
    pool = reviewers or DEFAULT_REVIEWERS
    return random.choice(pool)


def build_address_goal(
    component: str,
    release: str,
    checkout_branch: str,
    pr_base: str,
    reviewers: Optional[List[str]] = None,
) -> str:
    """Build the natural-language goal the agent executes for --address."""
    meta = component_meta(component, release=release)
    reviewer = pick_reviewer(reviewers)
    reviewer_list = ", ".join(reviewers or DEFAULT_REVIEWERS)
    build_hint = meta["build_cmd"] or "(discover build command from the repo)"
    tool_hint = meta["build_tool"]
    jdk = meta.get("jdk_version")
    jh = meta.get("java_home") or "(set CVE_JAVA_HOME_8 / CVE_JAVA_HOME_11)"

    return f"""Address ALL To-Do OSV CVEs for component '{component}' on release base {release}.

SCOPE (strict):
- release = {release} ONLY (pass release={release} / include_keys on every reclassify).
- component / cve-repo = {meta['repo']} (repo_substr '{component}').
- Do NOT touch other releases or other components.

REPO / BRANCHES:
- git_url = {meta['git_url']}
- workdir = {meta['workdir']}
- checkout branch (apply fixes here) = {checkout_branch}
- open PRs against = {pr_base}
- build_tool = {tool_hint}
- build_cmd = {build_hint}
- ODP JDK policy: release {release} → JDK {jdk} (JAVA_HOME={jh})
- has_cve_profile = {meta['has_profile']}

WORKFLOW:
1) TRIAGE first (read-only):
   - query_release / query_cve for this component + release, status To Do.
   - For each CVE call analyse_upstream (with current_version) to decide:
       FIX (drop-in version bump), EXCEPTION, or HUMAN (needs code changes /
       no clear bump / unclear ownership) — leave HUMAN ones alone and list them
       at the end for human intervention.
   - Apply known rules: shaded/fat-jar, platform-owned, jetty 9.4.x without
     same-major fix, libthrift breaking-major, base-image/OS-owned, R9
     JDK/Python incompatibility → EXCEPTION (not FIX).

2) EXCEPTIONS (writes, approval-gated):
   - Move to 'Exception Request' with exception_reason (Deferred / Not Exploitable /
     Spark Transitive) and a one-line CVE-Transition-Details justification.
   - Always pass release={release}.

3) FIXES — group by library, one PR per library bump:
   - Clone/refresh {meta['git_url']} into {meta['workdir']}.
   - Checkout {checkout_branch}, create a new branch named after one OSV key from
     the group (e.g. OSV-23906). Prefer one branch/PR covering all To-Do CVEs
     for the SAME lib (same artifact / family).
   - Bump the library to the agreed target (prefer the common/highest safe version
     that covers the group; verify with analyse_upstream / check_repo_version).
   - Compile with the build_cmd above (or the repo's real build). If the build
     FAILS: do NOT force the bump — mark that CVE/group as HUMAN intervention,
     leave the Jira in To Do, and continue with other libs. Emit [ESCALATE] only
     if a small compile fix is clearly in reach.
   - If the build PASSES:
       * commit with EXACTLY this subject format:
         <OSV-id> - CVE - Bumping-up <lib name> to <lib version> to fix <CVE_ID>
         (use the branch's OSV id and a representative CVE_ID; mention other
         OSV keys in the commit body if the PR covers multiple).
       * push the branch.
       * create a PR against {pr_base}; assign reviewer '{reviewer}'
         (chosen randomly from: {reviewer_list}).
       * For EVERY OSV ticket that shares this bumped lib: add a comment with
         the PR URL/id, then transition status to CLOSED (release-scoped).

4) REPEAT until every To-Do OSV for this component+release is either CLOSED,
   Exception Request, or listed under HUMAN INTERVENTION.

5) FINAL SUMMARY (terse table):
   CLOSED (with PR) | EXCEPTION (reason) | HUMAN (why left) — counts + keys.

Start by listing the To-Do CVEs and your FIX/EXCEPTION/HUMAN plan; then execute
writes only after showing each batch for approval.
"""


def _component_tags(name: str, osv_names: Optional[set] = None) -> str:
    tags: List[str] = []
    if name in cp.PROFILES:
        tags.append("profile")
    elif name in _EXTRA_COMPONENTS:
        tags.append("extra")
    if osv_names is not None and name in osv_names:
        tags.append("osv")
    return f" ({', '.join(tags)})" if tags else ""


def print_component_list(suggestions: Optional[List[str]] = None,
                         query: str = "", release: str = "") -> None:
    osv_stats: Dict[str, Dict] = {}
    osv_names: Optional[set] = None
    if suggestions is None and release:
        import cve_full_analysis as fa
        print(f"Fetching OSV components for release {release} …")
        osv_stats = fa.osv_component_stats(release)
        osv_names = set(osv_stats)
        comps = list_components(release)
    else:
        comps = suggestions if suggestions is not None else static_components()

    if query:
        print(f"Unknown component: {query!r}")
        print("Did you mean:")
    elif release and suggestions is None:
        static_n = len(static_components())
        osv_only = sorted((osv_names or set()) - set(static_components()))
        print(f"Components for release {release} "
              f"({len(comps)} total — catalog {static_n}, "
              f"OSV {len(osv_names or [])}, OSV-only {len(osv_only)}):")
        if osv_only:
            print(f"  OSV-only (not in static catalog): {', '.join(osv_only)}")
        print()
    else:
        print("Available components (static catalog — use "
              "--list-components --release 3.3.6.4 for OSV Jira list):")

    for c in comps:
        tags = _component_tags(c, osv_names)
        counts = ""
        if osv_stats and c in osv_stats:
            s = osv_stats[c]
            counts = f"  [{s['todo']} todo / {s['total']} total]"
        print(f"  - {c}{tags}{counts}")

    print(f"\nTotal: {len(comps)}"
          + (" matched" if suggestions is not None and query else " listed"))
    print("Usage: python3 cve_agent.py --address <component> "
          "[--release 3.3.6.4] [--branch nightly/3.3.6.5] "
          "[--pr-base nightly/3.3.6.5]")
    if not release:
        print("       python3 cve_agent.py --list-components "
              "--release 3.3.6.4")


def parse_list_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="cve_agent.py --list-components",
        description="List addressable components (optionally from OSV Jira).")
    ap.add_argument("--release",
                    default=os.environ.get("CVE_RELEASE", ""),
                    help="merge components seen in OSV Jira for this release "
                         "(needs Jira creds)")
    return ap.parse_args(argv)


def parse_address_args(argv: List[str]) -> argparse.Namespace:
    """Parse args after '--address' (argv[0] may be the component or a flag)."""
    ap = argparse.ArgumentParser(
        prog="cve_agent.py --address",
        description="Address all To-Do CVEs for one component (agent-driven).")
    ap.add_argument("component", nargs="?", default="",
                    help="component name (e.g. zookeeper). Omit to list.")
    ap.add_argument("--release",
                    default=os.environ.get("CVE_ADDRESS_RELEASE", "3.3.6.4"),
                    help="OSV release baseline (default 3.3.6.4 or "
                         "CVE_ADDRESS_RELEASE)")
    ap.add_argument("--branch",
                    default=os.environ.get("CVE_ADDRESS_BRANCH",
                                           "nightly/3.3.6.5"),
                    help="git branch to checkout and fix on "
                         "(default nightly/3.3.6.5 or CVE_ADDRESS_BRANCH)")
    ap.add_argument("--pr-base",
                    default=os.environ.get("CVE_ADDRESS_PR_BASE",
                                           "nightly/3.3.6.5"),
                    help="PR target branch (default nightly/3.3.6.5 or "
                         "CVE_ADDRESS_PR_BASE)")
    ap.add_argument("--reviewers",
                    default=os.environ.get("CVE_ADDRESS_REVIEWERS", ""),
                    help="comma-separated reviewer logins (default built-in list)")
    return ap.parse_args(argv)


def run_address_cli(argv: List[str], run_agent_cb) -> int:
    """Entry used by cve_agent.main.

    ``run_agent_cb(goal, cost_tracker=None)`` starts the agent; when a tracker
    is passed, each API turn is attributed to a workflow phase.
    """
    args = parse_address_args(argv)
    if not args.component:
        print_component_list(release=args.release)
        return 0

    name, suggestions = resolve_component(args.component)
    if not name:
        print_component_list(suggestions=suggestions, query=args.component)
        return 2

    reviewers = None
    if args.reviewers.strip():
        reviewers = [r.strip() for r in args.reviewers.split(",") if r.strip()]

    meta = component_meta(name, release=args.release)
    jdk = meta.get("jdk_version")
    print(f"[address] component={name}  release={args.release}  jdk={jdk}")
    print(f"          checkout={args.branch}  pr_base={args.pr_base}")
    print(f"          repo={meta['repo']}  git={meta['git_url']}")
    print(f"          profile={'yes' if meta['has_profile'] else 'no (inferred)'}")

    import cve_cost_tracker as ct
    # rates_for is injected by cve_agent when available
    rates_for = getattr(run_address_cli, "_rates_for", None)
    tracker = ct.ComponentCostTracker(
        component=name, release=args.release, rates_for=rates_for)

    goal = build_address_goal(
        name, release=args.release, checkout_branch=args.branch,
        pr_base=args.pr_base, reviewers=reviewers)
    try:
        run_agent_cb(goal, cost_tracker=tracker)
    finally:
        record = tracker.to_run_record()
        path = ct.save_run(record)
        ct.print_component_cost(record)
        print(f"\nCost ledger: {path}")
    return 0
