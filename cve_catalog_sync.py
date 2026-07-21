#!/usr/bin/env python3
"""
Sync cve_remediation_catalog / profile fix_targets from a --full-analysis report.

After scanning a new release (e.g. 3.3.6.5 or Ambari 3.0.0.2), libraries often
need *new* target versions. Instead of hand-editing the catalog:

  1. python3 cve_agent.py --full-analysis 3.3.6.5
  2. python3 cve_catalog_sync.py 3.3.6.5              # dry-run diff
  3. python3 cve_catalog_sync.py 3.3.6.5 --apply      # write release overrides

Or via the agent entrypoint:

  python3 cve_agent.py --sync-catalog 3.3.6.5
  python3 cve_agent.py --sync-catalog 3.3.6.5 --apply

What --apply does
-----------------
Writes ``reports/catalog_sync_<release>.json`` with per-component proposed
``fix_targets`` (family → max analysis target_version) and a summary of
exception reason counts from the analysis.

Also writes/updates ``cve_catalog_overrides.json`` (git-friendly), which
``cve_remediation_catalog.apply_release_overrides()`` merges into profiles at
import time — so ``CVE_PROFILE=odp-ambari`` picks up the new targets without
hand-editing the large catalog Python file.

Ambari note: Jira repo is ``sehajsandhu/ambari`` (comp name ``ambari``); catalog
key ``odp-ambari`` is aliased. For Ambari-only:

  python3 cve_full_analysis.py 3.0.0.2 --components ambari
  python3 cve_catalog_sync.py 3.0.0.2 --components ambari --apply
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import cve_env

cve_env.load_repo_env()

import cve_full_analysis as fa
import cve_remediation_catalog as cat

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(HERE, "reports")
OVERRIDES_PATH = os.path.join(HERE, "cve_catalog_overrides.json")

# Analysis component name (from Jira cve-repo) -> catalog key
COMP_ALIASES = {
    "ambari": "odp-ambari",
    "ch-ui": "clickhouse",
    "clickhouse": "clickhouse",
}

# Catalog fix_target.name / family aliases used when matching analysis families
FAMILY_TO_TARGET_NAMES = {
    "netty": ["netty", "hbase-shaded-netty"],
    "jackson": ["jackson", "jackson-databind"],
    "log4j": ["log4j2", "log4j"],
    "logback": ["logback"],
    "spring": ["spring-framework", "spring"],
    "spring-security": ["spring-security"],
    "spring-ldap": ["spring-ldap"],
    "commons-lang3": ["commons-lang3"],
    "commons-io": ["commons-io"],
    "commons-compress": ["commons-compress"],
    "commons-configuration2": ["commons-configuration2"],
    "postgresql": ["postgresql"],
    "nimbus-jose-jwt": ["nimbus-jose-jwt"],
    "mina": ["mina"],
    "jetty": ["jetty"],
    "tomcat": ["tomcat", "tomcat-embed"],
    "bouncycastle": ["bouncycastle"],
    "okio": ["okio"],
    "okhttp": ["okhttp"],
    "aircompressor": ["aircompressor"],
    "async-http-client": ["async-http-client"],
    "guava": ["guava"],
    "protobuf": ["protobuf"],
    "thrift": ["libthrift"],
}


def _analysis_path(release: str, explicit: str = "") -> str:
    if explicit:
        return os.path.expanduser(explicit)
    safe = release.replace("/", "_")
    return os.path.join(REPORT_DIR, f"full_analysis_{safe}.json")


def _catalog_key(comp: str) -> str:
    c = (comp or "").strip()
    if c in COMP_ALIASES:
        return COMP_ALIASES[c]
    if c in cat.COMPONENT_CATALOG:
        return c
    # try resolve alias reverse
    for k, v in cat.COMPONENT_CATALOG.items():
        if v.get("alias_of") == c:
            return k
    return c


def _load_analysis(release: str, path: str = "") -> Dict:
    p = _analysis_path(release, path)
    if not os.path.isfile(p):
        raise SystemExit(
            f"No analysis report at {p}\n"
            f"Run first: python3 cve_agent.py --full-analysis {release}"
        )
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _family_targets_from_comp(comp_data: Dict) -> Dict[str, Dict[str, Any]]:
    """family -> {target, current_versions, cves, keys} from FIX rows."""
    by_fam: Dict[str, Dict[str, Any]] = {}
    for row in comp_data.get("cves") or []:
        if row.get("decision") != "FIX":
            continue
        fam = row.get("family") or fa.lib_family(row.get("lib") or "")
        tgt = row.get("target_version") or ""
        if not fam or not tgt:
            continue
        e = by_fam.setdefault(fam, {
            "targets": [],
            "currents": set(),
            "cves": 0,
            "keys": [],
            "libs": set(),
        })
        e["targets"].append(tgt)
        if row.get("current_version"):
            e["currents"].add(row["current_version"])
        e["cves"] += 1
        e["keys"].append(row["key"])
        if row.get("lib"):
            e["libs"].add(row["lib"])
    out = {}
    for fam, e in by_fam.items():
        best = max(e["targets"], key=fa._ver_key)
        out[fam] = {
            "target_version": best,
            "current_versions": sorted(e["currents"], key=fa._ver_key),
            "cves": e["cves"],
            "keys": e["keys"],
            "libs": sorted(e["libs"]),
        }
    return out


def _match_existing_target(entry: Dict, family: str) -> Optional[Dict]:
    """Find an existing fix_target in catalog entry for this analysis family."""
    names = FAMILY_TO_TARGET_NAMES.get(family, [family])
    for t in entry.get("fix_targets") or []:
        tn = (t.get("name") or "").lower()
        if tn in {n.lower() for n in names}:
            return t
        # regex / name contains family token
        if family.lower() in tn:
            return t
    return None


def propose_sync(
    report: Dict,
    components: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a proposal: bumps, new targets, exception tallies per component."""
    allow = {c.lower() for c in components} if components else None
    proposal = {
        "release": report.get("release"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_generated_at": report.get("generated_at"),
        "components": {},
        "summary": {
            "bumps": 0,
            "new_targets": 0,
            "unchanged": 0,
            "unknown_components": [],
        },
    }

    for comp, data in sorted((report.get("components") or {}).items()):
        if allow and comp.lower() not in allow:
            continue
        ckey = _catalog_key(comp)
        fam_tgts = _family_targets_from_comp(data)
        exc_reasons = Counter(
            (row.get("reason") or "unknown")
            for row in (data.get("cves") or [])
            if row.get("decision") == "EXCEPTION"
        )

        try:
            entry = cat.resolve_entry(ckey)
            in_catalog = True
        except KeyError:
            entry = {"fix_targets": [], "exception_rules": []}
            in_catalog = False
            proposal["summary"]["unknown_components"].append(comp)

        bumps = []
        new_targets = []
        unchanged = []
        for fam, info in sorted(fam_tgts.items()):
            new_ver = info["target_version"]
            existing = _match_existing_target(entry, fam) if in_catalog else None
            if existing:
                old = existing.get("target_version") or ""
                if old and fa._cmp_ver(new_ver, old) > 0:
                    bumps.append({
                        "family": fam,
                        "name": existing.get("name"),
                        "old_target": old,
                        "new_target": new_ver,
                        "cves": info["cves"],
                        "keys": info["keys"][:8],
                        "current_versions": info["current_versions"],
                    })
                    proposal["summary"]["bumps"] += 1
                elif old and fa._cmp_ver(new_ver, old) <= 0:
                    unchanged.append({
                        "family": fam,
                        "name": existing.get("name"),
                        "catalog_target": old,
                        "analysis_target": new_ver,
                        "cves": info["cves"],
                    })
                    proposal["summary"]["unchanged"] += 1
                else:
                    bumps.append({
                        "family": fam,
                        "name": existing.get("name"),
                        "old_target": old or "(none)",
                        "new_target": new_ver,
                        "cves": info["cves"],
                        "keys": info["keys"][:8],
                        "current_versions": info["current_versions"],
                    })
                    proposal["summary"]["bumps"] += 1
            else:
                new_targets.append({
                    "family": fam,
                    "suggested_name": fam,
                    "target_version": new_ver,
                    "cves": info["cves"],
                    "libs": info["libs"][:5],
                    "keys": info["keys"][:8],
                    "note": (
                        "No matching fix_target in catalog — add a patch stanza "
                        "manually (property/dependency names), then set target_version."
                    ),
                })
                proposal["summary"]["new_targets"] += 1

        # Build override fix_targets list (only version bumps of known targets)
        override_targets = []
        for b in bumps:
            override_targets.append({
                "name": b["name"],
                "target_version": b["new_target"],
                "family": b["family"],
                "source": "full_analysis",
            })

        proposal["components"][ckey] = {
            "jira_comp": comp,
            "in_catalog": in_catalog,
            "analysis_todo": data.get("todo"),
            "analysis_fix": data.get("fix"),
            "analysis_exception": data.get("exception"),
            "bumps": bumps,
            "new_targets": new_targets,
            "unchanged": unchanged,
            "exception_reason_counts": dict(exc_reasons),
            "override_fix_targets": override_targets,
        }

    return proposal


def print_proposal(proposal: Dict) -> None:
    print("\n" + "=" * 78)
    print(f"CATALOG SYNC — release {proposal.get('release')}")
    print("=" * 78)
    s = proposal["summary"]
    print(f"Version bumps (catalog target ↑): {s['bumps']}")
    print(f"New families (need manual patch): {s['new_targets']}")
    print(f"Unchanged / already ≥ analysis:   {s['unchanged']}")
    if s.get("unknown_components"):
        print(f"Unknown comps (no catalog yet):   {', '.join(s['unknown_components'])}")

    for ckey, d in sorted(proposal["components"].items()):
        if not (d["bumps"] or d["new_targets"]):
            continue
        print(f"\n## {ckey}  (jira={d['jira_comp']}, "
              f"FIX={d['analysis_fix']}, EXC={d['analysis_exception']})")
        for b in d["bumps"]:
            print(f"  BUMP  {b['name'] or b['family']:28} "
                  f"{b['old_target']:>16} -> {b['new_target']:<16}  "
                  f"({b['cves']} CVEs)")
        for n in d["new_targets"]:
            print(f"  NEW   {n['suggested_name']:28} "
                  f"{'—':>16} -> {n['target_version']:<16}  "
                  f"({n['cves']} CVEs)  [add patch manually]")
        if d.get("exception_reason_counts"):
            top = sorted(d["exception_reason_counts"].items(),
                         key=lambda kv: -kv[1])[:5]
            print("  EXC reasons:", ", ".join(f"{r}×{n}" for r, n in top))


def apply_proposal(proposal: Dict, overrides_path: str = OVERRIDES_PATH) -> str:
    """Merge bump overrides into cve_catalog_overrides.json."""
    existing: Dict[str, Any] = {}
    if os.path.isfile(overrides_path):
        with open(overrides_path, encoding="utf-8") as fh:
            existing = json.load(fh)

    # Structure: { "releases": { rel: {...} }, "active_release": rel, "components": {..} }
    # "components" holds the merged latest target_version overrides by catalog key.
    releases = existing.setdefault("releases", {})
    rel = proposal["release"]
    releases[rel] = {
        "generated_at": proposal["generated_at"],
        "components": {
            k: {
                "override_fix_targets": v.get("override_fix_targets") or [],
                "new_targets": v.get("new_targets") or [],
                "exception_reason_counts": v.get("exception_reason_counts") or {},
            }
            for k, v in proposal["components"].items()
        },
    }
    existing["active_release"] = rel

    comps = existing.setdefault("components", {})
    for ckey, d in proposal["components"].items():
        slot = comps.setdefault(ckey, {"fix_target_versions": {}})
        versions = slot.setdefault("fix_target_versions", {})
        for t in d.get("override_fix_targets") or []:
            name = t.get("name")
            ver = t.get("target_version")
            if name and ver:
                versions[name] = ver
        slot["updated_from_release"] = rel
        slot["updated_at"] = proposal["generated_at"]

    with open(overrides_path, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2)
        fh.write("\n")
    return overrides_path


def write_report(proposal: Dict, release: str) -> str:
    os.makedirs(REPORT_DIR, exist_ok=True)
    safe = release.replace("/", "_")
    path = os.path.join(REPORT_DIR, f"catalog_sync_{safe}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(proposal, fh, indent=2)
        fh.write("\n")
    return path


def run_sync(
    release: str,
    analysis_path: str = "",
    components: Optional[List[str]] = None,
    apply: bool = False,
) -> Dict:
    report = _load_analysis(release, analysis_path)
    proposal = propose_sync(report, components=components)
    print_proposal(proposal)
    out = write_report(proposal, release)
    print(f"\nWrote proposal: {out}")
    if apply:
        op = apply_proposal(proposal)
        print(f"Applied overrides: {op}")
        print("Re-import cve_profiles (or re-run fixer) to pick up new target_versions.")
        print("Note: NEW families still need a manual patch stanza in "
              "cve_remediation_catalog.py — only version bumps of existing "
              "fix_targets are auto-applied.")
    else:
        print("\nDry-run only. Re-run with --apply to write cve_catalog_overrides.json")
    return proposal


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("release", help="release id, e.g. 3.3.6.5 or 3.0.0.2")
    ap.add_argument("--analysis", default="",
                    help="path to full_analysis JSON (default reports/full_analysis_<rel>.json)")
    ap.add_argument("--components", nargs="*", default=None,
                    help="limit to Jira component names (e.g. ambari zeppelin)")
    ap.add_argument("--apply", action="store_true",
                    help="write cve_catalog_overrides.json (default: dry-run)")
    args = ap.parse_args(argv)
    run_sync(args.release, analysis_path=args.analysis,
             components=args.components, apply=args.apply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
