"""
cve_full_analysis.py — release-wide FIX vs EXCEPTION analysis.

Deterministic (no LLM required): fetch OSV tickets for a release, classify each
To-Do as FIX or EXCEPTION, list per-component lib/current/target versions, and
suggest a cross-component *common* bump version (the highest target needed so
one version covers the most CVEs — e.g. netty 4.1.135.Final for all comps).

Usage:
    python3 cve_full_analysis.py 3.3.6.4
    python3 cve_agent.py --full-analysis 3.3.6.4

Outputs a human summary on stdout and a JSON report under reports/.
Meters wall-time / ticket counts per phase and per component.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import cve_analyser as ca
import cve_profiles as cp


HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(HERE, "reports")

# Python components — Java jars inside them are usually transitive/bundled.
_PY_COMPS = {"airflow", "hue", "jupyterhub", "superset"}
_PLATFORM_OWNED = ("hadoop", "zookeeper")
_BREAKING = {"libthrift", "thrift"}


# ---------------------------------------------------------------------------
# Usage / phase meter
# ---------------------------------------------------------------------------
@dataclass
class PhaseUsage:
    name: str
    started: float = 0.0
    ended: float = 0.0
    tickets: int = 0
    notes: Dict = field(default_factory=dict)

    @property
    def seconds(self) -> float:
        if not self.started:
            return 0.0
        end = self.ended or time.time()
        return round(end - self.started, 3)


@dataclass
class CompUsage:
    component: str
    tickets: int = 0
    fix: int = 0
    exception: int = 0
    seconds: float = 0.0


class UsageMonitor:
    """Tracks wall-time and ticket counts per phase and per component."""

    def __init__(self):
        self.phases: Dict[str, PhaseUsage] = {}
        self.components: Dict[str, CompUsage] = {}
        self.started = time.time()

    def begin(self, name: str, **notes) -> PhaseUsage:
        p = PhaseUsage(name=name, started=time.time(), notes=dict(notes))
        self.phases[name] = p
        print(f"\n[{name}] starting…")
        return p

    def end(self, name: str, tickets: int = 0, **notes) -> PhaseUsage:
        p = self.phases[name]
        p.ended = time.time()
        p.tickets = tickets
        p.notes.update(notes)
        print(f"[{name}] done in {p.seconds}s  (tickets={tickets}"
              + (f", {notes}" if notes else "") + ")")
        return p

    def record_comp(self, component: str, tickets: int, fix: int,
                    exception: int, seconds: float) -> None:
        self.components[component] = CompUsage(
            component=component, tickets=tickets, fix=fix,
            exception=exception, seconds=round(seconds, 3))

    def summary(self) -> Dict:
        return {
            "total_seconds": round(time.time() - self.started, 3),
            "phases": {n: {"seconds": p.seconds, "tickets": p.tickets,
                           **p.notes} for n, p in self.phases.items()},
            "components": {c: asdict(u) for c, u in
                           sorted(self.components.items(),
                                  key=lambda kv: -kv[1].tickets)},
        }

    def print_usage(self) -> None:
        print("\n" + "=" * 78)
        print("USAGE MONITOR")
        print("=" * 78)
        print(f"{'PHASE':24}{'SECONDS':>10}{'TICKETS':>10}")
        print("-" * 44)
        for n, p in self.phases.items():
            print(f"{n:24}{p.seconds:>10.2f}{p.tickets:>10}")
        print("-" * 44)
        print(f"{'TOTAL':24}{time.time()-self.started:>10.2f}")
        if self.components:
            print(f"\n{'COMPONENT':24}{'SEC':>8}{'TODO':>8}{'FIX':>8}{'EXC':>8}")
            print("-" * 56)
            for c, u in sorted(self.components.items(),
                               key=lambda kv: -kv[1].tickets):
                print(f"{c:24}{u.seconds:>8.2f}{u.tickets:>8}"
                      f"{u.fix:>8}{u.exception:>8}")


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------
def _ver_tuple(v: str) -> Optional[Tuple[int, ...]]:
    if not v:
        return None
    nums = re.findall(r"\d+", str(v))
    if not nums:
        return None
    return tuple(int(x) for x in nums[:4])


def _ver_key(v: str) -> Tuple:
    t = _ver_tuple(v)
    return t if t else (0,)


def _cmp_ver(a: str, b: str) -> int:
    """Return -1/0/1 comparing a vs b (numeric)."""
    ta, tb = _ver_key(a), _ver_key(b)
    # pad
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def parse_fix_versions(fix_text: str) -> List[str]:
    """Extract candidate version strings from Jira 'fixed in …' text."""
    if not fix_text:
        return []
    # Prefer the "fixed in X, Y" clause when present
    m = re.search(r"fixed\s+in\s+(.+)", fix_text, re.IGNORECASE)
    blob = m.group(1) if m else fix_text
    # Split on commas / 'and' / whitespace runs; keep tokens that look like versions
    parts = re.split(r"[,;/]|\\band\\b", blob, flags=re.IGNORECASE)
    out = []
    for p in parts:
        p = p.strip().strip(".")
        # accept 4.1.135.Final, 2.13.4.2, 9.4.57.v20241219, 3.18.0
        if re.match(r"^\d+(?:\.\d+)+(?:\.[A-Za-z0-9_-]+)?$", p):
            out.append(p)
        else:
            # sometimes "4.1.135.Final (recommended)"
            m2 = re.match(r"^(\d+(?:\.\d+)+(?:\.[A-Za-z0-9_-]+)?)", p)
            if m2:
                out.append(m2.group(1))
    # de-dupe preserve order
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def pick_target(current: str, fixed_list: List[str]) -> str:
    """Smallest fixed version strictly greater than current (else highest)."""
    if not fixed_list:
        return ""
    keyed = sorted(fixed_list, key=_ver_key)
    if current and _ver_tuple(current):
        for f in keyed:
            if _cmp_ver(f, current) > 0:
                return f
    return keyed[-1]  # already at/above all listed -> show highest known fix


def lib_family(lib: str) -> str:
    """Normalize artifact to a family for cross-component alignment."""
    art = ca.affected_artifact(lib).lower()
    if not art:
        return "(unknown)"
    if art.startswith("netty") or art.startswith("netty-"):
        return "netty"
    if "jackson" in art:
        return "jackson"
    if "jetty" in art:
        return "jetty"
    if art.startswith("log4j"):
        return "log4j"
    if art.startswith("commons-"):
        return art  # commons-lang3 / commons-io are distinct
    if "protobuf" in art:
        return "protobuf"
    if art in ("libthrift", "thrift"):
        return "thrift"
    if "snakeyaml" in art or art == "yaml":
        return "snakeyaml"
    if "guava" in art:
        return "guava"
    if "gson" in art:
        return "gson"
    if "okhttp" in art:
        return "okhttp"
    if "httpclient" in art or art == "httpcore":
        return art
    return art


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def _build_type(comp: str) -> str:
    try:
        return cp.profile_env(cp.get_profile(comp))["build_tool"]
    except SystemExit:
        return "python" if comp in _PY_COMPS else "maven"


def _has_no_fix(fix: str) -> bool:
    f = (fix or "").strip().lower()
    if not f:
        return True
    if (("open" in f or "no fix" in f or "n/a" in f or "not yet" in f)
            and not re.search(r"\d", f)):
        return True
    return False


def _is_java_lib(lib: str) -> bool:
    l = (lib or "").lower()
    return ("." in l or "_" in l or
            l in {"libthrift", "thrift", "gson", "dnsjava",
                  "jackson-mapper-asl", "swagger-ui", "snappy-java", "guava"})


def classify_ticket(r: Dict, btype: str) -> Tuple[str, str]:
    """Return (FIX|EXCEPTION, reason)."""
    if _has_no_fix(r["fix"]):
        return "EXCEPTION", "no upstream fix"
    art = ca.affected_artifact(r["lib"]).lower()
    jar = ca.jar_filename(r["path"]).lower()
    if (jar and any(x in jar for x in
                    ("shaded", "bundle", "-all", "with-dependencies", "uber"))
            and art and art not in jar):
        return "EXCEPTION", "shaded/fat-jar (owner-fixed)"
    if (any(p in art for p in _PLATFORM_OWNED)
            and r["comp"] not in ("hadoop", "zookeeper", "ozone")):
        return "EXCEPTION", "platform-owned (hadoop/zookeeper)"
    if art in _BREAKING:
        return "EXCEPTION", "breaking-major (libthrift/thrift)"
    # jetty 9.4.x: same-major fix only; 10/11/12 need jakarta + newer JDK
    if "jetty" in art:
        cur_m = re.match(r"(\d+)", r["ver"] or "")
        cur = cur_m.group(1) if cur_m else None
        fvs = parse_fix_versions(r["fix"])
        if cur and fvs and not any(v.split(".")[0] == cur for v in fvs):
            return "EXCEPTION", "jetty no same-major fix (breaking-major/JDK)"
    if btype == "python" and _is_java_lib(r["lib"]):
        return "EXCEPTION", "java-transitive in python component"
    # Go-stdlib / base-image hints in path or lib
    blob = f"{r['lib']} {r['path']}".lower()
    if any(x in blob for x in ("stdlib", "go-stdlib", "glibc", "openssl",
                               "ubi", "/usr/lib64/")):
        return "EXCEPTION", "base-image / OS-owned"
    return "FIX", "version bump"


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------
def fetch_release_tickets(release: str, repo_substr: str = "sehajsandhu/",
                          severities: Optional[List[str]] = None,
                          statuses: Optional[List[str]] = None,
                          components: Optional[List[str]] = None) -> List[Dict]:
    sev = severities or ["Critical", "High", "Medium"]
    parts = [
        "project = OSV",
        f'"cve-found-in-release-version[short text]" ~ "{release}"',
        f'"cve-severity[dropdown]" IN ({", ".join(sev)})',
    ]
    if components:
        # Narrow to the requested components (OR of cve-repo substrings).
        ors = " OR ".join(
            f'"cve-repo[short text]" ~ "{c}"' for c in components)
        parts.append(f"({ors})")
    elif repo_substr:
        parts.append(f'"cve-repo[short text]" ~ "{repo_substr}"')
    if statuses:
        parts.append("status IN (" + ", ".join(f'"{s}"' for s in statuses) + ")")
    jql = " AND ".join(parts) + " ORDER BY created DESC"

    fields = ("key,summary,status,customfield_10870,customfield_10888,"
              "customfield_10127,customfield_10875,customfield_10892,"
              "customfield_10891,customfield_10126")
    out: List[Dict] = []
    token = None
    page = 0
    while True:
        page += 1
        url = (f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql"
               f"?jql={urllib.parse.quote(jql)}&maxResults=100&fields={fields}")
        if token:
            url += f"&nextPageToken={urllib.parse.quote(token)}"
        r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                           auth=(ca.EMAIL, ca.API_TOKEN))
        if r.status_code != 200:
            raise RuntimeError(f"Jira HTTP {r.status_code}: {r.text[:300]}")
        d = r.json()
        for it in d.get("issues", []):
            f = it["fields"]
            repo = f.get("customfield_10870") or ""
            comp = repo.split("/", 1)[1].strip() if "/" in repo else (repo or "UNKNOWN")
            out.append({
                "key": it["key"],
                "status": (f.get("status") or {}).get("name", ""),
                "comp": comp,
                "repo": repo,
                "cve": ca.extract_cve_id(it["key"], f.get("summary", "") or "",
                                         f.get("customfield_10127", "") or ""),
                "lib": f.get("customfield_10875", "") or "",
                "ver": f.get("customfield_10892", "") or "",
                "fix": ca.extract_fixed_version(f.get("customfield_10891")),
                "sev": ca.extract_dropdown(f.get("customfield_10126")),
                "path": f.get("customfield_10888", "") or "",
            })
        print(f"  page {page}: {len(out)} tickets so far")
        token = d.get("nextPageToken")
        if d.get("isLast", True) or not token:
            break
    return out


def discover_osv_components(release: str, repo_substr: str = "sehajsandhu/",
                            severities: Optional[List[str]] = None) -> List[str]:
    """Distinct cve-repo component names from OSV Jira for a release."""
    rows = fetch_release_tickets(release, repo_substr=repo_substr,
                                 severities=severities)
    return sorted({r["comp"] for r in rows
                   if r.get("comp") and r["comp"] != "UNKNOWN"})


def osv_component_stats(release: str, repo_substr: str = "sehajsandhu/",
                        severities: Optional[List[str]] = None) -> Dict[str, Dict]:
    """Per-component ticket totals and To-Do counts from OSV Jira."""
    rows = fetch_release_tickets(release, repo_substr=repo_substr,
                                 severities=severities)
    total: Counter = Counter()
    todo: Counter = Counter()
    for r in rows:
        c = r.get("comp") or "UNKNOWN"
        total[c] += 1
        if r.get("status") == "To Do":
            todo[c] += 1
    return {c: {"total": total[c], "todo": todo[c]}
            for c in sorted(total)}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyse_release(release: str, repo_substr: str = "sehajsandhu/",
                    only_todo: bool = True,
                    components: Optional[List[str]] = None) -> Dict:
    mon = UsageMonitor()

    # Phase 1: fetch
    mon.begin("fetch", release=release)
    rows = fetch_release_tickets(release, repo_substr=repo_substr,
                                 components=components)
    mon.end("fetch", tickets=len(rows))

    by_status = dict(Counter(r["status"] for r in rows))
    work = [r for r in rows if (not only_todo) or r["status"] == "To Do"]
    if components:
        allow = {c.lower() for c in components}
        work = [r for r in work if r["comp"].lower() in allow]

    # Phase 2: classify
    mon.begin("classify")
    classified: List[Dict] = []
    per_comp: Dict[str, Dict] = {}
    for comp in sorted(set(r["comp"] for r in work)):
        t0 = time.time()
        btype = _build_type(comp)
        ct = [r for r in work if r["comp"] == comp]
        fix_n = exc_n = 0
        items = []
        reasons = Counter()
        for r in ct:
            decision, reason = classify_ticket(r, btype)
            fvs = parse_fix_versions(r["fix"])
            target = pick_target(r["ver"], fvs) if decision == "FIX" else ""
            row = {
                "key": r["key"], "cve": r["cve"], "lib": r["lib"],
                "artifact": ca.affected_artifact(r["lib"]),
                "family": lib_family(r["lib"]),
                "current_version": r["ver"],
                "proposed_fix_text": r["fix"],
                "fix_versions": fvs,
                "target_version": target,
                "severity": r["sev"],
                "decision": decision,
                "reason": reason,
                "path": r["path"],
            }
            items.append(row)
            classified.append({**row, "comp": comp, "build_type": btype})
            if decision == "FIX":
                fix_n += 1
            else:
                exc_n += 1
                reasons[reason] += 1
        elapsed = time.time() - t0
        mon.record_comp(comp, len(ct), fix_n, exc_n, elapsed)
        per_comp[comp] = {
            "build_type": btype,
            "todo": len(ct),
            "fix": fix_n,
            "exception": exc_n,
            "exception_reasons": dict(reasons),
            "cves": items,
        }
    mon.end("classify", tickets=len(work),
            fix=sum(1 for r in classified if r["decision"] == "FIX"),
            exception=sum(1 for r in classified if r["decision"] == "EXCEPTION"))

    # Phase 3: cross-component common-version alignment
    mon.begin("align")
    alignment = suggest_common_versions(classified)
    mon.end("align", tickets=len(alignment))

    # Phase 4: assemble report
    mon.begin("report")
    report = {
        "release": release,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo_substr": repo_substr,
        "totals": {
            "reported_all_statuses": len(rows),
            "by_status": by_status,
            "analysed": len(work),
            "fix": sum(1 for r in classified if r["decision"] == "FIX"),
            "exception": sum(1 for r in classified
                             if r["decision"] == "EXCEPTION"),
        },
        "exception_reasons": dict(Counter(
            r["reason"] for r in classified if r["decision"] == "EXCEPTION")),
        "components": per_comp,
        "common_version_suggestions": alignment,
        "usage": mon.summary(),
    }
    os.makedirs(REPORT_DIR, exist_ok=True)
    safe = release.replace("/", "_")
    out_path = os.path.join(REPORT_DIR, f"full_analysis_{safe}.json")
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    mon.end("report", tickets=0, path=out_path)
    report["report_path"] = out_path
    report["_monitor"] = mon
    return report


def suggest_common_versions(classified: List[Dict]) -> List[Dict]:
    """For each lib family, recommend the highest target version needed across
    components so one bump covers the most FIX CVEs (e.g. netty 4.1.135.Final
    if Hive needs it even when Hadoop only needs 4.1.133.Final)."""
    # family -> list of (comp, key, cve, current, target)
    by_fam: Dict[str, List[Dict]] = defaultdict(list)
    for r in classified:
        if r["decision"] != "FIX" or not r["target_version"]:
            continue
        by_fam[r["family"]].append(r)

    suggestions = []
    for fam, rows in sorted(by_fam.items(), key=lambda kv: -len(kv[1])):
        targets = [r["target_version"] for r in rows]
        recommended = max(targets, key=_ver_key)
        # How many FIX tickets does the recommended version cover?
        covered = sum(1 for r in rows
                      if _cmp_ver(recommended, r["target_version"]) >= 0)
        # Per-component current -> needed
        by_comp: Dict[str, Dict] = {}
        for r in rows:
            c = r["comp"]
            entry = by_comp.setdefault(c, {
                "current_versions": set(),
                "needed_targets": set(),
                "cves": 0,
                "keys": [],
            })
            if r["current_version"]:
                entry["current_versions"].add(r["current_version"])
            entry["needed_targets"].add(r["target_version"])
            entry["cves"] += 1
            entry["keys"].append(r["key"])
        comp_rows = []
        for c, e in sorted(by_comp.items()):
            needed = max(e["needed_targets"], key=_ver_key)
            comp_rows.append({
                "component": c,
                "cves": e["cves"],
                "current_versions": sorted(e["current_versions"], key=_ver_key),
                "needed_target": needed,
                "covered_by_recommended": _cmp_ver(recommended, needed) >= 0,
            })
        suggestions.append({
            "family": fam,
            "recommended_common_version": recommended,
            "fix_cves_covered": covered,
            "fix_cves_total": len(rows),
            "components": comp_rows,
            "rationale": (
                f"Highest required target across components is {recommended}; "
                f"bumping every component to this version covers {covered}/"
                f"{len(rows)} FIX CVEs in the '{fam}' family."
            ),
        })
    return suggestions


# ---------------------------------------------------------------------------
# Pretty print
# ---------------------------------------------------------------------------
def print_report(report: Dict) -> None:
    t = report["totals"]
    print("\n" + "=" * 78)
    print(f"FULL ANALYSIS — release {report['release']}")
    print("=" * 78)
    print(f"Reported (all statuses): {t['reported_all_statuses']}")
    print(f"By status:               {t['by_status']}")
    print(f"Analysed (To Do):        {t['analysed']}")
    print(f"  FIX (version bump):    {t['fix']}")
    print(f"  EXCEPTION REQUEST:     {t['exception']}")
    if report.get("exception_reasons"):
        print("\nException reasons:")
        for reason, n in sorted(report["exception_reasons"].items(),
                                key=lambda kv: -kv[1]):
            print(f"  {n:5d}  {reason}")

    print(f"\n{'COMPONENT':22}{'TYPE':8}{'TODO':6}{'FIX':6}{'EXC':6}")
    print("-" * 50)
    comps = report["components"]
    for comp, d in sorted(comps.items(), key=lambda kv: -kv[1]["todo"]):
        print(f"{comp:22}{d['build_type']:8}{d['todo']:<6}"
              f"{d['fix']:<6}{d['exception']:<6}")
    print("-" * 50)
    print(f"{'TOTAL':22}{'':8}{t['analysed']:<6}{t['fix']:<6}{t['exception']:<6}")

    # Per-component FIX list (compact)
    print("\n" + "=" * 78)
    print("PER-COMPONENT FIX LIST (lib | current -> target | CVE | OSV)")
    print("=" * 78)
    for comp, d in sorted(comps.items()):
        fixes = [c for c in d["cves"] if c["decision"] == "FIX"]
        if not fixes:
            continue
        print(f"\n## {comp}  ({len(fixes)} fixable)")
        for c in sorted(fixes, key=lambda x: (x["family"], x["lib"], x["cve"])):
            print(f"  {c['lib'] or '(unknown)':48} "
                  f"{c['current_version'] or '?':>16} -> "
                  f"{c['target_version'] or '?':<16}  "
                  f"{c['cve']:<18} {c['key']}")

    # Common version suggestions
    print("\n" + "=" * 78)
    print("COMMON VERSION SUGGESTIONS (cross-component)")
    print("=" * 78)
    print("Pick the highest required target per library family so one bump")
    print("fixes the most CVEs across components.\n")
    for s in report["common_version_suggestions"][:40]:
        print(f"  {s['family']:20} -> {s['recommended_common_version']:<18} "
              f"covers {s['fix_cves_covered']}/{s['fix_cves_total']} FIX CVEs")
        for c in s["components"]:
            flag = "OK" if c["covered_by_recommended"] else "GAP"
            print(f"      [{flag}] {c['component']:18} "
                  f"current={','.join(c['current_versions']) or '?'}  "
                  f"needs>={c['needed_target']}  ({c['cves']} CVEs)")

    print(f"\nJSON report: {report.get('report_path')}")
    mon = report.get("_monitor")
    if mon:
        mon.print_usage()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def run_full_analysis(release: str, repo_substr: str = "sehajsandhu/",
                      components: Optional[List[str]] = None,
                      only_todo: bool = True) -> Dict:
    if not ca.EMAIL or not ca.API_TOKEN:
        raise SystemExit(
            "Jira credentials missing. Set CVE_JIRA_EMAIL / CVE_JIRA_API_TOKEN "
            "or ~/.config/cve_fix/jira.env")
    report = analyse_release(release, repo_substr=repo_substr,
                             only_todo=only_todo, components=components)
    print_report(report)
    return report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Full FIX/EXCEPTION analysis for a CVE release baseline")
    ap.add_argument("release", help="e.g. 3.3.6.4")
    ap.add_argument("--repo-substr", default="sehajsandhu/",
                    help="cve-repo filter (default sehajsandhu/)")
    ap.add_argument("--components", nargs="*",
                    help="optional component allow-list (e.g. hadoop hive)")
    ap.add_argument("--all-statuses", action="store_true",
                    help="analyse all statuses, not only To Do")
    args = ap.parse_args(argv)
    run_full_analysis(args.release, repo_substr=args.repo_substr,
                      components=args.components,
                      only_todo=not args.all_statuses)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
