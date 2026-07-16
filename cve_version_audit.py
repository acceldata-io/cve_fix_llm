"""
cve_version_audit.py — read pinned library versions from GitHub branches and
compare them with --full-analysis FIX targets to recommend common bump versions.

Usage:
    python3 cve_version_audit.py 3.3.6.4
    python3 cve_agent.py --version-audit 3.3.6.4 --branch nightly/3.3.6.5
    python3 cve_agent.py --version-audit 3.3.6.4 --components hadoop hive
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import cve_env

cve_env.load_repo_env()

import cve_address as addr
import cve_analyser as ca
import cve_full_analysis as fa
import cve_profiles as cp

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(HERE, "reports")

# label, maven property candidates, dependency G:A matchers, analysis family key
LIB_CATALOG: List[Tuple[str, List[str], List[str], str]] = [
    ("Hadoop-thirdparty",
     ["hadoop-thirdparty.version", "hadoop.thirdparty.version"],
     ["org.apache.hadoop.thirdparty:hadoop-shaded-guava",
      "org.apache.hadoop.thirdparty:hadoop-shaded-protobuf_3_25"],
     "hadoop-thirdparty"),
    ("commons-lang3", ["commons-lang3.version"],
     ["org.apache.commons:commons-lang3"], "commons-lang3"),
    ("commons-text", ["commons-text.version"],
     ["org.apache.commons:commons-text"], "commons-text"),
    ("commons-configuration2",
     ["commons-configuration2.version", "commons.configuration2.version"],
     ["org.apache.commons:commons-configuration2"], "commons-configuration2"),
    ("Netty4",
     ["netty.version", "netty4.version", "netty.4.version", "io.netty.version",
      "netty-all.version"],
     ["io.netty:netty-all", "io.netty:netty-handler", "io.netty:netty-bom"],
     "netty"),
    ("protobuf",
     ["protobuf.version", "protobuf-java.version", "protobuf.java.version",
      "protoc.version"],
     ["com.google.protobuf:protobuf-java"], "protobuf"),
    ("commons-io", ["commons-io.version"], ["commons-io:commons-io"],
     "commons-io"),
    ("commons-compress", ["commons-compress.version"],
     ["org.apache.commons:commons-compress"], "commons-compress"),
    ("tomcat", ["tomcat.version", "tomcat.embed.version"],
     ["org.apache.tomcat.embed:tomcat-embed-core"], "tomcat"),
    ("opentelemetry-javaagent",
     ["opentelemetry-javaagent.version", "opentelemetry.version",
      "opentelemetry-api.version"],
     ["io.opentelemetry.javaagent:opentelemetry-javaagent",
      "io.opentelemetry:opentelemetry-api"],
     "opentelemetry-javaagent"),
    ("hbase-thirdparty",
     ["hbase-thirdparty.version", "hbase.thirdparty.version"],
     ["org.apache.hbase.thirdparty:hbase-shaded-netty",
      "org.apache.hbase.thirdparty:hbase-shaded-miscellaneous"],
     "hbase-thirdparty"),
    ("beanutils", ["beanutils.version"], [], "beanutils"),
    ("avro", ["avro.version"], ["org.apache.avro:avro"], "avro"),
    ("Jetty",
     ["jetty.version", "jetty9.version", "jetty.major.version"],
     ["org.eclipse.jetty:jetty-server", "org.eclipse.jetty:jetty-util",
      "org.eclipse.jetty:jetty-http"],
     "jetty"),
    ("nimbus-jose",
     ["nimbus-jose-jwt.version", "nimbus.jose.jwt.version", "nimbus-jose.version",
      "nimbusds.version"],
     ["com.nimbusds:nimbus-jose-jwt"], "nimbus-jose-jwt"),
    ("commons-beanutils", ["commons-beanutils.version"],
     ["commons-beanutils:commons-beanutils"], "commons-beanutils"),
    ("jackson2",
     ["jackson.version", "jackson2.version", "fasterxml.jackson.version",
      "jackson-bom.version", "jackson.databind.version"],
     ["com.fasterxml.jackson.core:jackson-databind",
      "com.fasterxml.jackson:jackson-bom"],
     "jackson"),
    ("guava", ["guava.version"], ["com.google.guava:guava"], "guava"),
    ("log4j2", ["log4j2.version", "log4j.version"],
     ["org.apache.logging.log4j:log4j-core"], "log4j"),
    ("xmlsec", ["xmlsec.version"], ["org.apache.santuario:xmlsec"], "xmlsec"),
    ("cron-utils", ["cron-utils.version", "cronutils.version"],
     ["com.cronutils:cron-utils"], "cron-utils"),
    ("bouncycastle",
     ["bouncycastle.version", "bouncy-castle.version", "bc.version",
      "bcprov.version"],
     ["org.bouncycastle:bcprov-jdk15on", "org.bouncycastle:bcprov-jdk18on"],
     "bouncycastle"),
    ("dnsjava", ["dnsjava.version"], ["dnsjava:dnsjava"], "dnsjava"),
    ("libthrift", ["thrift.version", "libthrift.version"],
     ["org.apache.thrift:libthrift"], "thrift"),
    ("aircompressor", ["aircompressor.version"],
     ["io.airlift:aircompressor"], "aircompressor"),
]

IMPALA_ENV = {
    "jackson2": "IMPALA_JACKSON_DATABIND_VERSION",
    "log4j2": "IMPALA_LOG4J2_VERSION",
    "guava": "IMPALA_GUAVA_VERSION",
    "avro": "IMPALA_AVRO_JAVA_VERSION",
    "protobuf": "IMPALA_PROTOBUF_JAVA_VERSION",
    "libthrift": "IMPALA_THRIFT_POM_VERSION",
    "bouncycastle": "IMPALA_BOUNCY_CASTLE_VERSION",
    "xmlsec": "IMPALA_XMLSEC_VERSION",
}

EXTRA_POM_PATHS: Dict[str, List[str]] = {
    "hadoop": ["hadoop-project/pom.xml"],
    "impala": ["bin/impala-config.sh", "java/pom.xml"],
    "clickhouse": ["ch-ui-wrapper/pom.xml"],
}


def _github_token() -> str:
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


def _parse_github_repo(git_url: str, fallback_name: str) -> str:
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+)", git_url or "")
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return f"acceldata-io/{fallback_name}"


def default_branch(release: str, explicit: str = "") -> str:
    if explicit:
        return explicit
    for env_key in ("CVE_VERSION_AUDIT_BRANCH", "CVE_ADDRESS_BRANCH"):
        v = os.environ.get(env_key, "").strip()
        if v:
            return v
    if release.startswith("3.3.6."):
        return "nightly/3.3.6.5"
    if release.startswith("3.2.3."):
        return "nightly/ODP-3.2.3.7-2"
    return "nightly/ODP-3.2.3.7-2"


def component_sources(name: str, branch: str, release: str) -> Dict:
    """Return {repo, branch, files[]} for GitHub raw fetches."""
    if name in cp.PROFILES:
        p = cp.get_profile(name, release=release or None)
        repo = _parse_github_repo(p.get("git_url", ""), name)
        files = [p["pom_path"]] if p.get("pom_path") else EXTRA_POM_PATHS.get(name, ["pom.xml"])
        return {"repo": repo, "branch": branch or p.get("target_branch", branch),
                "files": files, "has_profile": True}
    meta = addr.component_meta(name, release=release)
    files = EXTRA_POM_PATHS.get(name, [meta.get("pom_path") or "pom.xml"])
    return {
        "repo": _parse_github_repo(meta.get("git_url", ""), name),
        "branch": branch,
        "files": files,
        "has_profile": False,
    }


def fetch_raw(repo: str, branch: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    token = _github_token()
    hdrs = {"Authorization": f"token {token}"} if token else {}
    r = ca.SESSION.get(url, headers=hdrs, timeout=45)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} fetching {url}")
    return r.text


def props_from_pom(text: str) -> Dict[str, str]:
    d: Dict[str, str] = {}
    for m in re.finditer(r"<([a-zA-Z0-9_.\-]+)>\s*([^<>]+?)\s*</\1>", text):
        d.setdefault(m.group(1).lower(), m.group(2).strip())
    return d


def deps_from_pom(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        blk = m.group(1)
        g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", blk)
        a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", blk)
        v = re.search(r"<version>\s*([^<]+?)\s*</version>", blk)
        if g and a and v:
            out[f"{g.group(1).strip()}:{a.group(1).strip()}"] = v.group(1).strip()
    return out


def resolve_version(val: str, props: Dict[str, str], depth: int = 0) -> str:
    if not val or depth > 5:
        return val
    m = re.fullmatch(r"\$\{([^}]+)\}", val.strip())
    if m and m.group(1).lower() in props:
        return resolve_version(props[m.group(1).lower()], props, depth + 1)
    return val


def impala_env(cfg_text: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for m in re.finditer(r"export\s+([A-Z][A-Z0-9_]+)=([^\s#]+)", cfg_text):
        env[m.group(1)] = m.group(2)
    for k, v in list(env.items()):
        mm = re.fullmatch(r"\$\{([A-Z0-9_]+)(:-[^}]*)?\}", v)
        if mm and mm.group(1) in env:
            env[k] = env[mm.group(1)]
    return env


def audit_component_versions(component: str, branch: str,
                             release: str = "") -> Dict[str, str]:
    """Return {lib_label: resolved_version_or_-} from GitHub."""
    src = component_sources(component, branch, release)
    props: Dict[str, str] = {}
    deps: Dict[str, str] = {}
    cfg = ""
    errors: List[str] = []
    for path in src["files"]:
        try:
            txt = fetch_raw(src["repo"], src["branch"], path)
        except Exception as e:
            errors.append(f"{path}: {e}")
            continue
        if path.endswith(".sh"):
            cfg = txt
        else:
            props.update(props_from_pom(txt))
            deps.update(deps_from_pom(txt))
    env = impala_env(cfg) if cfg else {}
    row: Dict[str, str] = {"_repo": src["repo"], "_branch": src["branch"]}
    if errors:
        row["_errors"] = "; ".join(errors)
    for label, candidates, gas, _fam in LIB_CATALOG:
        val = None
        if component == "impala" and label in IMPALA_ENV:
            val = env.get(IMPALA_ENV[label])
        if val is None:
            for c in candidates:
                if c in props:
                    val = resolve_version(props[c], props)
                    break
        if val is None:
            for ga in gas:
                if ga in deps:
                    val = resolve_version(deps[ga], props)
                    break
        row[label] = val or "-"
    return row


def analysis_report_path(release: str, explicit: str = "") -> str:
    if explicit:
        return os.path.expanduser(explicit)
    safe = release.replace("/", "_")
    return os.path.join(REPORT_DIR, f"full_analysis_{safe}.json")


def load_analysis_report(release: str, path: str = "") -> Optional[Dict]:
    p = analysis_report_path(release, path)
    if not os.path.isfile(p):
        return None
    with open(p) as fh:
        return json.load(fh)


def index_analysis_families(report: Dict) -> Dict[str, Dict]:
    """family -> {recommended, fix_cves_covered, fix_cves_total, by_component}."""
    out: Dict[str, Dict] = {}
    for s in report.get("common_version_suggestions", []):
        fam = s.get("family", "")
        if not fam:
            continue
        out[fam] = {
            "recommended": s.get("recommended_common_version", ""),
            "fix_cves_covered": s.get("fix_cves_covered", 0),
            "fix_cves_total": s.get("fix_cves_total", 0),
            "rationale": s.get("rationale", ""),
            "by_component": {c["component"]: c for c in s.get("components", [])},
        }
    return out


def pick_suggest_version(current: str, recommended: str, needed: str) -> str:
    """Highest version among recommended/needed that is strictly above current."""
    candidates = [v for v in (recommended, needed) if v and v != "-"]
    if not candidates:
        return ""
    best = max(candidates, key=fa._ver_key)
    if current and current != "-" and fa._cmp_ver(best, current) <= 0:
        return current
    return best


def run_audit(release: str, branch: str = "", components: Optional[List[str]] = None,
              analysis_path: str = "") -> Dict:
    branch = default_branch(release, branch)
    comps = components or addr.list_components(release)
    analysis = load_analysis_report(release, analysis_path)
    fam_index = index_analysis_families(analysis) if analysis else {}

    current_matrix: Dict[str, Dict[str, str]] = {}
    for comp in comps:
        print(f"  fetching {comp} @ {branch} …", flush=True)
        try:
            current_matrix[comp] = audit_component_versions(comp, branch, release)
        except Exception as e:
            current_matrix[comp] = {"_error": str(e)}

    comparisons: List[Dict] = []
    recommendations: List[Dict] = []
    for label, _cand, _gas, family in LIB_CATALOG:
        fam = fam_index.get(family, {})
        recommended = fam.get("recommended", "")
        comp_rows = []
        for comp in comps:
            cur_row = current_matrix.get(comp, {})
            current = cur_row.get(label, "-")
            if current == "-" and "_error" in cur_row:
                current = f"ERR:{cur_row['_error'][:40]}"
            ac = fam.get("by_component", {}).get(comp, {})
            needed = ac.get("needed_target", "")
            suggest = pick_suggest_version(current, recommended, needed)
            gap = (current not in ("-", "") and suggest
                   and fa._cmp_ver(suggest, current) > 0)
            comp_rows.append({
                "component": comp,
                "current_github": current,
                "analysis_needed_target": needed or "-",
                "suggest_bump_to": suggest or "-",
                "needs_bump": gap,
                "fix_cves": ac.get("cves", 0),
            })
        if recommended or any(r["needs_bump"] for r in comp_rows):
            recommendations.append({
                "library": label,
                "family": family,
                "recommended_common_version": recommended or "-",
                "fix_cves_covered": fam.get("fix_cves_covered", 0),
                "fix_cves_total": fam.get("fix_cves_total", 0),
                "rationale": fam.get("rationale", ""),
                "components": comp_rows,
            })
        comparisons.append({
            "library": label,
            "family": family,
            "recommended_common_version": recommended or "-",
            "components": comp_rows,
        })

    report = {
        "release": release,
        "github_branch": branch,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "components_audited": comps,
        "analysis_report": analysis_report_path(release, analysis_path),
        "analysis_loaded": analysis is not None,
        "current_versions": {
            c: {k: v for k, v in row.items() if not k.startswith("_")}
            for c, row in current_matrix.items()
        },
        "github_sources": {
            c: {k: row.get(k) for k in ("_repo", "_branch", "_errors")
                if k in row}
            for c, row in current_matrix.items()
        },
        "comparisons": comparisons,
        "recommendations": recommendations,
    }
    os.makedirs(REPORT_DIR, exist_ok=True)
    safe = release.replace("/", "_")
    out_path = os.path.join(REPORT_DIR, f"version_audit_{safe}.json")
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    report["report_path"] = out_path
    return report


def print_summary(report: Dict) -> None:
    rel = report["release"]
    branch = report["github_branch"]
    comps = report["components_audited"]
    print(f"\nVERSION AUDIT  release={rel}  github_branch={branch}")
    if not report.get("analysis_loaded"):
        print(f"WARN: no analysis report at {report.get('analysis_report')}")
        print("      Run: python3 cve_agent.py --full-analysis", rel)
    else:
        print(f"Analysis: {report['analysis_report']}")

    print("\nCURRENT VERSIONS (from GitHub)")
    hdr = f"{'LIBRARY':22}" + "".join(f"{c:14}" for c in comps)
    print(hdr)
    print("-" * len(hdr))
    labels = [x[0] for x in LIB_CATALOG]
    matrix = report.get("current_versions", {})
    for label in labels:
        row = f"{label:22}"
        for c in comps:
            row += f"{matrix.get(c, {}).get(label, '-'):14}"
        print(row)

    recs = [r for r in report.get("recommendations", [])
            if r.get("recommended_common_version") not in ("", "-")]
    if recs:
        print("\nRECOMMENDED COMMON BUMPS (from --full-analysis + GitHub current)")
        print(f"{'LIBRARY':22}{'RECOMMEND':18}{'CVEs':>8}  COMPONENTS NEEDING BUMP")
        print("-" * 90)
        for r in sorted(recs, key=lambda x: -x.get("fix_cves_total", 0)):
            needing = [f"{x['component']}({x['current_github']}→{x['suggest_bump_to']})"
                       for x in r["components"] if x.get("needs_bump")]
            need_s = ", ".join(needing[:6])
            if len(needing) > 6:
                need_s += f" +{len(needing)-6} more"
            print(f"{r['library']:22}{r['recommended_common_version']:18}"
                  f"{r.get('fix_cves_total', 0):>8}  {need_s or '(all at/above target)'}")

    print(f"\nJSON: {report.get('report_path', '')}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit pinned library versions on GitHub and compare with "
                    "--full-analysis FIX targets.")
    ap.add_argument("release", help="OSV release baseline, e.g. 3.3.6.4")
    ap.add_argument("--branch", default="",
                    help="GitHub branch to read (default from release / env)")
    ap.add_argument("--components", nargs="*", help="optional component allow-list")
    ap.add_argument("--analysis-report", default="",
                    help="path to full_analysis JSON (default reports/full_analysis_<rel>.json)")
    ap.add_argument("--json-only", action="store_true",
                    help="print JSON to stdout instead of human summary")
    args = ap.parse_args(argv)

    print(f"Auditing {len(args.components or addr.list_components(args.release))} "
          f"components for release {args.release} …")
    report = run_audit(args.release, branch=args.branch,
                       components=args.components or None,
                       analysis_path=args.analysis_report)
    if args.json_only:
        print(json.dumps(report, indent=2))
    else:
        print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
