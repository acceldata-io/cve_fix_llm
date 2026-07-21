#!/usr/bin/env python3
"""hbase-connectors + spark4-hbase-connectors (release 3.3.6.4) CVE routing.

Both live in acceldata-io/hbase-connectors with different nightlies:

  hbase-connectors       -> nightly/ODP-3.3.6.5        JDK 11
  spark4-hbase-connectors-> nightly/ODP-4.1.1.3.3.6.5  JDK 17

FIX (owned pins):
  - commons-lang3.version     -> 3.18.0
  - hbase-thirdparty.version  -> 4.1.13
      (hbase-shaded-netty ships netty 4.1.131.Final; closes 4.1.x tickets
       whose same-major fix is <= 4.1.131)

EXCEPTION:
  - hadoop-common / commons-configuration2 (Hadoop platform transitive)
  - logback-core 1.3.x (fix only on 1.5.x; not connectors-owned)
  - jetty-* on 9.4.x with only 11.x/12.x published fixes
  - opentelemetry-api (HBase platform transitive)
  - netty inside hbase-shaded-netty needing >4.1.131 (no thirdparty release yet)

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_ONLY=hbase-connectors,spark4-hbase-connectors
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ASSIGNEE = "senthil.kumar"
REVIEWER = "basapuram-kumar"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
ROUTE_ONLY = os.environ.get("CVE_ROUTE_ONLY", "") not in ("", "0", "false", "False")
ONLY = {
    x.strip()
    for x in os.environ.get("CVE_ONLY", "").split(",")
    if x.strip()
}
RELEASE = "3.3.6.4"
STATUS = Path("/tmp/hbase_connectors_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "5400"))
TOKEN = ""

LANG3 = "3.18.0"
THIRDPARTY = "4.1.13"
PROVIDES_NETTY = "4.1.131.Final"

VARIANTS = [
    {
        "label": "hbase-connectors",
        "jira": "sehajsandhu/hbase-connectors",
        "work": Path("/root/3.3.6.5/hbase-connectors"),
        "gh": "acceldata-io/hbase-connectors",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
        "build": (
            "mvn -Pbuild-with-jdk11 -DskipTests -Dmaven.test.skip=true "
            "-Dcheckstyle.skip=true -Dspotbugs.skip=true -Drat.skip=true "
            "-Denforcer.skip=true package"
        ),
    },
    {
        "label": "spark4-hbase-connectors",
        "jira": "sehajsandhu/spark4-hbase-connectors",
        "work": Path("/root/3.3.6.5/spark4-hbase-connectors"),
        "gh": "acceldata-io/hbase-connectors",
        "base": "nightly/ODP-4.1.1.3.3.6.5",
        "jdk": 17,
        "build": (
            "mvn -U -Pbuild-with-jdk17 -Pspark-4 -DskipTests -Dmaven.test.skip=true "
            "-Dcheckstyle.skip=true -Dspotbugs.skip=true -Drat.skip=true "
            "-Denforcer.skip=true package"
        ),
    },
]


def write_status(**kwargs):
    cur = {}
    if STATUS.is_file():
        try:
            cur = json.loads(STATUS.read_text())
        except Exception:
            cur = {}
    cur.update(kwargs)
    cur["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    STATUS.write_text(json.dumps(cur, indent=2), encoding="utf-8")
    print(f"STATUS: {json.dumps(kwargs)[:450]}", flush=True)


def field_text(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        out = []
        for c in v.get("content") or []:
            for n in c.get("content") or []:
                if n.get("type") == "text":
                    out.append(n.get("text") or "")
        return " ".join(out)
    return str(v)


def load_token():
    global TOKEN
    sys.path.insert(0, "/root/cve_fix_llm")
    os.chdir("/root/cve_fix_llm")
    import cve_env

    cve_env.load_repo_env()
    TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
    if not TOKEN:
        raise SystemExit("GITHUB_TOKEN missing")
    askpass = Path("/tmp/git-askpass-github.sh")
    askpass.write_text(
        "#!/bin/sh\ncase \"$1\" in\n*Username*) echo x-access-token ;;\n"
        "*Password*) echo \"$GITHUB_TOKEN\" ;;\nesac\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    os.environ["GIT_ASKPASS"] = str(askpass)
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GITHUB_TOKEN"] = TOKEN


def git_env(jdk: int):
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    home = jdk_home(jdk)
    env["JAVA_HOME"] = home
    env["PATH"] = f"{home}/bin:" + env.get("PATH", "")
    return env


def jdk_home(jdk: int) -> str:
    for c in [f"/usr/lib/jvm/java-{jdk}-openjdk", f"/usr/lib/jvm/java-{jdk}"]:
        if Path(c).exists():
            return c
    raise SystemExit(f"JDK {jdk} not found")


def run(cmd, cwd, env=None, timeout=TIMEOUT, log_path=None):
    print(f"+ ({cwd}) {cmd}", flush=True)
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=str(cwd), text=True,
            capture_output=True, env=env, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"TIMEOUT after {timeout}s"
    out, err = p.stdout or "", p.stderr or ""
    if log_path:
        Path(log_path).write_text(out + "\n" + err, encoding="utf-8", errors="replace")
    return p.returncode, out, err


def parse_fix_versions(fix_field: str) -> list[str]:
    if not fix_field:
        return []
    parts = re.split(r"[,;/]| and ", fix_field)
    vers = []
    for p in parts:
        m = re.search(r"\b(\d+(?:\.\d+)+(?:[a-zA-Z0-9._\-]*)?)\b", p.strip())
        if m:
            vers.append(m.group(1))
    return vers


def parse_ver_tuple(v: str):
    """Comparable tuple for 4.1.131.Final-style versions."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", v or "")
    if not m:
        return (0, 0, 0)
    return tuple(int(x) for x in m.groups())


def netty_covered_by_thirdparty(fix_field: str) -> bool:
    """True if any 4.1.x fix is <= PROVIDES_NETTY (OR with 4.2.x alternatives)."""
    provides = parse_ver_tuple(PROVIDES_NETTY)
    line41 = [v for v in parse_fix_versions(fix_field) if v.startswith("4.1.")]
    if not line41:
        return False
    need = min(parse_ver_tuple(v) for v in line41)
    return provides >= need


def load_tickets(ca, jira: str):
    jql = (
        f'project = OSV AND status = "To Do" AND summary ~ "{jira}" '
        "ORDER BY key ASC"
    )
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,"
                "customfield_10892,customfield_10891,customfield_10888"
            ),
        }
        if token:
            params["nextPageToken"] = token
        r = ca.SESSION.get(
            f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql",
            params=params,
            headers={"Accept": "application/json"},
            auth=(ca.EMAIL, ca.API_TOKEN),
        )
        data = r.json()
        issues.extend(data.get("issues") or [])
        token = data.get("nextPageToken")
        if not token:
            break
    rows = []
    for i in issues:
        f = i["fields"]
        if field_text(f.get("customfield_10893")) != RELEASE:
            continue
        summ = f.get("summary") or ""
        pkg = field_text(f.get("customfield_10875"))
        fix = (
            ca.extract_fixed_version(f.get("customfield_10891"))
            if hasattr(ca, "extract_fixed_version")
            else field_text(f.get("customfield_10891"))
        )
        path = field_text(f.get("customfield_10888"))
        m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
        rows.append({
            "key": i["key"],
            "pkg": pkg,
            "ver": field_text(f.get("customfield_10892")),
            "fix": fix or "",
            "path": path,
            "jar": path.split("/")[-1] if path else "",
            "cve": m.group(1) if m else "",
            "summary": summ,
        })
    return rows


def classify(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    jar = (row["jar"] or "").lower()

    if "hadoop" in pkg:
        return "exception", {
            "why": (
                "hadoop-common is the ODP Hadoop platform artifact; remediation "
                "belongs to the Hadoop component, not a connectors-owned pin. "
                "Exception Request (Deferred)."
            )
        }

    if "commons-configuration2" in pkg or "commons_configuration2" in pkg:
        return "exception", {
            "why": (
                "commons-configuration2 is pulled transitively via ODP Hadoop/"
                "HBase, not managed as an hbase-connectors property. "
                "Exception Request (Deferred)."
            )
        }

    if "logback" in pkg:
        return "exception", {
            "why": (
                "logback-core 1.3.x fix is only on the 1.5.x line; connectors "
                "pull logback transitively from the HBase/platform stack and "
                "do not own a safe same-major bump. "
                "Exception Request (Deferred)."
            )
        }

    if "opentelemetry" in pkg:
        return "exception", {
            "why": (
                "opentelemetry-api is pulled transitively by the HBase fork; "
                "upgrading to 1.62.0 is owned by the platform HBase build. "
                "Exception Request (Deferred)."
            )
        }

    if "jetty" in pkg:
        return "exception", {
            "why": (
                "Jetty CVE fix is only published on 11.x/12.x; connectors stay "
                "on Jetty 9.4.x (javax stack) with no same-major 9.4.x fix. "
                "Exception Request (Deferred)."
            )
        }

    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {"target": LANG3}

    if "netty" in pkg or "io.netty" in pkg:
        in_shade = "hbase-shaded-netty" in jar or "hbase-shaded-netty" in path
        if in_shade or "hbase-shaded-netty" in path:
            if netty_covered_by_thirdparty(row["fix"]):
                return "fix_thirdparty", {
                    "target": THIRDPARTY,
                    "provides": PROVIDES_NETTY,
                }
            return "exception", {
                "why": (
                    "Netty classes are inside org.apache.hbase.thirdparty:"
                    f"hbase-shaded-netty. Latest thirdparty {THIRDPARTY} ships "
                    f"netty {PROVIDES_NETTY}; this CVE needs a newer 4.1.x "
                    "(4.1.132+/4.1.133+) not yet packaged by hbase-thirdparty. "
                    "Exception Request (Deferred)."
                )
            }
        return "exception", {
            "why": (
                "Netty is not a direct connectors pin; remediation requires "
                "the owning shaded/platform artifact. "
                "Exception Request (Deferred)."
            )
        }

    return "unknown", {}


def route_tickets(ca, rows, label: str):
    closed, excepted, fixable, unknown = [], [], [], []
    need = {"lang3": False, "thirdparty": False}
    for row in rows:
        action, meta = classify(row)
        key = row["key"]
        if action == "exception":
            print(f"[{label}] EXCEPTION {key} {row['pkg']}", flush=True)
            if not DRY:
                ok = ca.update_ticket_exception(
                    key, meta["why"], reason="Deferred", assignee=ASSIGNEE
                )
                (excepted if ok else unknown).append(
                    {**row, "action": action, "ok": ok}
                )
            else:
                excepted.append({**row, "action": action, "ok": True})
        elif action.startswith("fix_"):
            kind = action.replace("fix_", "")
            need[kind] = True
            print(
                f"[{label}] FIXABLE {key} {row['pkg']} -> {meta.get('target')} "
                f"({kind})",
                flush=True,
            )
            fixable.append({**row, "action": action, **meta})
        else:
            print(
                f"[{label}] UNKNOWN {key} pkg={row['pkg']} path={row['jar']} "
                f"fix={row['fix']}",
                flush=True,
            )
            unknown.append({**row, "action": "unknown"})
    return closed, excepted, fixable, unknown, need


def ensure_repo(v: dict):
    work = v["work"]
    env = git_env(v["jdk"])
    work.mkdir(parents=True, exist_ok=True)
    if not (work / ".git").exists():
        run(
            f"git clone https://github.com/{v['gh']}.git {work}",
            Path("/root/3.3.6.5"),
            env=env,
            timeout=600,
        )
    run(
        f"git remote set-url origin https://github.com/{v['gh']}.git",
        work, env=env, timeout=60,
    )
    run(f"git fetch origin {v['base']} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {v['base']} origin/{v['base']}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", work, env=env, timeout=600)
    run(f"git checkout -B {v['base']} origin/{v['base']}", work, env=env, timeout=120)
    return work


def apply_bumps(work: Path, need: dict) -> list[str]:
    pom = work / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text
    if need.get("lang3"):
        text2, n = re.subn(
            r"(<commons-lang3\.version>)([^<]+)(</commons-lang3\.version>)",
            rf"\g<1>{LANG3}\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("commons-lang3.version not found")
        text = text2
    if need.get("thirdparty"):
        text2, n = re.subn(
            r"(<hbase-thirdparty\.version>)([^<]+)(</hbase-thirdparty\.version>)",
            rf"\g<1>{THIRDPARTY}\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("hbase-thirdparty.version not found")
        text = text2
    if text != orig:
        pom.write_text(text, encoding="utf-8")
        return ["pom.xml"]
    return []


def compile_gate(v: dict, log: str) -> bool:
    code, out, err = run(
        v["build"], v["work"], env=git_env(v["jdk"]),
        timeout=TIMEOUT, log_path=log,
    )
    if code != 0:
        for ln in (out + err).splitlines()[-40:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
    return code == 0


def create_pr(gh: str, branch: str, base: str, title: str, body: str):
    import requests

    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    r = requests.post(
        f"https://api.github.com/repos/{gh}/pulls",
        headers=headers,
        json={"title": title, "head": branch, "base": base, "body": body},
        timeout=60,
    )
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        requests.post(
            f"https://api.github.com/repos/{gh}/pulls/{num}/requested_reviewers",
            headers=headers,
            json={"reviewers": [REVIEWER]},
            timeout=60,
        )
        return url
    print(f"PR fail {r.status_code}: {r.text[:400]}", flush=True)
    return None


def deliver(ca, v: dict, fixable: list, need: dict):
    if not any(need.values()):
        print(f"[{v['label']}] no bumps", flush=True)
        return {"ok": True, "pr": None, "closed": []}

    branch = fixable[0]["key"]
    parts = []
    if need.get("lang3"):
        parts.append(f"commons-lang3 {LANG3}")
    if need.get("thirdparty"):
        parts.append(f"hbase-thirdparty {THIRDPARTY} (netty {PROVIDES_NETTY})")
    title = (
        f"{branch} - CVE - Bumped-up {', '.join(parts)} "
        f"to address ODP {RELEASE} CVEs"
    )

    ensure_repo(v)
    env = git_env(v["jdk"])
    run(f"git checkout -B {branch} origin/{v['base']}", v["work"], env=env, timeout=120)
    changed = apply_bumps(v["work"], need)
    write_status(**{f"{v['label']}_patched": changed, f"{v['label']}_bumps": need})

    if DRY:
        return {"ok": True, "dry": True, "title": title, "bumps": need}

    log = f"/tmp/{v['label'].replace('-', '_')}_cve_build.log"
    if not compile_gate(v, log):
        return {"ok": False, "phase": "FAILED_COMPILE", "log": log}

    run("git add pom.xml", v["work"], env=env, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(v["work"]),
        text=True,
        capture_output=True,
        env=env,
    )
    if p.returncode != 0:
        return {"ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", v["work"], env=env, timeout=300)
    if code != 0:
        return {"ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: {v['label']} ({v['base']}, release {RELEASE})",
        f"- Tickets: {', '.join(r['key'] for r in fixable)}",
        "- Bumps:",
        *[
            f"  - commons-lang3: -> {LANG3}" if k == "lang3" and on else
            f"  - hbase-thirdparty: -> {THIRDPARTY} (provides netty {PROVIDES_NETTY})"
            if k == "thirdparty" and on else ""
            for k, on in need.items()
        ],
    ])
    pr = create_pr(v["gh"], branch, v["base"], title, body)
    if not pr:
        return {"ok": False, "pr": None}

    closed = []
    for r in fixable:
        tgt = r.get("target")
        comment = (
            f"Fixed via PR: {pr} — bumped {r['action'].replace('fix_', '')} "
            f"to {tgt} on {v['base']}."
        )
        ok = ca.close_ticket_with_comment(
            r["key"], comment, "Closed", assignee=ASSIGNEE
        )
        print(f"  [{v['label']}] {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])
    return {"ok": True, "pr": pr, "closed": closed, "bumps": need}


def process_variant(ca, v: dict):
    label = v["label"]
    print(f"\n===== {label} / {v['base']} =====", flush=True)
    rows = load_tickets(ca, v["jira"])
    write_status(**{f"{label}_count": len(rows)})
    closed, excepted, fixable, unknown, need = route_tickets(ca, rows, label)
    write_status(**{
        f"{label}_closed": [r["key"] for r in closed],
        f"{label}_excepted": [r["key"] for r in excepted],
        f"{label}_fixable": [r["key"] for r in fixable],
        f"{label}_unknown": [r["key"] for r in unknown],
        f"{label}_need": need,
    })
    if ROUTE_ONLY:
        return {
            "label": label,
            "closed": [r["key"] for r in closed],
            "excepted": [r["key"] for r in excepted],
            "fixable": [r["key"] for r in fixable],
            "unknown": [r["key"] for r in unknown],
            "need": need,
        }
    res = deliver(ca, v, fixable, need)
    return {"label": label, "excepted": [r["key"] for r in excepted], "result": res}


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY

    results = []
    for v in VARIANTS:
        if ONLY and v["label"] not in ONLY:
            continue
        results.append(process_variant(ca, v))

    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
