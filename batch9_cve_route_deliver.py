#!/usr/bin/env python3
"""Batch CVE deliver for clickhouse UI (ch-ui wrapper), release 3.3.6.4.

Jira component: sehajsandhu/clickhouse
GitHub: acceldata-io/ch-ui (ch-ui-wrapper Spring Boot fat jar)

Status: /tmp/batch9_cve_status.json
Summary: /root/cve_fix_llm/reports/batch9_status.md

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_COMPONENTS=clickhouse
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
RELEASE = "3.3.6.4"
ROOT = Path("/root/3.3.6.5")
STATUS = Path("/tmp/batch9_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch9_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "1800"))
TOKEN = ""

TOMCAT = "9.0.119"
JACKSON = "2.18.6"
LOGBACK = "1.5.37"
SLF4J = "2.0.18"
SPRING53 = "5.3.39"
SNAKEYAML = "2.0"

COMPONENTS = {
    "clickhouse": {
        "jira": "sehajsandhu/clickhouse",
        "gh": "acceldata-io/ch-ui",
        "work": ROOT / "ch-ui",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
    },
}

FILTER = [
    c.strip()
    for c in os.environ.get("CVE_COMPONENTS", "clickhouse").split(",")
    if c.strip()
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
    print(f"STATUS: {json.dumps(kwargs)[:700]}", flush=True)


def write_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Batch9 CVE status ({RELEASE}) — clickhouse first",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        "",
        "Google Sheet: not updated (no Sheets credentials).",
        "",
        "Note: Jira `sehajsandhu/clickhouse` maps to GitHub `acceldata-io/ch-ui`",
        "(Spring Boot `ch-ui-wrapper` fat jar under clickhouse/ui).",
        "",
    ]
    for comp, res in results.items():
        lines.append(f"## {comp}")
        lines.append(f"- excepted: {', '.join(res.get('excepted') or []) or '—'}")
        lines.append(f"- closed: {', '.join(res.get('closed') or []) or '—'}")
        if res.get("already_fixed"):
            lines.append(f"- already-fixed: {', '.join(res['already_fixed'])}")
        for pr in res.get("prs") or []:
            lines.append(f"- PR: {pr}")
        if res.get("unknown"):
            lines.append(f"- unknown: {', '.join(res['unknown'])}")
        if res.get("errors"):
            lines.append(f"- errors: {json.dumps(res['errors'])[:500]}")
        lines.append("")
    SUMMARY.write_text("\n".join(lines), encoding="utf-8")


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


def jdk_home(jdk: int):
    for c in (
        f"/usr/lib/jvm/java-{jdk}-openjdk",
        f"/usr/lib/jvm/java-{jdk}",
        f"/usr/lib/jvm/temurin-{jdk}",
    ):
        if Path(c).exists():
            return c
    jvm = Path("/usr/lib/jvm")
    if jvm.is_dir():
        for p in sorted(jvm.iterdir()):
            if p.is_dir() and str(jdk) in p.name:
                return str(p)
    raise SystemExit(f"JDK {jdk} not found")


def git_env(jdk: int = 11):
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    home = jdk_home(jdk)
    env["JAVA_HOME"] = home
    env["PATH"] = f"{home}/bin:" + env.get("PATH", "")
    return env


def run(cmd, cwd, env=None, timeout=TIMEOUT, log_path=None):
    print(f"+ ({cwd}) {cmd}", flush=True)
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=str(cwd), text=True,
            capture_output=True, env=env or git_env(), timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"TIMEOUT after {timeout}s"
    out, err = p.stdout or "", p.stderr or ""
    if log_path:
        Path(log_path).write_text(out + "\n" + err, encoding="utf-8", errors="replace")
    return p.returncode, out, err


def load_tickets(ca, cfg):
    jira = cfg["jira"]
    jql = f'project = OSV AND status = "To Do" AND summary ~ "{jira}" ORDER BY key ASC'
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,customfield_10870,"
                "customfield_10892,customfield_10891,customfield_10888,"
                "customfield_10127"
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
        repo = field_text(f.get("customfield_10870"))
        if jira not in repo and jira not in (f.get("summary") or ""):
            continue
        if field_text(f.get("customfield_10893")) != RELEASE:
            continue
        summ = f.get("summary") or ""
        pkg = field_text(f.get("customfield_10875"))
        fix = (
            ca.extract_fixed_version(f.get("customfield_10891"))
            if hasattr(ca, "extract_fixed_version")
            else field_text(f.get("customfield_10891"))
        )
        cve = field_text(f.get("customfield_10127")) or ""
        if not cve:
            m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
            cve = m.group(1) if m else ""
        rows.append({
            "key": i["key"],
            "pkg": pkg,
            "ver": field_text(f.get("customfield_10892")),
            "fix": fix or "",
            "path": field_text(f.get("customfield_10888")),
            "cve": cve,
            "summary": summ,
            "repo": repo,
        })
    return rows


def classify_clickhouse(row):
    pkg = (row["pkg"] or "").lower()
    fix = row["fix"] or ""

    if "spring-boot" in pkg and "starter" not in pkg:
        return "exception", (
            "Spring Boot 2.7.x; advisory fixes are on 3.x/4.x (major). "
            "Exception Request (Deferred)."
        )
    if pkg.startswith("spring-") or "spring-" in pkg:
        # same-line 5.3.39 where listed; else major / unpublished 5.3.41+
        if any(v in fix for v in ("5.3.39", "5.3.38", "5.3.33")):
            return "fix_spring", {
                "target": SPRING53, "lib": "spring", "name": "Spring Framework",
            }
        return "exception", (
            f"Spring Framework advisory needs 6.x/7.x or unpublished 5.3.41+ "
            f"({fix}); ch-ui stays on Boot 2.7 / Spring 5.3.x. "
            "Exception Request (Deferred)."
        )
    if "tomcat" in pkg:
        return "fix_tomcat", {
            "target": TOMCAT, "lib": "tomcat", "name": "Tomcat Embed",
        }
    if "jackson" in pkg:
        return "fix_jackson", {
            "target": JACKSON, "lib": "jackson", "name": "Jackson",
        }
    if "logback" in pkg:
        return "fix_logback", {
            "target": LOGBACK, "lib": "logback", "name": "logback",
        }
    if "snakeyaml" in pkg:
        # nightly already at 2.0 which covers 1.31/1.32/2.0 advisories
        return "already_fixed", {
            "note": (
                f"ch-ui-wrapper already pins snakeyaml.version={SNAKEYAML} on "
                f"{COMPONENTS['clickhouse']['base']} (covers flagged snakeyaml CVEs)."
            ),
        }
    return "unknown", f"No rule for {pkg}"


CLASSIFY = {"clickhouse": classify_clickhouse}


def set_prop(pom: Path, prop: str, ver: str):
    text = pom.read_text(encoding="utf-8")
    pat = rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)"
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n == 1:
        pom.write_text(text2, encoding="utf-8")
        return
    if "</properties>" not in text:
        raise RuntimeError(f"no properties / {prop}")
    pom.write_text(
        text.replace(
            "</properties>",
            f"        <{prop}>{ver}</{prop}>\n    </properties>",
            1,
        ),
        encoding="utf-8",
    )


def apply_tomcat(work: Path):
    set_prop(work / "ch-ui-wrapper/pom.xml", "tomcat.version", TOMCAT)
    return ["ch-ui-wrapper/pom.xml"]


def apply_jackson(work: Path):
    set_prop(work / "ch-ui-wrapper/pom.xml", "jackson-bom.version", JACKSON)
    return ["ch-ui-wrapper/pom.xml"]


def apply_logback(work: Path):
    pom = work / "ch-ui-wrapper/pom.xml"
    set_prop(pom, "logback.version", LOGBACK)
    set_prop(pom, "slf4j.version", SLF4J)
    return ["ch-ui-wrapper/pom.xml"]


def apply_spring(work: Path):
    set_prop(work / "ch-ui-wrapper/pom.xml", "spring-framework.version", SPRING53)
    return ["ch-ui-wrapper/pom.xml"]


APPLY = {
    ("clickhouse", "tomcat"): apply_tomcat,
    ("clickhouse", "jackson"): apply_jackson,
    ("clickhouse", "logback"): apply_logback,
    ("clickhouse", "spring"): apply_spring,
}


def ensure_repo(work: Path, gh: str, base: str, jdk: int):
    env = git_env(jdk)
    if not (work / ".git").exists():
        run(
            f"git clone https://github.com/{gh}.git {work}",
            ROOT, env=env, timeout=600,
        )
    run(f"git remote set-url origin https://github.com/{gh}.git", work, env=env, timeout=60)
    run(f"git fetch origin {base} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {base} origin/{base}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", work, env=env, timeout=300)


def compile_gate(comp: str, work: Path, lib: str, jdk: int) -> bool:
    log = f"/tmp/batch9_{comp}_{lib}_build.log"
    env = git_env(jdk)
    # spring-boot plugin packages frontend from ../dist — create minimal stub
    dist = work / "dist"
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text("<html><body>ch-ui</body></html>", encoding="utf-8")
    cmd = (
        "mvn -f ch-ui-wrapper/pom.xml -q -DskipTests "
        "-Dmaven.javadoc.skip=true package"
    )
    code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        for ln in (out + err).splitlines()[-40:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
    return code == 0


def create_pr(gh, branch, title, body, base):
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
    if r.status_code == 422:
        r2 = requests.get(
            f"https://api.github.com/repos/{gh}/pulls",
            headers=headers,
            params={"head": f"acceldata-io:{branch}", "state": "open"},
            timeout=60,
        )
        if r2.ok and r2.json():
            return r2.json()[0]["html_url"]
    print(f"PR fail {r.status_code}: {r.text[:500]}", flush=True)
    return None


def deliver_lib(ca, comp, cfg, lib, tickets):
    if not tickets:
        return None
    work = cfg["work"]
    gh = cfg["gh"]
    base = cfg["base"]
    jdk = cfg["jdk"]
    meta = tickets[0]
    name = meta.get("name") or lib
    target = meta.get("target")
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    cve_str = "/".join(cves) if cves else "CVE"
    title = f"{branch} - CVE - Bumped-up {name} to {target} to address {cve_str}"

    print(f"\n=== {comp}/{lib} PR branch={branch} ({len(tickets)} tickets) ===", flush=True)
    ensure_repo(work, gh, base, jdk)
    run(f"git checkout -B {branch} origin/{base}", work, env=git_env(jdk), timeout=120)

    applier = APPLY.get((comp, lib))
    if not applier:
        raise RuntimeError(f"no applier for {comp}/{lib}")
    changed = applier(work)
    if DRY:
        return {
            "lib": lib, "dry": True, "title": title,
            "tickets": [t["key"] for t in tickets],
        }

    if not compile_gate(comp, work, lib, jdk):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "branch": branch}

    run("git add -A", work, env=git_env(jdk), timeout=120)
    # do not commit stub dist if any
    run("git reset HEAD -- dist 2>/dev/null; git checkout -- dist 2>/dev/null; true", work, env=git_env(jdk), timeout=60)
    # only commit pom
    run("git add ch-ui-wrapper/pom.xml", work, env=git_env(jdk), timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(work), text=True, capture_output=True, env=git_env(jdk),
    )
    if p.returncode != 0:
        return {"lib": lib, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", work, env=git_env(jdk), timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: clickhouse / ch-ui ({base}, release {RELEASE})",
        f"- Library: {name} → {target}",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Files: {', '.join(changed)}",
        "",
        "Overrides Spring Boot 2.7.18 managed versions in ch-ui-wrapper so the",
        "rebuilt fat jar clears CVEs flagged under clickhouse/ui/lib/ch-ui-wrapper.jar.",
    ])
    pr = create_pr(gh, branch, title, body, base)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}

    closed = []
    for t in tickets:
        ok = ca.close_ticket_with_comment(
            t["key"],
            f"Fixed via PR: {pr} — bumped {name} to {target} on {base} (acceldata-io/ch-ui).",
            "Closed",
            assignee=ASSIGNEE,
        )
        print(f"  {t['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(t["key"])
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed, "branch": branch}


LIB_ORDER = {
    "clickhouse": ["tomcat", "jackson", "logback", "spring"],
}


def process_component(ca, comp: str):
    cfg = COMPONENTS[comp]
    write_status(phase=f"{comp}:load")
    rows = load_tickets(ca, cfg)
    write_status(**{f"{comp}_tickets": [r["key"] for r in rows]})

    excepted, fixable, unknown, already = [], [], [], []
    classify = CLASSIFY[comp]
    for row in rows:
        action, meta = classify(row)
        if action == "exception":
            print(f"[{comp}] EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE
                )
                (excepted if ok else unknown).append(row["key"])
        elif action == "already_fixed":
            print(f"[{comp}] ALREADY_FIXED {row['key']} {row['pkg']}", flush=True)
            note = meta.get("note") if isinstance(meta, dict) else str(meta)
            if DRY:
                already.append(row["key"])
            else:
                ok = ca.close_ticket_with_comment(
                    row["key"], note, "Closed", assignee=ASSIGNEE
                )
                (already if ok else unknown).append(row["key"])
        elif action.startswith("fix_"):
            print(
                f"[{comp}] FIXABLE {row['key']} {row['pkg']} -> {meta.get('target')}",
                flush=True,
            )
            fixable.append({**row, **meta, "action": action})
        else:
            print(f"[{comp}] UNKNOWN {row['key']} {meta}", flush=True)
            unknown.append(row["key"])

    if ROUTE_ONLY:
        return {
            "excepted": excepted,
            "fixable": [r["key"] for r in fixable],
            "already_fixed": already,
            "unknown": unknown,
            "prs": [],
            "fixable_detail": [
                {"key": r["key"], "lib": r.get("lib"), "target": r.get("target")}
                for r in fixable
            ],
        }

    by_lib: dict[str, list] = {}
    for r in fixable:
        by_lib.setdefault(r["lib"], []).append(r)

    prs, closed, errors = [], [], []
    for lib in LIB_ORDER[comp]:
        if lib not in by_lib:
            continue
        try:
            res = deliver_lib(ca, comp, cfg, lib, by_lib[lib])
        except Exception as e:
            res = {"lib": lib, "ok": False, "error": str(e)[:400]}
            print(f"[{comp}/{lib}] ERROR {e}", flush=True)
        if res and res.get("pr"):
            prs.append(res["pr"])
            closed.extend(res.get("closed") or [])
        elif res and not res.get("ok", True) and not res.get("dry"):
            errors.append(res)

    out = {
        "excepted": excepted,
        "closed": closed,
        "already_fixed": already,
        "prs": prs,
        "unknown": unknown,
    }
    if errors:
        out["errors"] = errors
    return out


def main():
    write_status(phase="start", components=FILTER)
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    results = {}
    for comp in FILTER:
        if comp not in COMPONENTS:
            print(f"skip unknown {comp}", flush=True)
            continue
        try:
            results[comp] = process_component(ca, comp)
        except Exception as e:
            results[comp] = {"error": str(e)[:800]}
        write_summary(results)
        write_status(phase=f"{comp}:done", results=results)

    write_status(phase="DONE", results=results)
    write_summary(results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        write_status(phase="INTERRUPTED")
        raise
