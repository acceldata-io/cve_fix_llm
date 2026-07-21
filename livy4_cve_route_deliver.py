#!/usr/bin/env python3
"""Livy4 (sehajsandhu/livy4, release 3.3.6.4) CVE routing + bumps.

Branch: nightly/ODP-4.1.1.3.3.6.5  (JDK 17)

CLOSE (transitive / already-fixed PR):
  - commons-io shaded in velocity-engine-core -> hive#167
  - netty-handler-proxy 4.2.7 -> livy#100 (Netty 4.2.13.Final)

EXCEPTION:
  - jetty-runner fat jar (mina / jetty-* / commons-lang3)
  - livy-server own CVEs
  - hadoop-common
  - pac4j-core (Hive transitive)

FIX (Livy-owned, one PR):
  - commons-configuration2 2.11.0 -> 2.15.0
  - jackson 2.15.4 -> 2.18.6
  - okio-jvm 3.2.0 -> 3.4.0

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 supported
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
WORK = Path("/root/3.3.6.5/livy4")
if not WORK.is_dir():
    WORK = Path("/root/3.3.6.5/livy")
GH = "acceldata-io/livy"
BASE = "nightly/ODP-4.1.1.3.3.6.5"
JIRA = "sehajsandhu/livy4"
STATUS = Path("/tmp/livy4_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""
JDK = 17

BUILD = (
    "mvn -DskipTests -Drat.skip=true -Denforcer.skip=true -DskipITs "
    "-Dremoteresources.skip=true "
    "package -pl '!integration-test,!thriftserver/server,!coverage,!python-api,!assembly'"
)

CLOSE_RULES = [
    {
        "path_re": r"velocity-engine-core-",
        "pkg_re": r"commons-io",
        "pr": "https://github.com/acceldata-io/hive/pull/167",
        "why": (
            "commons-io is shaded inside velocity-engine-core; Hive bumped "
            "velocity to 2.4.1 (hive#167). Livy thriftserver pulls Hive."
        ),
    },
    {
        "path_re": r"netty-",
        "pkg_re": r"io\.netty|netty",
        "pr": "https://github.com/acceldata-io/livy/pull/100",
        "why": (
            "Netty already bumped to 4.2.13.Final on this branch via livy#100 "
            "(OSV-23293 et al.); this module is covered by that bump."
        ),
    },
]

EXCEPTION_RULES = [
    {
        "path_re": r"jetty-runner-",
        "why": (
            "Vulnerable classes are bundled inside the third-party "
            "jetty-runner fat jar (9.4.x) and cannot be bumped independently; "
            "jetty 9.4 has no fix for the jetty-* CVEs (fix only in 12.x). "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"livy-server-",
        "pkg_re": r"livy-server",
        "why": (
            "Vulnerabilities in Livy's own server code; published fix is "
            "0.9.0-incubating (code backport, not a dependency bump). "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"hadoop-common-",
        "pkg_re": r"hadoop-common",
        "why": (
            "hadoop-common is the ODP Hadoop platform fork; upgrade is owned "
            "by the Hadoop build, not bumpable inside Livy. "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"pac4j-core-",
        "pkg_re": r"pac4j",
        "why": (
            "pac4j-core is pulled transitively from Hive; fix only in "
            "5.7.10 / 6.4.1 (major jump from 4.5.x) and must be applied in "
            "Hive. Exception Request (Deferred)."
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
    print(f"STATUS: {json.dumps(kwargs)[:400]}", flush=True)


def field_text(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        out = []

        def walk(n):
            if isinstance(n, dict):
                if n.get("type") == "text":
                    out.append(n.get("text") or "")
                for c in n.get("content") or []:
                    walk(c)
            elif isinstance(n, list):
                for c in n:
                    walk(c)

        walk(v)
        return " ".join(out) if out else ""
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


def git_env():
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    return env


def jdk_home():
    for c in [f"/usr/lib/jvm/java-{JDK}-openjdk", f"/usr/lib/jvm/java-{JDK}"]:
        if Path(c).exists():
            return c
    raise SystemExit(f"JDK {JDK} not found")


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


def load_tickets(ca):
    jql = f'project = OSV AND status = "To Do" AND summary ~ "{JIRA}" ORDER BY key ASC'
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10888,customfield_10875,"
                "customfield_10892,status,priority"
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
        path = field_text(f.get("customfield_10888"))
        pkg = field_text(f.get("customfield_10875"))
        summ = f.get("summary") or ""
        if "3.3.6.4" not in path and "3.3.6.4" not in summ:
            continue
        m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
        rows.append({
            "key": i["key"],
            "path": path,
            "pkg": pkg,
            "ver": field_text(f.get("customfield_10892")),
            "summary": summ,
            "cve": m.group(1) if m else "",
            "jar": path.split("/")[-1] if path else "",
        })
    return rows


def classify(row):
    path, pkg = row["path"] or "", row["pkg"] or ""
    for rule in CLOSE_RULES:
        if re.search(rule["path_re"], path) and re.search(rule["pkg_re"], pkg, re.I):
            return "close", rule
    for rule in EXCEPTION_RULES:
        if re.search(rule["path_re"], path):
            return "exception", rule
    jar = row["jar"]
    if "commons-configuration2" in jar or "commons-configuration2" in pkg:
        return "fix_config2", None
    if "jackson" in jar.lower() or "jackson" in pkg.lower():
        return "fix_jackson", None
    if "okio" in jar.lower() or "okio" in pkg.lower():
        return "fix_okio", None
    return "unknown", None


def route_tickets(ca, rows):
    closed, excepted, fixable, unknown = [], [], [], []
    for row in rows:
        action, rule = classify(row)
        key = row["key"]
        if action == "close":
            comment = f"Closed: {rule['why']} See {rule['pr']}."
            print(f"CLOSE {key} ({row['jar']}) -> {rule['pr']}", flush=True)
            if not DRY:
                ok = ca.close_ticket_with_comment(key, comment, "Closed", assignee=ASSIGNEE)
                (closed if ok else unknown).append({**row, "action": "close", "ok": ok})
            else:
                closed.append({**row, "action": "close", "ok": True})
        elif action == "exception":
            print(f"EXCEPTION {key} ({row['jar']})", flush=True)
            if not DRY:
                ok = ca.update_ticket_exception(key, rule["why"], reason="Deferred", assignee=ASSIGNEE)
                (excepted if ok else unknown).append({**row, "action": "exception", "ok": ok})
            else:
                excepted.append({**row, "action": "exception", "ok": True})
        elif action.startswith("fix_"):
            print(f"FIXABLE {key} ({row['jar']}) -> {action}", flush=True)
            fixable.append({**row, "action": action})
        else:
            print(f"UNKNOWN {key} path={row['path'][:80]} pkg={row['pkg']}", flush=True)
            unknown.append({**row, "action": "unknown"})
    return closed, excepted, fixable, unknown


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=300)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    return WORK


def apply_bumps(repo: Path, need_config2: bool, need_jackson: bool, need_okio: bool) -> list[str]:
    pom = repo / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text

    if need_jackson:
        text2, n = re.subn(
            r"(<jackson\.version>)([^<]+)(</jackson\.version>)",
            r"\g<1>2.18.6\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("jackson.version not found")
        text = text2

    if need_config2:
        text2, n = re.subn(
            r"(<artifactId>commons-configuration2</artifactId>\s*\n\s*"
            r"<version>)([^<]+)(</version>)",
            r"\g<1>2.15.0\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("commons-configuration2 version not found")
        text = text2

    if need_okio:
        if "okio.version" in text:
            text, _ = re.subn(
                r"(<okio\.version>)([^<]+)(</okio\.version>)",
                r"\g<1>3.4.0\g<3>",
                text,
                count=1,
            )
        else:
            text = text.replace(
                "<jackson.version>",
                "<okio.version>3.4.0</okio.version>\n    <jackson.version>",
                1,
            )
        okio_block = """
            <!-- CVE: okio-jvm 3.2.0 -> 3.4.0 (CVE-2023-3635) -->
            <dependency>
                <groupId>com.squareup.okio</groupId>
                <artifactId>okio-jvm</artifactId>
                <version>${okio.version}</version>
            </dependency>
            <dependency>
                <groupId>com.squareup.okio</groupId>
                <artifactId>okio</artifactId>
                <version>${okio.version}</version>
            </dependency>
"""
        if "okio-jvm" not in text or "${okio.version}" not in text:
            markers = [
                "    </dependencies>\n  </dependencyManagement>",
                "        </dependencies>\n    </dependencyManagement>",
            ]
            inserted = False
            for m in markers:
                if m in text:
                    text = text.replace(m, okio_block + "\n" + m, 1)
                    inserted = True
                    break
            if not inserted:
                raise RuntimeError("failed to insert okio dependencyManagement")

    if text == orig:
        raise RuntimeError("no pom changes")
    pom.write_text(text, encoding="utf-8")
    return ["pom.xml"]


def create_pr(branch, title, body):
    import requests
    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    r = requests.post(
        f"https://api.github.com/repos/{GH}/pulls",
        headers=headers,
        json={"title": title, "head": branch, "base": BASE, "body": body},
        timeout=60,
    )
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        requests.post(
            f"https://api.github.com/repos/{GH}/pulls/{num}/requested_reviewers",
            headers=headers, json={"reviewers": [REVIEWER]}, timeout=60,
        )
        return url
    print(f"PR fail {r.status_code}: {r.text[:400]}", flush=True)
    return None


def deliver(ca, fix_rows):
    if not fix_rows:
        return None
    need_config2 = any(r["action"] == "fix_config2" for r in fix_rows)
    need_jackson = any(r["action"] == "fix_jackson" for r in fix_rows)
    need_okio = any(r["action"] == "fix_okio" for r in fix_rows)
    branch = fix_rows[0]["key"]
    parts = []
    if need_config2:
        parts.append("commons-configuration2 2.15.0")
    if need_jackson:
        parts.append("jackson 2.18.6")
    if need_okio:
        parts.append("okio 3.4.0")
    title = f"{branch} - CVE - Bumped-up {', '.join(parts)} to address Livy4 CVEs"

    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_bumps(WORK, need_config2, need_jackson, need_okio)
    write_status(patched=changed)

    java = jdk_home()
    env = git_env()
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log = "/tmp/livy4_compile.log"
    code, out, err = run(BUILD, WORK, env=env, timeout=TIMEOUT, log_path=log)
    write_status(compile={"exit": code, "ok": code == 0, "log": log})
    if code != 0:
        text = Path(log).read_text(errors="replace") if Path(log).exists() else out + err
        for ln in text.splitlines()[-80:]:
            if any(x in ln for x in ("ERROR", "FAILURE", "error:", "BUILD")):
                print("   ", ln[:220], flush=True)
        return {"ok": False, "log": log}

    body = "\n".join([
        f"- Component: livy4 ({BASE})",
        f"- Tickets: {', '.join(r['key'] for r in fix_rows)}",
        *(["- commons-configuration2: 2.11.0 -> 2.15.0"] if need_config2 else []),
        *(["- jackson: 2.15.4 -> 2.18.6"] if need_jackson else []),
        *(["- okio / okio-jvm: 3.2.0 -> 3.4.0"] if need_okio else []),
    ])
    if DRY:
        return {"ok": True, "dry": True, "title": title}

    run("git add -A", WORK, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title], cwd=str(WORK),
        text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        return {"ok": False, "commit_err": (p.stderr or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", WORK, timeout=300)
    if code != 0:
        return {"ok": False, "push_err": err[-400:]}
    pr = create_pr(branch, title, body)
    if not pr:
        return {"ok": False, "pr": None}

    closed = []
    for r in fix_rows:
        comment = f"Fixed via PR: {pr} — bumped Livy4-owned dependency on {BASE}."
        ok = ca.close_ticket_with_comment(r["key"], comment, "Closed", assignee=ASSIGNEE)
        print(f"  {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])
    return {"ok": True, "pr": pr, "closed": closed}


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca
    ca.DRY_RUN = DRY

    rows = load_tickets(ca)
    write_status(phase="loaded", count=len(rows))
    closed, excepted, fixable, unknown = route_tickets(ca, rows)
    write_status(
        phase="routed",
        closed=[r["key"] for r in closed],
        excepted=[r["key"] for r in excepted],
        fixable=[r["key"] for r in fixable],
        unknown=[r["key"] for r in unknown],
    )
    if ROUTE_ONLY:
        write_status(phase="ROUTE_ONLY_DONE")
        return

    res = deliver(ca, fixable)
    write_status(phase="DONE", result=res)
    print("DONE", json.dumps(res, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
