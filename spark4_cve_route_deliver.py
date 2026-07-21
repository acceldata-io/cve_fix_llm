#!/usr/bin/env python3
"""Spark4 (sehajsandhu/spark4, release 3.3.6.4) CVE routing + bumps.

Repo/branch: acceldata-io/spark3 @ nightly/ODP-4.1.1.3.3.6.5  (JDK 17)

CLOSE:
  - yarn-shuffle netty-handler-proxy -> spark3#204 (Netty 4.2.13.Final)

EXCEPTION (shaded / platform / no same-major fix):
  - AWS SDK bundle netty, iceberg aircompressor, hadoop-client-*, gcs shaded,
    hive-exec 2.3, hudi bundle, okhttp 3.x->4.x major, jetty-http (no 11.x fix)

FIX (Spark-owned):
  - jetty 11.0.26 -> 11.0.28  (jetty-io CVEs with 11.0.27/28 fixes)
  - lz4-java 1.8.0 -> 1.8.1
  - vertx-core 4.5.14 -> 4.5.24  (via DM; pulled by fabric8 kubernetes-client)

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
WORK = Path("/root/3.3.6.5/spark4")
GH = "acceldata-io/spark3"
BASE = "nightly/ODP-4.1.1.3.3.6.5"
JIRA = "sehajsandhu/spark4"
STATUS = Path("/tmp/spark4_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
TOKEN = ""
JDK = 17

BUILD = (
    "./dev/make-distribution.sh --tgz "
    "-Pyarn,hadoop-3,hive,hive-thriftserver,kubernetes "
    "-Dscala.version=2.13.17 -DskipSparkTests -DskipTests -Dgpg.skip"
)

CLOSE_RULES = [
    {
        "path_re": r"yarn-shuffle|netty-",
        "pkg_re": r"io\.netty|netty",
        "pr": "https://github.com/acceldata-io/spark3/pull/204",
        "why": (
            "Netty already bumped to 4.2.13.Final on this branch via "
            "spark3#204 (OSV-23629 et al.); yarn-shuffle is rebuilt from "
            "netty.version."
        ),
    },
]

EXCEPTION_RULES = [
    {
        "path_re": r"bundle-.*\.jar$",
        "why": (
            "Vulnerable Netty classes are shaded inside the AWS SDK bundle "
            "jar and cannot be bumped via Spark's netty.version. "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"iceberg-.*\.jar$",
        "why": (
            "aircompressor is shaded inside the Iceberg Spark runtime bundle; "
            "remediation requires an Iceberg rebuild/upgrade, not a Spark "
            "dependency bump. Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"hadoop-client-(runtime|api)-",
        "why": (
            "This CVE is inside the ODP Hadoop client shaded jars shipped "
            "with Spark; fix is owned by the Hadoop platform build. "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"gcs-connector-.*shaded",
        "why": (
            "commons-codec is shaded inside the GCS connector jar and cannot "
            "be displaced by Spark dependency management. "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"hive-exec-",
        "pkg_re": r"hive",
        "why": (
            "hive-exec 2.3.x is Spark's embedded Hive fork; the published fix "
            "is Hive 4.0.1 (major upgrade). Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"hudi-.*bundle",
        "why": (
            "Vulnerable classes are shaded inside the Hudi Spark bundle and "
            "are not separately managed Spark dependencies. "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"okhttp-",
        "pkg_re": r"okhttp",
        "why": (
            "okhttp 3.12.12 has no fix on the 3.12.x line; remediation requires "
            "okhttp 4.9.2+ (major upgrade) with coordinated Spark/hadoop-cloud "
            "changes. Exception Request (Deferred)."
        ),
    },
    {
        # jetty-http CVE-2025-11143: published fixes are only on 12.x
        "path_re": r"spark-core_",
        "pkg_re": r"jetty-http",
        "why": (
            "jetty-http CVE has no published fix on the Jetty 11.x line "
            "(fix only in 12.x), which would be a major upgrade for Spark 4. "
            "Exception Request (Deferred)."
        ),
    },
    {
        # jetty-io needs 11.0.27/11.0.28 which are not in ODP staging Nexus
        "path_re": r"spark-core_",
        "pkg_re": r"jetty-io|jetty",
        "why": (
            "jetty-io fixes require Jetty 11.0.27 / 11.0.28 (or 12.x); those "
            "11.0.x artifacts are not available in the ODP staging Nexus "
            "(latest mirrored 11.x is 11.0.26), and Jetty 12.x is a major "
            "upgrade for Spark 4. Exception Request (Deferred)."
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
            "priority": (f.get("priority") or {}).get("name", ""),
        })
    return rows


def classify(row):
    path, pkg = row["path"] or "", row["pkg"] or ""
    for rule in CLOSE_RULES:
        if re.search(rule["path_re"], path) and re.search(rule["pkg_re"], pkg, re.I):
            return "close", rule
    for rule in EXCEPTION_RULES:
        if re.search(rule["path_re"], path):
            if rule.get("pkg_re") and not re.search(rule["pkg_re"], pkg, re.I):
                continue
            return "exception", rule
    jar = row["jar"]
    if "lz4-java" in jar or "lz4" in pkg.lower():
        return "fix_lz4", None
    if "vertx" in jar or "vertx" in pkg.lower():
        return "fix_vertx", None
    if "spark-core_" in path and "jetty" in pkg.lower():
        return "fix_jetty", None
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
            print(f"EXCEPTION {key} ({row['jar']}) pkg={row['pkg']}", flush=True)
            if not DRY:
                ok = ca.update_ticket_exception(key, rule["why"], reason="Deferred", assignee=ASSIGNEE)
                (excepted if ok else unknown).append({**row, "action": "exception", "ok": ok})
            else:
                excepted.append({**row, "action": "exception", "ok": True})
        elif action.startswith("fix_"):
            print(f"FIXABLE {key} ({row['jar']}) -> {action}", flush=True)
            fixable.append({**row, "action": action})
        else:
            print(f"UNKNOWN {key} path={row['path'][-90:]} pkg={row['pkg']}", flush=True)
            unknown.append({**row, "action": "unknown"})
    return closed, excepted, fixable, unknown


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    return WORK


def apply_bumps(repo: Path, need_jetty: bool, need_lz4: bool, need_vertx: bool) -> list[str]:
    pom = repo / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text

    if need_jetty:
        text2, n = re.subn(
            r"(<jetty\.version>)([^<]+)(</jetty\.version>)",
            r"\g<1>11.0.28\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("jetty.version not found")
        text = text2

    if need_lz4:
        text2, n = re.subn(
            r"(<artifactId>lz4-java</artifactId>\s*\n\s*<version>)1\.8\.0(</version>)",
            r"\g<1>1.8.1\g<2>",
            text,
            count=1,
        )
        if n != 1:
            text2, n = re.subn(
                r"(<artifactId>lz4-java</artifactId>\s*\n\s*<version>)([^<]+)(</version>)",
                r"\g<1>1.8.1\g<3>",
                text,
                count=1,
            )
        if n != 1:
            raise RuntimeError("lz4-java version not found")
        text = text2

    if need_vertx:
        if "vertx.version" in text:
            text, _ = re.subn(
                r"(<vertx\.version>)([^<]+)(</vertx\.version>)",
                r"\g<1>4.5.24\g<3>",
                text,
                count=1,
            )
        else:
            text = text.replace(
                "<jetty.version>",
                "<vertx.version>4.5.24</vertx.version>\n    <jetty.version>",
                1,
            )
        vertx_arts = [
            "vertx-core", "vertx-web-client", "vertx-web-common", "vertx-auth-common",
        ]
        block_lines = [
            "",
            "      <!-- CVE: vertx 4.5.14 -> 4.5.24 (OSV-23624 / CVE-2026-1002) -->",
        ]
        for art in vertx_arts:
            block_lines += [
                "      <dependency>",
                "        <groupId>io.vertx</groupId>",
                f"        <artifactId>{art}</artifactId>",
                "        <version>${vertx.version}</version>",
                "      </dependency>",
            ]
        block = "\n".join(block_lines) + "\n"
        if "vertx-core" not in text or "${vertx.version}" not in text:
            markers = [
                "    </dependencies>\n  </dependencyManagement>",
                "      </dependencies>\n  </dependencyManagement>",
            ]
            inserted = False
            for m in markers:
                if m in text:
                    text = text.replace(m, block + m, 1)
                    inserted = True
                    break
            if not inserted:
                raise RuntimeError("failed to insert vertx dependencyManagement")

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
    need_jetty = any(r["action"] == "fix_jetty" for r in fix_rows)
    need_lz4 = any(r["action"] == "fix_lz4" for r in fix_rows)
    need_vertx = any(r["action"] == "fix_vertx" for r in fix_rows)
    branch = fix_rows[0]["key"]
    parts = []
    if need_jetty:
        parts.append("jetty 11.0.28")
    if need_lz4:
        parts.append("lz4-java 1.8.1")
    if need_vertx:
        parts.append("vertx 4.5.24")
    title = f"{branch} - CVE - Bumped-up {', '.join(parts)} to address Spark4 CVEs"

    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_bumps(WORK, need_jetty, need_lz4, need_vertx)
    write_status(patched=changed)

    java = jdk_home()
    env = git_env()
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log = "/tmp/spark4_compile.log"
    code, out, err = run(BUILD, WORK, env=env, timeout=TIMEOUT, log_path=log)
    write_status(compile={"exit": code, "ok": code == 0, "log": log})
    if code != 0:
        text = Path(log).read_text(errors="replace") if Path(log).exists() else out + err
        for ln in text.splitlines()[-100:]:
            if any(x in ln for x in ("ERROR", "FAILURE", "error:", "BUILD", "Failed")):
                print("   ", ln[:220], flush=True)
        return {"ok": False, "log": log}

    body = "\n".join([
        f"- Component: spark4 ({BASE})",
        f"- Tickets: {', '.join(r['key'] for r in fix_rows)}",
        *(["- jetty: 11.0.26 -> 11.0.28 (jetty-io CVEs)"] if need_jetty else []),
        *(["- lz4-java: 1.8.0 -> 1.8.1"] if need_lz4 else []),
        *(["- vertx-*: 4.5.14 -> 4.5.24 (DM override for k8s client)"] if need_vertx else []),
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
        comment = f"Fixed via PR: {pr} — bumped Spark4-owned dependency on {BASE}."
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
