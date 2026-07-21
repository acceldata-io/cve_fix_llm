#!/usr/bin/env python3
"""Livy3 / Livy3_3_3_3 / Livy3_3_5_1 (release 3.3.6.4) CVE routing + bumps.

Routing:
  CLOSE (transitive, PR ref):
    - commons-io shaded in velocity-engine-core -> Hive velocity 2.4.1 (hive#167)
    - commons-lang3 3.13.0 in rsc-jars (livy3_3_5_1) -> spark3#205

  EXCEPTION:
    - jetty-runner fat jar (mina / jetty-http / jetty-io / commons-lang3 3.17)
    - livy-server own CVEs (need 0.9.0 backport)
    - hadoop-common (ODP Hadoop fork)
    - pac4j-core (Hive transitive; fix only in 5.7+/6.x)
    - logback-core (transitive; fix only in 1.5.x)

  FIX (Livy-owned bumps, one PR per branch):
    - commons-configuration2 2.11.0 -> 2.15.0
    - jackson 2.15.4 -> 2.18.6 (where ticketed)
    - okio-jvm 3.2.0 -> 3.4.0

Branches:
  livy3         -> nightly/ODP-3.3.6.5
  livy3_3_3_3   -> nightly/ODP-3.3.3.3.3.6.5
  livy3_3_5_1   -> nightly/ODP-3.5.1.3.3.6.5

  CVE_DRY_RUN=1 to preview
  CVE_ROUTE_ONLY=1 to skip compile/PR
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
WORK = Path("/root/3.3.6.5/livy")
GH = "acceldata-io/livy"
STATUS = Path("/tmp/livy3_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

VARIANTS = [
    {
        "jira": "sehajsandhu/livy3",
        "base": "nightly/ODP-3.3.6.5",
        "label": "livy3",
    },
    {
        "jira": "sehajsandhu/livy3_3_3_3",
        "base": "nightly/ODP-3.3.3.3.3.6.5",
        "label": "livy3_3_3_3",
    },
    {
        "jira": "sehajsandhu/livy3_3_5_1",
        "base": "nightly/ODP-3.5.1.3.3.6.5",
        "label": "livy3_3_5_1",
    },
]

# Close rules: (path_re, pkg_re) -> pr, why
CLOSE_RULES = [
    {
        "path_re": r"velocity-engine-core-",
        "pkg_re": r"commons-io",
        "pr": "https://github.com/acceldata-io/hive/pull/167",
        "why": (
            "commons-io is shaded inside velocity-engine-core; Hive bumped "
            "velocity to 2.4.1 (hive#167 / OSV-17489). Livy thriftserver pulls "
            "Hive; remediation is owned by Hive."
        ),
    },
    {
        "path_re": r"rsc-jars/commons-lang3-",
        "pkg_re": r"commons-lang3",
        "pr": "https://github.com/acceldata-io/spark3/pull/205",
        "why": (
            "commons-lang3 in Livy rsc-jars is pulled from the Spark 3.5.1 "
            "baseline; fix owned by Spark (spark3#205 -> 3.18.0)."
        ),
    },
]

EXCEPTION_RULES = [
    {
        "path_re": r"jetty-runner-",
        "why": (
            "Vulnerable classes are bundled inside the third-party "
            "jetty-runner fat jar (9.4.x). They are not separately managed "
            "Livy dependencies and cannot be bumped independently; jetty 9.4 "
            "has no fix for the jetty-* CVEs (fix only in 12.x). "
            "Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"livy-server-",
        "pkg_re": r"livy-server",
        "why": (
            "These are vulnerabilities in Livy's own server code; the only "
            "published fix is 0.9.0-incubating, requiring a code backport "
            "rather than a dependency bump. Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"hadoop-common-",
        "pkg_re": r"hadoop-common",
        "why": (
            "hadoop-common is the ODP Hadoop platform fork; upgrading to "
            "3.4.0 is owned by the Hadoop build and coordinated across ODP, "
            "not bumpable inside Livy. Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"pac4j-core-",
        "pkg_re": r"pac4j",
        "why": (
            "pac4j-core is pulled transitively from Hive (pac4j-saml); the "
            "fix is only in pac4j 5.7.10 / 6.4.1 (major line jump from 4.5.x) "
            "and must be applied in Hive. Exception Request (Deferred)."
        ),
    },
    {
        "path_re": r"logback-core-",
        "pkg_re": r"logback",
        "why": (
            "logback-core is a transitive dependency; the published fix is "
            "only on the 1.5.x line (1.5.25), a major upgrade from 1.3.x that "
            "requires coordinated changes with logback-classic consumers. "
            "Exception Request (Deferred)."
        ),
    },
]

BUILD = (
    "mvn clean package -DskipTests -Pspark3 -Dremoteresources.skip=true "
    "-pl '!integration-test,!thriftserver/server,!coverage,!python-api,!assembly'"
)


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
    for c in ["/usr/lib/jvm/java-11-openjdk", "/usr/lib/jvm/java-11"]:
        if Path(c).exists():
            return c
    raise SystemExit("JDK 11 not found")


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
    rows = []
    for v in VARIANTS:
        jql = (
            f'project = OSV AND status = "To Do" AND summary ~ "{v["jira"]}" '
            "ORDER BY key ASC"
        )
        issues, token = [], None
        while True:
            params = {
                "jql": jql,
                "maxResults": 100,
                "fields": (
                    "summary,customfield_10888,customfield_10875,"
                    "customfield_10892,customfield_10891,status,priority"
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
        for i in issues:
            f = i["fields"]
            path = field_text(f.get("customfield_10888"))
            pkg = field_text(f.get("customfield_10875"))
            ver = field_text(f.get("customfield_10892"))
            summ = f.get("summary") or ""
            m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
            # Scope to ODP 3.3.6.4 scan paths only (JQL summary match also
            # returns older-release To Dos for the same jira repo tag).
            if "3.3.6.4" not in path and "3.3.6.4" not in summ:
                continue
            rows.append({
                "key": i["key"],
                "jira": v["jira"],
                "label": v["label"],
                "base": v["base"],
                "path": path,
                "pkg": pkg,
                "ver": ver,
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
            if rule.get("pkg_re") and not re.search(rule["pkg_re"], pkg, re.I):
                # path match alone is enough for jetty-runner
                if "jetty-runner" not in rule["path_re"]:
                    continue
            return "exception", rule
    # Fixable by Livy bump
    jar = row["jar"]
    if "commons-configuration2" in jar or "commons-configuration2" in pkg:
        return "fix_config2", None
    if "jackson-core" in jar or "jackson" in pkg.lower():
        return "fix_jackson", None
    if "okio" in jar or "okio" in pkg.lower():
        return "fix_okio", None
    return "unknown", None


def route_tickets(ca, rows):
    closed, excepted, fixable, unknown = [], [], [], []
    for row in rows:
        action, rule = classify(row)
        key = row["key"]
        if action == "close":
            comment = (
                f"Closed: transitive dependency — {rule['why']} "
                f"See {rule['pr']}."
            )
            print(f"CLOSE {key} ({row['jar']}) -> {rule['pr']}", flush=True)
            if not DRY:
                ok = ca.close_ticket_with_comment(key, comment, "Closed", assignee=ASSIGNEE)
                (closed if ok else unknown).append({**row, "action": "close", "pr": rule["pr"], "ok": ok})
            else:
                closed.append({**row, "action": "close", "pr": rule["pr"], "ok": True})
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


def ensure_repo(base: str) -> Path:
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {base} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {base} origin/{base}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=300)
    run(f"git checkout -B {base} origin/{base}", WORK, env=env, timeout=120)
    return WORK


def apply_bumps(repo: Path, need_config2: bool, need_jackson: bool, need_okio: bool) -> list[str]:
    pom = repo / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text
    changed = []

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
            r"(<artifactId>commons-configuration2</artifactId>\s*"
            r"<version>)2\.11\.0(</version>)",
            r"\g<1>2.15.0\g<2>",
            text,
            count=1,
            flags=re.DOTALL,
        )
        if n != 1:
            # try looser
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
            # add property near jackson.version
            text = text.replace(
                "<jackson.version>",
                "<okio.version>3.4.0</okio.version>\n    <jackson.version>",
                1,
            )
        # inject DM entries before </dependencyManagement> inner </dependencies>
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
                "      </dependencies>\n  </dependencyManagement>",
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
        raise RuntimeError("no pom changes applied")
    pom.write_text(text, encoding="utf-8")
    changed.append("pom.xml")
    return changed


def create_pr(branch, base, title, body):
    import requests
    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    r = requests.post(
        f"https://api.github.com/repos/{GH}/pulls",
        headers=headers,
        json={"title": title, "head": branch, "base": base, "body": body},
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


def deliver_variant(ca, label, base, fix_rows):
    if not fix_rows:
        print(f"[{label}] no fixable tickets", flush=True)
        return None

    need_config2 = any(r["action"] == "fix_config2" for r in fix_rows)
    need_jackson = any(r["action"] == "fix_jackson" for r in fix_rows)
    need_okio = any(r["action"] == "fix_okio" for r in fix_rows)

    branch = fix_rows[0]["key"]  # first OSV
    parts = []
    if need_config2:
        parts.append("commons-configuration2 2.15.0")
    if need_jackson:
        parts.append("jackson 2.18.6")
    if need_okio:
        parts.append("okio 3.4.0")
    title = f"{branch} - CVE - Bumped-up {', '.join(parts)} to address Livy CVEs"

    ensure_repo(base)
    run(f"git checkout -B {branch} origin/{base}", WORK, env=git_env(), timeout=120)
    changed = apply_bumps(WORK, need_config2, need_jackson, need_okio)
    write_status(**{f"{label}_patched": changed})

    java = jdk_home()
    env = git_env()
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log = f"/tmp/livy3_{label}_compile.log"
    code, out, err = run(BUILD, WORK, env=env, timeout=TIMEOUT, log_path=log)
    write_status(**{f"{label}_compile": {"exit": code, "ok": code == 0, "log": log}})
    if code != 0:
        text = Path(log).read_text(errors="replace") if Path(log).exists() else out + err
        for ln in text.splitlines()[-80:]:
            if any(x in ln for x in ("ERROR", "FAILURE", "error:", "BUILD")):
                print("   ", ln[:220], flush=True)
        return {"ok": False, "label": label, "log": log}

    body_lines = [f"- Component: {label} ({base})", f"- Tickets: {', '.join(r['key'] for r in fix_rows)}"]
    if need_config2:
        body_lines.append("- commons-configuration2: 2.11.0 -> 2.15.0")
    if need_jackson:
        body_lines.append("- jackson: 2.15.4 -> 2.18.6")
    if need_okio:
        body_lines.append("- okio / okio-jvm: 3.2.0 -> 3.4.0")

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
    pr = create_pr(branch, base, title, "\n".join(body_lines))
    if not pr:
        return {"ok": False, "pr": None}

    closed = []
    for r in fix_rows:
        comment = (
            f"Fixed via PR: {pr} — bumped Livy-owned dependency on {base}."
        )
        ok = ca.close_ticket_with_comment(r["key"], comment, "Closed", assignee=ASSIGNEE)
        print(f"  {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])
    return {"ok": True, "pr": pr, "closed": closed, "label": label}


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

    results = []
    for v in VARIANTS:
        fix_rows = [r for r in fixable if r["label"] == v["label"]]
        res = deliver_variant(ca, v["label"], v["base"], fix_rows)
        if res:
            results.append(res)
            write_status(**{f"{v['label']}_result": res})

    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
