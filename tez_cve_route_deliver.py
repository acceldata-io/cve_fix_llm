#!/usr/bin/env python3
"""Tez (sehajsandhu/tez, release 3.3.6.4) CVE routing + bumps.

Branch: nightly/ODP-3.3.6.5  (JDK 11 gate; source level 1.8)

FIX (Tez-owned / DM-overridable):
  - asynchttpclient.version  2.12.4 -> 2.15.0
  - okio / okio-jvm (via okhttp from hadoop-hdfs-client) -> 3.4.0 (DM)
  - commons-configuration2 (Hadoop transitive) -> 2.15.0 (DM)

EXCEPTION:
  - jetty-* 9.4.x with only 11.x/12.x fixes (javax stack)
  - hadoop-common (ODP platform)
  - logback-core 1.3.x (fix only on 1.5.x)

Build: mvn -pl '!tez-ui,!tez-dist' -am (tez-ui needs ancient node)

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
WORK = Path("/root/3.3.6.5/tez")
GH = "acceldata-io/tez"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/tez"
RELEASE = "3.3.6.4"
STATUS = Path("/tmp/tez_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "5400"))
TOKEN = ""
JDK = 11

AHC = "2.15.0"
OKIO = "3.4.0"
CONFIG2 = "2.15.0"

BUILD = (
    "mvn -DskipTests -Dmaven.test.skip=true -Dmaven.javadoc.skip=true "
    "-Drat.skip=true -Denforcer.skip=true "
    "-pl '!tez-dist' -am package"
)
DELIVER_ONLY = os.environ.get("CVE_DELIVER_ONLY", "") not in ("", "0", "false", "False")


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


def git_env():
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    home = jdk_home()
    env["JAVA_HOME"] = home
    env["PATH"] = f"{home}/bin:" + env.get("PATH", "")
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
    jql = (
        f'project = OSV AND status = "To Do" AND summary ~ "{JIRA}" '
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
            "cve": m.group(1) if m else "",
            "summary": summ,
        })
    return rows


def classify(row):
    pkg = (row["pkg"] or "").lower()

    if "hadoop" in pkg:
        return "exception", {
            "why": (
                "hadoop-common is the ODP Hadoop platform artifact; remediation "
                "belongs to the Hadoop component, not a Tez-owned dependency pin. "
                "Exception Request (Deferred)."
            )
        }

    if "jetty" in pkg:
        return "exception", {
            "why": (
                "Jetty CVE fix is only published on 11.x/12.x; Tez stays on "
                "Jetty 9.4.x (javax.servlet / JDK 8 stack) with no same-major "
                "9.4.x fix. Exception Request (Deferred)."
            )
        }

    if "logback" in pkg:
        return "exception", {
            "why": (
                "logback-core 1.3.x fix is only on the 1.5.x line; Tez pulls "
                "logback transitively and does not own a safe same-major bump. "
                "Exception Request (Deferred)."
            )
        }

    if "async-http-client" in pkg or "asynchttpclient" in pkg:
        return "fix_ahc", {"target": AHC}

    if "okio" in pkg:
        return "fix_okio", {"target": OKIO}

    if "commons-configuration2" in pkg or "commons_configuration2" in pkg:
        return "fix_config2", {"target": CONFIG2}

    return "unknown", {}


def route_tickets(ca, rows):
    excepted, fixable, unknown = [], [], []
    need = {"ahc": False, "okio": False, "config2": False}
    for row in rows:
        action, meta = classify(row)
        key = row["key"]
        if action == "exception":
            print(f"EXCEPTION {key} {row['pkg']}", flush=True)
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
                f"FIXABLE {key} {row['pkg']} -> {meta.get('target')} ({kind})",
                flush=True,
            )
            fixable.append({**row, "action": action, **meta})
        else:
            print(
                f"UNKNOWN {key} pkg={row['pkg']} ver={row['ver']} fix={row['fix']}",
                flush=True,
            )
            unknown.append({**row, "action": "unknown"})
    return excepted, fixable, unknown, need


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    return WORK


def _ensure_dm_dep(text: str, group: str, artifact: str, version: str) -> str:
    """Insert or replace a dependencyManagement entry after commons-lang block."""
    # Replace existing managed pin if present
    pat = re.compile(
        rf"(<dependency>\s*<groupId>{re.escape(group)}</groupId>\s*"
        rf"<artifactId>{re.escape(artifact)}</artifactId>\s*"
        rf"<version>)([^<]+)(</version>)",
        re.S,
    )
    text2, n = pat.subn(rf"\g<1>{version}\g<3>", text, count=1)
    if n:
        return text2

    block = f"""      <dependency>
        <groupId>{group}</groupId>
        <artifactId>{artifact}</artifactId>
        <version>{version}</version>
      </dependency>
"""
    # Insert after commons-lang managed dep
    anchor = re.search(
        r"(<dependency>\s*<groupId>commons-lang</groupId>\s*"
        r"<artifactId>commons-lang</artifactId>\s*"
        r"<version>[^<]+</version>\s*</dependency>)",
        text,
        re.S,
    )
    if not anchor:
        raise RuntimeError("commons-lang DM anchor not found")
    return text[: anchor.end()] + "\n" + block + text[anchor.end() :]


def apply_bumps(need: dict) -> list[str]:
    pom = WORK / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text

    if need.get("ahc"):
        text2, n = re.subn(
            r"(<asynchttpclient\.version>)([^<]+)(</asynchttpclient\.version>)",
            rf"\g<1>{AHC}\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("asynchttpclient.version not found")
        text = text2

    if need.get("okio"):
        # okhttp 4.x pulls okio-jvm; pin both coordinates
        text = _ensure_dm_dep(text, "com.squareup.okio", "okio-jvm", OKIO)
        text = _ensure_dm_dep(text, "com.squareup.okio", "okio", OKIO)

    if need.get("config2"):
        text = _ensure_dm_dep(
            text, "org.apache.commons", "commons-configuration2", CONFIG2
        )

    if text != orig:
        pom.write_text(text, encoding="utf-8")
        return ["pom.xml"]
    return []


def compile_gate(log="/tmp/tez_cve_build.log") -> bool:
    code, out, err = run(BUILD, WORK, timeout=TIMEOUT, log_path=log)
    write_status(compile={"exit": code, "ok": code == 0, "log": log})
    if code != 0:
        for ln in (out + err).splitlines()[-50:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
    return code == 0


def create_pr(branch, title, body):
    import requests

    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
    }
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
            headers=headers,
            json={"reviewers": [REVIEWER]},
            timeout=60,
        )
        return url
    print(f"PR fail {r.status_code}: {r.text[:400]}", flush=True)
    return None


def deliver(ca, fixable, need):
    if not any(need.values()):
        print("No bumps to apply", flush=True)
        return {"ok": True, "pr": None, "closed": []}

    branch = fixable[0]["key"]
    parts = []
    if need.get("ahc"):
        parts.append(f"async-http-client {AHC}")
    if need.get("okio"):
        parts.append(f"okio {OKIO}")
    if need.get("config2"):
        parts.append(f"commons-configuration2 {CONFIG2}")
    title = (
        f"{branch} - CVE - Bumped-up {', '.join(parts)} "
        f"to address ODP {RELEASE} CVEs"
    )

    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_bumps(need)
    write_status(patched=changed, bumps=need)

    if DRY:
        return {"ok": True, "dry": True, "title": title, "bumps": need}

    if not compile_gate():
        return {"ok": False, "phase": "FAILED_COMPILE"}

    run("git add pom.xml", WORK, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(WORK),
        text=True,
        capture_output=True,
        env=git_env(),
    )
    if p.returncode != 0:
        return {"ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", WORK, timeout=300)
    if code != 0:
        return {"ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: tez ({BASE}, release {RELEASE})",
        f"- Tickets: {', '.join(r['key'] for r in fixable)}",
        "- Bumps:",
        *[
            f"  - async-http-client: -> {AHC}" if k == "ahc" and on else
            f"  - okio/okio-jvm: -> {OKIO}" if k == "okio" and on else
            f"  - commons-configuration2: -> {CONFIG2}" if k == "config2" and on else ""
            for k, on in need.items()
        ],
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        return {"ok": False, "pr": None}

    closed = []
    for r in fixable:
        comment = (
            f"Fixed via PR: {pr} — bumped {r['action'].replace('fix_', '')} "
            f"to {r.get('target')} on {BASE}."
        )
        ok = ca.close_ticket_with_comment(
            r["key"], comment, "Closed", assignee=ASSIGNEE
        )
        print(f"  {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])
    return {"ok": True, "pr": pr, "closed": closed, "bumps": need}


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY

    if DELIVER_ONLY:
        prev = json.loads(STATUS.read_text()) if STATUS.is_file() else {}
        need = prev.get("bumps") or {}
        fix_keys = prev.get("fixable") or []
        if not need or not fix_keys:
            raise SystemExit("CVE_DELIVER_ONLY needs prior status with bumps+fixable")
        fixable = [
            {"key": k, "pkg": "", "action": "fix_deps", "target": "see bumps"}
            for k in fix_keys
        ]
        write_status(phase="deliver_only", bumps=need, fixable=fix_keys)
        res = deliver(ca, fixable, need)
        write_status(phase="DONE", result=res)
        print("DONE", json.dumps(res, indent=2), flush=True)
        return

    rows = load_tickets(ca)
    write_status(phase="loaded", count=len(rows))
    excepted, fixable, unknown, need = route_tickets(ca, rows)
    write_status(
        phase="routed",
        excepted=[r["key"] for r in excepted],
        fixable=[r["key"] for r in fixable],
        unknown=[r["key"] for r in unknown],
        bumps=need,
    )
    if ROUTE_ONLY:
        write_status(phase="ROUTE_ONLY_DONE")
        return

    res = deliver(ca, fixable, need)
    write_status(phase="DONE", result=res)
    print("DONE", json.dumps(res, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
