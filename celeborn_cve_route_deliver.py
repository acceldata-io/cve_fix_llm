#!/usr/bin/env python3
"""Celeborn (sehajsandhu/celeborn, release 3.3.6.4) CVE routing + bumps.

Branch: nightly/ODP-3.3.6.5 (JDK 11)

CLOSE (existing PR):
  - All io.netty_* at 4.1.115/4.1.118 -> covered by netty.version 4.1.135.Final
    (PR #4 / OSV-22793). Highest same-major fix listed is 4.1.133.Final.

EXCEPTION:
  - jetty-* CVEs whose only published fixes are 12.x (no 9.4.x line)
  - org.apache.hadoop_hadoop-common (ODP Hadoop fork / platform)
  - commons-configuration2 pulled via Hadoop (not a Celeborn-owned pin)

FIX (Celeborn-owned property bumps, one PR):
  - netty.version            -> 4.1.135.Final   (if not already on open PR #4)
  - commons-lang3.version    -> 3.18.0
  - jetty.version            -> 9.4.57.v20241219  (covers 9.4.57-fix jetty-io)

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_USE_EXISTING_NETTY_PR=1 supported
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
USE_EXISTING_NETTY_PR = os.environ.get("CVE_USE_EXISTING_NETTY_PR", "1") not in (
    "", "0", "false", "False"
)
SKIP_NETTY_COMPILE = os.environ.get("CVE_SKIP_NETTY_COMPILE", "") not in (
    "", "0", "false", "False"
)
WORK = Path("/root/3.3.6.5/celeborn")
GH = "acceldata-io/celeborn"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/celeborn"
RELEASE = "3.3.6.4"
STATUS = Path("/tmp/celeborn_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
TOKEN = ""
JDK = 11

NETTY = "4.1.135.Final"
LANG3 = "3.18.0"
JETTY = "9.4.57.v20241219"
EXISTING_NETTY_PR = "https://github.com/acceldata-io/celeborn/pull/4"
EXISTING_NETTY_BRANCH = "OSV-22793"

BUILD = (
    "./build/make-distribution.sh --release "
    "-Dmaven.test.skip=true -DskipTests "
    "-Pspark-3.5 -Ptez -Pmr -Pjdk-11 -Paws -Dspotless.check.skip=true"
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
    env["JAVA_HOME"] = jdk_home()
    env["PATH"] = f"{env['JAVA_HOME']}/bin:" + env.get("PATH", "")
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


def norm_pkg(pkg: str) -> str:
    return (pkg or "").strip().lower().replace("_", ":").replace("-", ":")


def is_netty(pkg: str) -> bool:
    p = (pkg or "").lower()
    return "io.netty" in p or p.startswith("netty")


def is_jetty(pkg: str) -> bool:
    p = (pkg or "").lower()
    return "jetty" in p


def jetty_has_94_fix(fix_field: str) -> bool:
    """True if any listed fix is still on the 9.4.x line."""
    for v in parse_fix_versions(fix_field):
        if v.startswith("9.4."):
            return True
    return False


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
        m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
        rows.append({
            "key": i["key"],
            "pkg": pkg,
            "ver": field_text(f.get("customfield_10892")),
            "fix": fix or "",
            "path": field_text(f.get("customfield_10888")),
            "cve": m.group(1) if m else "",
            "summary": summ,
        })
    return rows


def classify(row):
    pkg = row["pkg"] or ""
    pl = pkg.lower()

    if is_netty(pkg):
        if USE_EXISTING_NETTY_PR:
            return "close_netty", {
                "why": (
                    f"Netty bumped to {NETTY} on {BASE} via {EXISTING_NETTY_PR} "
                    f"(netty.version). Same-major 4.1.x fixes up through "
                    f"4.1.133.Final are covered by {NETTY}."
                ),
                "pr": EXISTING_NETTY_PR,
            }
        return "fix_netty", {"target": NETTY}

    if "hadoop-common" in pl or "hadoop_hadoop-common" in pl:
        return "exception", {
            "why": (
                "hadoop-common is the ODP Hadoop platform artifact "
                f"({row.get('ver')}); remediation belongs to the Hadoop "
                "component, not a Celeborn-owned dependency pin. "
                "Exception Request (Deferred)."
            )
        }

    if "commons-configuration2" in pl or "commons_configuration2" in pl:
        return "exception", {
            "why": (
                "commons-configuration2 is pulled transitively via ODP "
                "Hadoop, not managed as a Celeborn property. Bumping it in "
                "Celeborn alone is not the owning fix path. "
                "Exception Request (Deferred)."
            )
        }

    if is_jetty(pkg):
        if jetty_has_94_fix(row["fix"]):
            return "fix_jetty", {"target": JETTY}
        return "exception", {
            "why": (
                "Jetty CVE fix is only published on 12.x; Celeborn stays on "
                "Jetty 9.4.x (javax/servlet stack) and has no same-major "
                "9.4.x fix. Exception Request (Deferred)."
            )
        }

    if "commons-lang3" in pl or "commons_lang3" in pl:
        return "fix_lang3", {"target": LANG3}

    return "unknown", {}


def route_tickets(ca, rows):
    closed, excepted, fixable, unknown = [], [], [], []
    need = {"netty": False, "lang3": False, "jetty": False}
    for row in rows:
        action, meta = classify(row)
        key = row["key"]
        if action == "close_netty":
            comment = f"Closed: {meta['why']}"
            print(f"CLOSE {key} {row['pkg']} -> {meta['pr']}", flush=True)
            if not DRY:
                ok = ca.close_ticket_with_comment(
                    key, comment, "Closed", assignee=ASSIGNEE
                )
                (closed if ok else unknown).append({**row, "action": action, "ok": ok})
            else:
                closed.append({**row, "action": action, "ok": True})
        elif action == "exception":
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
                f"FIXABLE {key} {row['pkg']}: -> {meta.get('target')} ({kind})",
                flush=True,
            )
            fixable.append({**row, "action": action, **meta})
        else:
            print(
                f"UNKNOWN {key} pkg={row['pkg']} ver={row['ver']} fix={row['fix']}",
                flush=True,
            )
            unknown.append({**row, "action": "unknown"})
    return closed, excepted, fixable, unknown, need


def ensure_repo(branch: str | None = None):
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    if branch and branch != BASE:
        run(f"git fetch origin {branch} --prune", WORK, env=env, timeout=300)
        run(f"git checkout -B {branch} origin/{branch}", WORK, env=env, timeout=120)
    else:
        run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=600)
    return WORK


def apply_bumps(need: dict) -> list[str]:
    pom = WORK / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text
    if need.get("netty"):
        text2, n = re.subn(
            r"(<netty\.version>)([^<]+)(</netty\.version>)",
            rf"\g<1>{NETTY}\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("netty.version not found")
        text = text2
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
    if need.get("jetty"):
        text2, n = re.subn(
            r"(<jetty\.version>)([^<]+)(</jetty\.version>)",
            rf"\g<1>{JETTY}\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("jetty.version not found")
        text = text2
    if text != orig:
        pom.write_text(text, encoding="utf-8")
        return ["pom.xml"]
    return []


def compile_gate(log="/tmp/celeborn_cve_build.log") -> bool:
    code, out, err = run(BUILD, WORK, timeout=TIMEOUT, log_path=log)
    write_status(compile={"exit": code, "ok": code == 0, "log": log})
    if code != 0:
        for ln in (out + err).splitlines()[-40:]:
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


def deliver_extra(ca, fixable, need):
    """PR for lang3/jetty (and netty if not using existing PR)."""
    deliver_need = {
        "netty": bool(need.get("netty")) and not USE_EXISTING_NETTY_PR,
        "lang3": bool(need.get("lang3")),
        "jetty": bool(need.get("jetty")),
    }
    if not any(deliver_need.values()):
        print("No extra bumps to deliver", flush=True)
        return {"ok": True, "pr": None, "closed": []}

    branch = fixable[0]["key"]
    parts = []
    if deliver_need["netty"]:
        parts.append(f"Netty {NETTY}")
    if deliver_need["lang3"]:
        parts.append(f"commons-lang3 {LANG3}")
    if deliver_need["jetty"]:
        parts.append(f"Jetty {JETTY}")
    title = (
        f"{branch} - CVE - Bumped-up {', '.join(parts)} "
        f"to address ODP {RELEASE} CVEs"
    )

    ensure_repo(BASE)
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_bumps(deliver_need)
    write_status(patched=changed, bumps=deliver_need)

    if DRY:
        return {"ok": True, "dry": True, "title": title, "bumps": deliver_need}

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
        f"- Component: celeborn ({BASE}, release {RELEASE})",
        f"- Tickets: {', '.join(r['key'] for r in fixable)}",
        "- Bumps:",
        *[f"  - {k}: -> {NETTY if k=='netty' else LANG3 if k=='lang3' else JETTY}"
          for k, v in deliver_need.items() if v],
        f"- Netty tickets closed against existing {EXISTING_NETTY_PR}"
        if USE_EXISTING_NETTY_PR else "",
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
    return {"ok": True, "pr": pr, "closed": closed, "bumps": deliver_need}


def verify_existing_netty_compile():
    """Compile-gate the already-open netty PR branch before closing tickets."""
    ensure_repo(EXISTING_NETTY_BRANCH)
    pom = (WORK / "pom.xml").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"<netty\.version>([^<]+)</netty\.version>", pom)
    ver = m.group(1) if m else ""
    write_status(netty_branch_version=ver)
    if ver != NETTY:
        print(f"WARN: expected netty {NETTY} on {EXISTING_NETTY_BRANCH}, got {ver}", flush=True)
    if DRY or SKIP_NETTY_COMPILE:
        write_status(netty_compile_skipped=True)
        return True
    return compile_gate("/tmp/celeborn_netty_pr4_build.log")


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY

    rows = load_tickets(ca)
    write_status(phase="loaded", count=len(rows))

    # Optionally verify existing netty PR compiles before closing netty todos
    netty_ok = True
    if USE_EXISTING_NETTY_PR and any(is_netty(r["pkg"]) for r in rows):
        write_status(phase="verify_netty_pr")
        netty_ok = verify_existing_netty_compile()
        write_status(netty_compile_ok=netty_ok)
        if not netty_ok and not DRY:
            write_status(phase="FAILED_NETTY_COMPILE")
            print("Existing netty PR failed compile; abort before closing", flush=True)
            return

    closed, excepted, fixable, unknown, need = route_tickets(ca, rows)
    # If using existing netty PR, netty is not in fixable
    write_status(
        phase="routed",
        closed=[r["key"] for r in closed],
        excepted=[r["key"] for r in excepted],
        fixable=[r["key"] for r in fixable],
        unknown=[r["key"] for r in unknown],
        need=need,
    )
    if ROUTE_ONLY:
        write_status(phase="ROUTE_ONLY_DONE")
        return

    res = deliver_extra(ca, fixable, need)
    write_status(phase="DONE", result=res)
    print("DONE", json.dumps(res, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
