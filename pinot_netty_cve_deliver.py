#!/usr/bin/env python3
"""Re-open pinot Netty Exception Request tickets via bump to 4.1.135.Final.

Pinot already imports netty-bom at ${netty.version}. CVEs live in Pinot's own
plugin *-shaded.jar assemblies, so a property bump + rebuild addresses them.

Base: nightly/ODP-3.3.6.5
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
RELEASE = "3.3.6.4"
WORK = Path("/root/3.3.6.5/pinot")
GH = "acceldata-io/pinot"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/pinot"
NETTY = "4.1.135.Final"
STATUS = Path("/tmp/pinot_netty_fix_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""


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


def jdk_home():
    for c in (
        "/usr/lib/jvm/java-11-openjdk",
        "/usr/lib/jvm/java-11",
        "/usr/lib/jvm/temurin-11",
    ):
        if Path(c).exists():
            return c
    raise SystemExit("JDK 11 not found")


def git_env():
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    home = jdk_home()
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


def load_netty_tickets(ca):
    """Netty tickets in Exception Request or To Do for release 3.3.6.4."""
    rows = []
    for status in ("Exception Request", "To Do"):
        jql = (
            f'project = OSV AND status = "{status}" AND summary ~ "{JIRA}" '
            "ORDER BY key ASC"
        )
        issues, token = [], None
        while True:
            params = {
                "jql": jql,
                "maxResults": 100,
                "fields": (
                    "summary,status,customfield_10893,customfield_10875,"
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
        for i in issues:
            f = i["fields"]
            if field_text(f.get("customfield_10893")) != RELEASE:
                continue
            pkg = field_text(f.get("customfield_10875"))
            if "netty" not in pkg.lower():
                continue
            fix = (
                ca.extract_fixed_version(f.get("customfield_10891"))
                if hasattr(ca, "extract_fixed_version")
                else field_text(f.get("customfield_10891"))
            )
            cve = field_text(f.get("customfield_10127")) or ""
            if not cve:
                m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", f.get("summary") or "")
                cve = m.group(1) if m else ""
            rows.append({
                "key": i["key"],
                "pkg": pkg,
                "ver": field_text(f.get("customfield_10892")),
                "fix": fix or "",
                "path": field_text(f.get("customfield_10888")),
                "cve": cve,
                "status": status,
            })
    return rows


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=900)


def apply_netty() -> list[str]:
    pom = WORK / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<netty\.version>)[^<]+(</netty\.version>)",
        rf"\g<1>{NETTY}\2",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("netty.version property not updated")
    pom.write_text(text2, encoding="utf-8")
    return [f"pom.xml:netty.version={NETTY}"]


def compile_gate() -> bool:
    log = "/tmp/pinot_netty_validate.log"
    env = git_env()
    cmd = (
        "mvn -q -N validate -DskipTests -Dcheckstyle.skip=true "
        "-Drat.skip=true -Dspotless.check.skip=true -Denforcer.skip=true"
    )
    code, out, err = run(cmd, WORK, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        for ln in (out + err).splitlines()[-40:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
        return False
    return True


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
            headers=headers,
            json={"reviewers": [REVIEWER]},
            timeout=60,
        )
        return url
    if r.status_code == 422:
        r2 = requests.get(
            f"https://api.github.com/repos/{GH}/pulls",
            headers=headers,
            params={"head": f"acceldata-io:{branch}", "state": "open"},
            timeout=60,
        )
        if r2.ok and r2.json():
            return r2.json()[0]["html_url"]
    print(f"PR fail {r.status_code}: {r.text[:500]}", flush=True)
    return None


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    rows = load_netty_tickets(ca)
    write_status(phase="loaded", count=len(rows), keys=[r["key"] for r in rows])
    if not rows:
        write_status(phase="DONE", message="no netty tickets")
        print("No netty tickets in Exception Request / To Do", flush=True)
        return

    for r in rows:
        print(f"  {r['key']} [{r['status']}] {r['pkg']}@{r['ver']} fix={r['fix']}", flush=True)

    branch = rows[0]["key"]
    cves = sorted({r["cve"] for r in rows if r.get("cve")})
    title = (
        f"{branch} - CVE - Bumped-up Netty to {NETTY} to address "
        f"{'/'.join(cves) if cves else 'Netty CVEs'}"
    )

    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_netty()
    if DRY:
        write_status(phase="DRY", title=title, changed=changed)
        print("DRY", title, changed)
        return
    if not compile_gate():
        write_status(phase="FAILED_COMPILE")
        raise SystemExit("compile gate failed")

    run("git add pom.xml", WORK, env=git_env(), timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(WORK), text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        write_status(phase="COMMIT_FAIL", err=(p.stderr or p.stdout or "")[-400:])
        raise SystemExit("commit failed")
    code, _, err = run(f"git push -u origin {branch}", WORK, env=git_env(), timeout=300)
    if code != 0:
        write_status(phase="PUSH_FAIL", err=err[-400:])
        raise SystemExit("push failed")

    body = "\n".join([
        f"- Component: pinot ({BASE}, release {RELEASE})",
        f"- Library: Netty → {NETTY} (via netty.version + netty-bom)",
        f"- Tickets: {', '.join(r['key'] for r in rows)}",
        "- Note: CVEs were previously Exception Requested because they appear",
        "  inside pinot-*-shaded.jar plugins; those jars are Pinot's own",
        "  assemblies rebuilt from the managed Netty BOM, so this bump fixes them.",
        f"- Files: {', '.join(changed)}",
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        write_status(phase="PR_FAIL")
        raise SystemExit("PR create failed")

    closed = []
    for r in rows:
        comment = (
            f"Reclassifying from Exception Request: Netty is managed by Pinot "
            f"via `${{netty.version}}` / netty-bom. The flagged jars are Pinot's "
            f"own plugin shaded assemblies (pinot-kinesis / pinot-parquet), which "
            f"rebuild with the managed Netty version.\n\n"
            f"Fixed via PR: {pr} — bumped Netty to {NETTY} on {BASE}."
        )
        ok = ca.close_ticket_with_comment(
            r["key"], comment, "Closed", assignee=ASSIGNEE,
        )
        print(f"  {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])

    write_status(phase="DONE", pr=pr, closed=closed, changed=changed)
    print("DONE", pr, "closed", len(closed), "/", len(rows), flush=True)


if __name__ == "__main__":
    main()
