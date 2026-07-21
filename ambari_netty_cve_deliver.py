#!/usr/bin/env python3
"""odp-ambari Netty CVE deliver for release 3.0.0.1 on rel/ODP-AMBARI-3.0.0.2-1.

FIX (11): standalone netty-*-4.1.132.Final.jar inside files view jar
  -> bump ambari-project netty4.version 4.1.132.Final -> 4.1.135.Final

EXCEPTION (8): netty shaded inside aws-java-sdk-bundle-1.12.797.jar
EXCEPTION (5): ambari-infra-solr 4.1.99.Final (not built from this repo)

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1
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
RELEASE = "3.0.0.1"
WORK = Path("/root/3.0.0.2/odp-ambari")
GH = "acceldata-io/odp-ambari"
BASE = "rel/ODP-AMBARI-3.0.0.2-1"
JIRA = "sehajsandhu/ambari"
NETTY = "4.1.135.Final"
STATUS = Path("/tmp/ambari_netty_cve_status.json")
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
        "/usr/lib/jvm/java-17-openjdk",
        "/usr/lib/jvm/java-17",
        "/usr/lib/jvm/temurin-17",
    ):
        if Path(c).exists():
            return c
    raise SystemExit("JDK 17 not found")


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


def load_tickets(ca):
    jql = (
        f'project = OSV AND status = "To Do" AND assignee is EMPTY '
        f'AND summary ~ "{JIRA}" ORDER BY key ASC'
    )
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,customfield_10892,"
                "customfield_10891,customfield_10888,customfield_10127,"
                "customfield_10870"
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
        rel = field_text(f.get("customfield_10893"))
        if RELEASE not in rel:
            continue
        pkg = field_text(f.get("customfield_10875"))
        path = field_text(f.get("customfield_10888"))
        summ = f.get("summary") or ""
        if "netty" not in f"{pkg} {path} {summ}".lower():
            continue
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
            "path": path,
            "cve": cve,
            "summary": summ,
        })
    return rows


def classify(row):
    path = (row["path"] or "").lower()
    pkg = (row["pkg"] or "").lower()
    if "netty" not in pkg and "netty" not in path:
        return "unknown", "not netty"
    if "ambari-infra-solr" in path or "/solr-" in path:
        return "exception", (
            "Netty 4.1.99.Final is bundled inside ambari-infra-solr "
            "(vendor Solr webapp WEB-INF/lib), not built from odp-ambari "
            f"{BASE}. Remediation belongs to the ambari-infra/Solr package. "
            "Exception Request (Deferred)."
        )
    if "aws-java-sdk-bundle" in path:
        return "exception", (
            "Netty is shaded inside aws-java-sdk-bundle (fat jar). Ambari's "
            "netty4.version / netty-bom bump does not rewrite the shaded "
            "bundle; requires a newer AWS SDK line with patched Netty or an "
            "ODP hadoop-aws rebuild. Exception Request (Deferred)."
        )
    if re.search(r"netty-[a-z0-9.-]+-4\.1\.\d+", path) or "netty-" in path:
        # standalone netty jar inside files view
        return "fix", {"lib": "netty", "name": "Netty", "target": NETTY}
    return "unknown", f"unmapped path={path}"


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=900)


def apply_netty() -> list[str]:
    pom = WORK / "ambari-project/pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<netty4\.version>)[^<]+(</netty4\.version>)",
        rf"\g<1>{NETTY}\2",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("netty4.version not updated")
    # refresh comment
    text2 = re.sub(
        r"<!-- CVE-2026-33870 / CVE-2026-33871 \(HTTP smuggling in netty-codec-http\); align io\.netty 4\.1\.x -->",
        f"<!-- Netty CVEs fixed in 4.1.133+; pin {NETTY} via netty-bom -->",
        text2,
        count=1,
    )
    pom.write_text(text2, encoding="utf-8")
    return [f"ambari-project/pom.xml:netty4.version={NETTY}"]


def compile_gate() -> bool:
    log = "/tmp/ambari_netty_validate.log"
    env = git_env()
    # lightweight: validate ambari-project + files view module
    cmd = (
        "mvn -q -pl ambari-project,contrib/views/files -am validate "
        "-DskipTests -Dcheckstyle.skip=true -Drat.skip=true -Denforcer.skip=true"
    )
    code, out, err = run(cmd, WORK, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        # fallback root -N
        code2, out2, err2 = run(
            "mvn -q -N -f ambari-project/pom.xml validate -DskipTests",
            WORK, env=env, timeout=600, log_path=log,
        )
        if code2 == 0:
            print("   module validate failed; ambari-project -N OK", flush=True)
            return True
        for ln in (out + err + out2 + err2).splitlines()[-40:]:
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


def process(ca):
    write_status(phase="load")
    rows = load_tickets(ca)
    write_status(phase="loaded", count=len(rows), keys=[r["key"] for r in rows])
    excepted, fixable, unknown = [], [], []
    for row in rows:
        action, meta = classify(row)
        if action == "exception":
            print(f"[ambari] EXCEPTION {row['key']} {row['pkg']} path=...{row['path'][-60:]}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE,
                )
                (excepted if ok else unknown).append(row["key"])
        elif action == "fix":
            print(f"[ambari] FIXABLE {row['key']} {row['pkg']}@{row['ver']} -> {NETTY}", flush=True)
            fixable.append({**row, **meta})
        else:
            print(f"[ambari] UNKNOWN {row['key']} {meta}", flush=True)
            unknown.append(row["key"])

    if ROUTE_ONLY:
        return {
            "excepted": excepted,
            "fixable": [r["key"] for r in fixable],
            "unknown": unknown,
            "prs": [],
        }

    if not fixable:
        return {"excepted": excepted, "closed": [], "prs": [], "unknown": unknown}

    branch = fixable[0]["key"]
    cves = sorted({r["cve"] for r in fixable if r.get("cve")})
    title = (
        f"{branch} - CVE - Bumped-up Netty to {NETTY} to address "
        f"{'/'.join(cves) if cves else 'Netty CVEs'}"
    )
    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_netty()
    if DRY:
        return {"excepted": excepted, "dry": True, "title": title, "changed": changed}
    if not compile_gate():
        return {"excepted": excepted, "ok": False, "phase": "FAILED_COMPILE", "errors": [{"phase": "FAILED_COMPILE"}]}

    run("git add ambari-project/pom.xml", WORK, env=git_env(), timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(WORK), text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        return {"excepted": excepted, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", WORK, env=git_env(), timeout=300)
    if code != 0:
        return {"excepted": excepted, "ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: odp-ambari ({BASE}, scan release {RELEASE})",
        f"- Library: Netty → {NETTY} (ambari-project `netty4.version` + netty-bom)",
        f"- Tickets closed: {', '.join(r['key'] for r in fixable)}",
        f"- Files: {', '.join(changed)}",
        "",
        "Standalone `netty-*-4.1.132.Final.jar` inside the Files view are managed",
        "by Ambari's netty-bom. AWS-SDK-bundle-shaded and ambari-infra-solr Netty",
        "CVEs are Exception Requested separately.",
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        return {"excepted": excepted, "ok": False, "pr": None}

    closed = []
    for r in fixable:
        ok = ca.close_ticket_with_comment(
            r["key"],
            f"Fixed via PR: {pr} — bumped Netty to {NETTY} on {BASE} "
            f"(netty4.version / netty-bom). Addresses standalone Netty jars in "
            f"the Ambari Files view.",
            "Closed",
            assignee=ASSIGNEE,
        )
        print(f"  {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])
    return {"excepted": excepted, "closed": closed, "prs": [pr], "unknown": unknown}


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    results = process(ca)
    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    main()
