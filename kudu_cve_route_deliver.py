#!/usr/bin/env python3
"""Kudu (sehajsandhu/kudu, release 3.3.6.4) CVE routing + per-lib PRs.

Branch: nightly/ODP-3.3.6.5 (JDK 11)

FIX (separate PR per library):
  - netty 4.1.132.Final -> 4.1.135.Final  (java/gradle/dependencies.gradle)
  - commons-lang3 3.3.2 -> 3.18.0        (ext/ranger/install/lib/gradle.properties)
  - commons-compress 1.21 -> 1.26.0      (ext/ranger/install/lib/gradle.properties)

EXCEPTION:
  - jetty-* 9.4.x (fixes only on 12.x; also Hadoop-transitive in subprocess fat jar)
  - hadoop-common (ODP platform)
  - logback-core 1.3.x (fix only on 1.5.x; Hadoop-transitive)
  - commons-codec (transitive into kudu-test-utils shaded jar via httpclient)

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_DELIVER_ONLY=1 supported
  CVE_LIBS=netty,lang3,compress  to deliver a subset
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
DELIVER_ONLY = os.environ.get("CVE_DELIVER_ONLY", "") not in ("", "0", "false", "False")
WORK = Path("/root/3.3.6.5/kudu")
GH = "acceldata-io/kudu"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/kudu"
RELEASE = "3.3.6.4"
STATUS = Path("/tmp/kudu_cve_route_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "5400"))
TOKEN = ""
JDK = 11

NETTY = "4.1.135.Final"
LANG3 = "3.18.0"
COMPRESS = "1.26.0"

LIB_FILTER = {
    x.strip().lower()
    for x in os.environ.get("CVE_LIBS", "netty,lang3,compress").split(",")
    if x.strip()
}

# lib key -> (first-ticket branch name hint, human name, target ver)
LIB_META = {
    "netty": ("Netty4", NETTY),
    "lang3": ("commons-lang3", LANG3),
    "compress": ("commons-compress", COMPRESS),
}


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
    print(f"STATUS: {json.dumps(kwargs)[:500]}", flush=True)


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
    for c in [f"/usr/lib/jvm/java-{JDK}-openjdk", f"/usr/lib/jvm/java-{JDK}"]:
        if Path(c).exists():
            return c
    raise SystemExit(f"JDK {JDK} not found")


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


def jetty_has_94_fix(fix_field: str) -> bool:
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
            m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+|PRISMA-\d+-\d+)", summ)
            cve = m.group(1) if m else ""
        rows.append({
            "key": i["key"],
            "pkg": pkg,
            "ver": field_text(f.get("customfield_10892")),
            "fix": fix or "",
            "path": field_text(f.get("customfield_10888")),
            "cve": cve,
            "summary": summ,
        })
    return rows


def classify(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()

    if "hadoop-common" in pkg or "hadoop_hadoop-common" in pkg:
        return "exception", {
            "why": (
                "hadoop-common is the ODP Hadoop platform artifact "
                f"({row.get('ver')}); remediation belongs to the Hadoop "
                "component, not a Kudu-owned dependency pin. "
                "Exception Request (Deferred)."
            )
        }

    if "jetty" in pkg:
        if jetty_has_94_fix(row["fix"]):
            return "exception", {
                "why": (
                    "Jetty has a same-major 9.4.x fix listed, but the flagged "
                    "artifact is Hadoop-transitive inside the kudu-subprocess "
                    "fat jar (not Kudu's managed jetty.version). Exception "
                    "Request (Deferred)."
                )
            }
        return "exception", {
            "why": (
                "Jetty CVE fix is only published on 12.x; Kudu/Hadoop stay on "
                "Jetty 9.4.x (javax stack) with no same-major 9.4.x fix. "
                "Exception Request (Deferred)."
            )
        }

    if "logback" in pkg:
        return "exception", {
            "why": (
                "logback-core is at 1.3.x (Hadoop-transitive in subprocess fat "
                "jar); advisory fix is only on 1.5.x. Crossing the 1.3→1.5 "
                "line is not a safe Kudu-owned pin. Exception Request (Deferred)."
            )
        }

    if "commons-codec" in pkg or "commons_codec" in pkg:
        return "exception", {
            "why": (
                "commons-codec is transitive into the kudu-test-utils shaded "
                "jar via httpclient and is not a managed Kudu version pin. "
                "Exception Request (Deferred)."
            )
        }

    if "netty" in pkg or "io.netty" in pkg:
        return "fix_netty", {"target": NETTY, "lib": "netty"}

    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {"target": LANG3, "lib": "lang3"}

    if "commons-compress" in pkg or "commons_compress" in pkg:
        return "fix_compress", {"target": COMPRESS, "lib": "compress"}

    return "unknown", {}


def route_tickets(ca, rows):
    closed, excepted, fixable, unknown = [], [], [], []
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
                    {**row, "action": action, "ok": ok, **meta}
                )
            else:
                excepted.append({**row, "action": action, "ok": True, **meta})
        elif action.startswith("fix_"):
            print(
                f"FIXABLE {key} {row['pkg']}: -> {meta.get('target')} ({meta.get('lib')})",
                flush=True,
            )
            fixable.append({**row, "action": action, **meta})
        else:
            print(
                f"UNKNOWN {key} pkg={row['pkg']} ver={row['ver']} fix={row['fix']}",
                flush=True,
            )
            unknown.append({**row, "action": "unknown"})
    return closed, excepted, fixable, unknown


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx -e ext/ranger/install/lib/*.jar", WORK, env=env, timeout=600)
    return WORK


def apply_lib(lib: str) -> list[str]:
    changed = []
    if lib == "netty":
        path = WORK / "java" / "gradle" / "dependencies.gradle"
        text = path.read_text(encoding="utf-8")
        text2, n = re.subn(
            r'(netty\s*:\s*")([^"]+)(")',
            rf'\g<1>{NETTY}\g<3>',
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("netty version pin not found in dependencies.gradle")
        path.write_text(text2, encoding="utf-8")
        changed.append("java/gradle/dependencies.gradle")
    elif lib == "lang3":
        path = WORK / "ext" / "ranger" / "install" / "lib" / "gradle.properties"
        text = path.read_text(encoding="utf-8")
        text2, n = re.subn(
            r"(commonslangVersion=)([^\n]+)",
            rf"\g<1>{LANG3}",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("commonslangVersion not found")
        path.write_text(text2, encoding="utf-8")
        changed.append("ext/ranger/install/lib/gradle.properties")
    elif lib == "compress":
        path = WORK / "ext" / "ranger" / "install" / "lib" / "gradle.properties"
        text = path.read_text(encoding="utf-8")
        text2, n = re.subn(
            r"(commonscompressVersion=)([^\n]+)",
            rf"\g<1>{COMPRESS}",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("commonscompressVersion not found")
        path.write_text(text2, encoding="utf-8")
        changed.append("ext/ranger/install/lib/gradle.properties")
    else:
        raise RuntimeError(f"unknown lib {lib}")
    return changed


def compile_lib(lib: str) -> bool:
    env = git_env()
    if lib == "netty":
        log = "/tmp/kudu_cve_netty_build.log"
        # Gate: assemble Java modules that shade/consume netty (skip full cmake).
        cmd = "./gradlew jar -x test --no-daemon"
        code, out, err = run(cmd, WORK / "java", env=env, timeout=TIMEOUT, log_path=log)
    else:
        log = f"/tmp/kudu_cve_{lib}_build.log"
        # Resolve rangerVersion like do-component-build
        deps = (WORK / "java" / "gradle" / "dependencies.gradle").read_text(
            encoding="utf-8", errors="replace"
        )
        m = re.search(r'ranger\s*:\s*"([^"]+)"', deps)
        ranger_ver = m.group(1) if m else "2.5.0.3.3.6.5-SNAPSHOT"
        cmd = f"./gradlew --no-daemon clean downloadJars -PrangerVersion={ranger_ver}"
        code, out, err = run(
            cmd, WORK / "ext" / "ranger" / "install" / "lib",
            env=env, timeout=600, log_path=log,
        )
        if code == 0:
            jars = list((WORK / "ext" / "ranger" / "install" / "lib").glob("*.jar"))
            names = sorted(j.name for j in jars)
            print(f"  ranger jars: {names}", flush=True)
            if lib == "lang3" and not any(f"commons-lang3-{LANG3}" in n for n in names):
                print(f"  FAIL: expected commons-lang3-{LANG3}.jar", flush=True)
                code = 1
            if lib == "compress" and not any(
                f"commons-compress-{COMPRESS}" in n for n in names
            ):
                print(f"  FAIL: expected commons-compress-{COMPRESS}.jar", flush=True)
                code = 1
    write_status(compile={lib: {"exit": code, "ok": code == 0, "log": log}})
    if code != 0:
        for ln in (out + err).splitlines()[-30:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed", "exception")):
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


def deliver_one(ca, lib: str, tickets: list[dict]):
    if not tickets:
        return {"lib": lib, "ok": True, "skipped": True}

    lib_name, target = LIB_META[lib]
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    cve_str = "/".join(cves) if cves else "CVE"
    title = (
        f"{branch} - CVE - Bumped-up {lib_name} to {target} "
        f"to address {cve_str}"
    )

    print(f"\n=== DELIVER {lib} ({len(tickets)} tickets) branch={branch} ===", flush=True)
    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_lib(lib)
    write_status(delivering=lib, branch=branch, changed=changed)

    if DRY:
        return {"lib": lib, "ok": True, "dry": True, "title": title, "tickets": [t["key"] for t in tickets]}

    if not compile_lib(lib):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "branch": branch}

    # Don't commit downloaded ranger jars — only the properties/gradle pin.
    add_files = " ".join(changed)
    run(f"git add {add_files}", WORK, timeout=60)
    # Drop any jar noise from downloadJars
    run("git checkout -- ext/ranger/install/lib/*.jar 2>/dev/null || true", WORK, timeout=60)
    run("git clean -fd -- ext/ranger/install/lib/*.jar 2>/dev/null || true", WORK, timeout=60)

    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(WORK),
        text=True,
        capture_output=True,
        env=git_env(),
    )
    if p.returncode != 0:
        return {
            "lib": lib,
            "ok": False,
            "commit_err": (p.stderr or p.stdout or "")[-400:],
        }
    code, _, err = run(f"git push -u origin {branch}", WORK, timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: kudu ({BASE}, release {RELEASE})",
        f"- Library: {lib_name} → {target}",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Advisories: {', '.join(cves) if cves else 'n/a'}",
        f"- Files: {', '.join(changed)}",
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}

    closed = []
    for t in tickets:
        comment = (
            f"Fixed via PR: {pr} — bumped {lib_name} to {target} on {BASE}."
        )
        ok = ca.close_ticket_with_comment(
            t["key"], comment, "Closed", assignee=ASSIGNEE
        )
        print(f"  {t['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(t["key"])
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed, "branch": branch}


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY

    rows = load_tickets(ca)
    write_status(phase="loaded", count=len(rows), keys=[r["key"] for r in rows])

    if not DELIVER_ONLY:
        closed, excepted, fixable, unknown = route_tickets(ca, rows)
    else:
        closed, excepted, unknown = [], [], []
        fixable = []
        for row in rows:
            action, meta = classify(row)
            if action.startswith("fix_"):
                fixable.append({**row, "action": action, **meta})
        write_status(phase="deliver_only_classify", fixable=[r["key"] for r in fixable])

    write_status(
        phase="routed",
        closed=[r["key"] for r in closed],
        excepted=[r.get("key") for r in excepted],
        fixable=[r["key"] for r in fixable],
        unknown=[r["key"] for r in unknown],
    )
    if ROUTE_ONLY:
        write_status(phase="ROUTE_ONLY_DONE")
        return

    by_lib: dict[str, list] = {"netty": [], "lang3": [], "compress": []}
    for r in fixable:
        lib = r.get("lib")
        if lib in by_lib:
            by_lib[lib].append(r)

    results = []
    for lib in ("netty", "lang3", "compress"):
        if lib not in LIB_FILTER:
            print(f"SKIP {lib} (not in CVE_LIBS)", flush=True)
            continue
        results.append(deliver_one(ca, lib, by_lib[lib]))

    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
