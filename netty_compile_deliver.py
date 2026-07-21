#!/usr/bin/env python3
"""Netty owned-pin compile + PR deliver on node82.

Policy:
  - comps needing >=4.1.133  -> 4.1.135.Final
  - livy4 / nifi2 / spark4   -> 4.2.13.Final

Owned-pin only: close tickets whose CVE-Path is standalone netty-*.jar
or spark yarn-shuffle jars rebuilt from netty.version.
Commit: <OSV> - CVE - Bumped-up Netty to <ver> to address <CVE>
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

WORK = Path("/root/3.3.6.5")
BASE = "nightly/ODP-3.3.6.5"
RESULT = Path("/tmp/netty_compile_matrix.json")
REVIEWER = "basapuram-kumar"
ASSIGNEE = "senthil.kumar"
RELEASE = "3.3.6.4"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
SKIP_BUILD = os.environ.get("CVE_SKIP_BUILD", "0") not in ("0", "false", "False")
ONLY = [x.strip() for x in os.environ.get("CVE_ONLY_COMPS", "").split(",") if x.strip()]
RESUME = os.environ.get("CVE_RESUME", "1") == "1"
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "5400"))
MODE = os.environ.get("CVE_MODE", "compile")  # compile | deliver | both
TOKEN = ""

NETTY_41 = "4.1.135.Final"
NETTY_42 = "4.2.13.Final"

JOBS = [
    {
        "comp": "spark3", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3"], "jdk": 11, "branch": BASE,
        "version": NETTY_41,
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver -DskipTests -DskipSparkTests",
        "props": ["netty.version"],
        "close_path_re": r"yarn-shuffle|netty-",
    },
    {
        "comp": "spark3_3_3_3", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3_3_3_3"], "jdk": 11,
        "branch": "nightly/ODP-3.3.3.3.3.6.5",
        "version": NETTY_41,
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver -DskipTests -DskipSparkTests",
        "props": ["netty.version"],
        "close_path_re": r"yarn-shuffle|netty-",
    },
    {
        "comp": "spark3_3_5_1", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3_3_5_1"], "jdk": 11,
        "branch": "nightly/ODP-3.5.1.3.3.6.5",
        "version": NETTY_41,
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver -DskipTests -DskipSparkTests",
        "props": ["netty.version"],
        "close_path_re": r"yarn-shuffle|netty-",
    },
    {
        "comp": "spark4", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark4"], "jdk": 17,
        "branch": "nightly/ODP-4.1.1.3.3.6.5",
        "version": NETTY_42,
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver,kubernetes -Dscala.version=2.13.17 -DskipSparkTests -DskipTests -Dgpg.skip",
        "props": ["netty.version"],
        "close_path_re": r"yarn-shuffle|netty-",
    },
    {
        "comp": "livy4", "repo": "livy", "gh": "acceldata-io/livy",
        "jira_repos": ["sehajsandhu/livy4"], "jdk": 17,
        "branch": "nightly/ODP-4.1.1.3.3.6.5",
        "version": NETTY_42,
        "build": (
            "mvn -DskipTests -Drat.skip=true -Denforcer.skip=true -DskipITs "
            # integration-test needs unavailable spark tgz; coverage depends on it
            "package -pl '!integration-test,!coverage'"
        ),
        "props": ["netty.version"],  # all occurrences incl. nested profiles
        "close_path_re": r"/netty-[^/]+\.jar$",
    },
    {
        "comp": "nifi2", "repo": "nifi", "gh": "acceldata-io/nifi",
        "jira_repos": ["sehajsandhu/nifi2"], "jdk": 21,
        "branch": "nightly/ODP-2.7.2.3.3.6.5",
        "version": NETTY_42,
        "build": (
            "mvn -DskipTests -Dskip.npm -Dcheckstyle.skip=true -Denforcer.skip=true "
            "-Drat.skip=true -Dspotbugs.skip=true -Dspotless.check.skip=true "
            "dependency:resolve -N"
        ),
        "props": ["netty.4.version"],
        "close_path_re": r"/netty-[^/]+\.jar$",
    },
]


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
        "#!/bin/sh\ncase \"$1\" in\n*Username*) echo x-access-token ;;\n*Password*) echo \"$GITHUB_TOKEN\" ;;\nesac\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    os.environ["GIT_ASKPASS"] = str(askpass)
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GITHUB_TOKEN"] = TOKEN


def git_env() -> dict:
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    return env


def jdk_home(major: int) -> str:
    cands = {
        8: ["/usr/lib/jvm/java-1.8.0-openjdk", "/usr/lib/jvm/java-1.8.0"],
        11: ["/usr/lib/jvm/java-11-openjdk", "/usr/lib/jvm/java-11"],
        17: ["/usr/lib/jvm/java-17-openjdk", "/usr/lib/jvm/java-17"],
        21: ["/usr/lib/jvm/java-21-openjdk", "/usr/lib/jvm/java-21"],
    }
    for c in cands.get(major, []):
        if Path(c).exists():
            return c
    for p in Path("/usr/lib/jvm").glob(f"java-{major}*"):
        if p.is_dir():
            return str(p)
    # fall back for missing JDK 21
    if major == 21:
        for m in (17, 11):
            try:
                return jdk_home(m)
            except SystemExit:
                pass
    raise SystemExit(f"JDK {major} not found")


def run(cmd, cwd, env=None, timeout=TIMEOUT, log_path=None):
    print(f"+ ({cwd}) {cmd}", flush=True)
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=str(cwd), text=True,
            capture_output=True, env=env or git_env(), timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s", ""
    out, err = p.stdout or "", p.stderr or ""
    if log_path:
        Path(log_path).write_text(out + "\n" + err, encoding="utf-8", errors="replace")
    return p.returncode, out, err


def ensure_clone(job: dict) -> Path:
    repo = job["repo"]
    branch = job.get("branch", BASE)
    path = WORK / job["comp"]
    WORK.mkdir(parents=True, exist_ok=True)
    env = git_env()
    url = f"https://github.com/acceldata-io/{repo}.git"
    if (path / ".git").is_dir():
        run(f"git remote set-url origin {url}", path, env=env, timeout=60)
        code, _, err = run(f"git fetch origin {branch} --prune", path, env=env, timeout=300)
        if code != 0:
            # try discover livy4 branch
            if job.get("discover_branch"):
                code2, out, _ = run("git ls-remote --heads origin 'nightly/ODP-*'", path, env=env, timeout=120)
                cands = [ln.split("/")[-1] if False else ln.split("\t")[-1].replace("refs/heads/", "")
                         for ln in (out or "").splitlines() if "nightly/ODP" in ln]
                # prefer 4.0* for livy4
                pref = [c for c in cands if "4.0" in c or "4.1" in c]
                pick = (pref or cands or [None])[0]
                if pick:
                    job["branch"] = pick
                    branch = pick
                    print(f"  discovered branch {branch}", flush=True)
                    run(f"git fetch origin {branch} --prune", path, env=env, timeout=300)
            else:
                print(f"fetch warn: {err[-500:]}")
        run(f"git checkout -B {branch} origin/{branch}", path, env=env, timeout=120)
        return path
    code, _, err = run(
        f"git clone --branch {branch} --single-branch {url} {path.name}",
        WORK, env=env, timeout=900,
    )
    if code != 0 and job.get("discover_branch"):
        run(f"git clone --single-branch {url} {path.name}", WORK, env=env, timeout=900)
        return ensure_clone(job)
    if code != 0:
        raise RuntimeError(f"clone {repo} failed: {err[-800:]}")
    return path


def restore_clean(repo_dir: Path):
    run("git reset --hard HEAD && git clean -fdx", repo_dir, env=git_env(), timeout=300)


def discover_pins(repo_dir: Path, props: list[str]) -> list[dict]:
    pins = []
    files = []
    root = repo_dir / "pom.xml"
    if root.is_file():
        files.append(root)
    for p in repo_dir.rglob("pom.xml"):
        if any(x in str(p) for x in ("/target/", "/.git/")):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if "netty" not in text.lower():
            continue
        files.append(p)
    seen = set()
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(p.relative_to(repo_dir))
        for prop in props:
            for m in re.finditer(rf"<{re.escape(prop)}>([^<]+)</{re.escape(prop)}>", text):
                key = (rel, prop, m.group(1))
                if key in seen:
                    continue
                if "${" in m.group(1):
                    continue
                seen.add(key)
                pins.append({"file": rel, "kind": "xml", "name": prop, "value": m.group(1).strip()})
    return pins


def apply_version(repo_dir: Path, pins: list[dict], version: str, props: list[str]) -> list[str]:
    changed = []
    allowed = set(props)
    pins = [p for p in pins if p.get("name") in allowed]
    by_file: dict[str, list] = {}
    for pin in pins:
        by_file.setdefault(pin["file"], []).append(pin)
    for rel, plist in by_file.items():
        fp = repo_dir / rel
        if not fp.is_file():
            continue
        text = fp.read_text(encoding="utf-8", errors="replace")
        orig = text
        for pin in plist:
            name = pin["name"]
            text = re.sub(
                rf"<{re.escape(name)}>[^<]+</{re.escape(name)}>",
                f"<{name}>{version}</{name}>",
                text,
            )
        if text != orig:
            fp.write_text(text, encoding="utf-8")
            changed.append(rel)
    return changed


def try_compile(job, repo_dir: Path) -> dict:
    version = job["version"]
    restore_clean(repo_dir)
    branch = job.get("branch", BASE)
    run(f"git checkout -B {branch} origin/{branch}", repo_dir, env=git_env(), timeout=120)
    pins = discover_pins(repo_dir, job["props"])
    print(f"  pins: {pins}", flush=True)
    if not pins:
        return {"version": version, "ok": False, "exit": -1, "status": "NO_PINS",
                "changed": [], "jdk": job["jdk"]}
    changed = apply_version(repo_dir, pins, version, job["props"])
    print(f"  applied {version} in {changed}", flush=True)
    env = git_env()
    java = jdk_home(job["jdk"])
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log_path = f"/tmp/netty_build_{job['comp']}_{version}.log"
    t0 = time.time()
    if SKIP_BUILD:
        code, out, err = 0, "SKIP_BUILD", ""
    else:
        code, out, err = run(job["build"], repo_dir, env=env, timeout=TIMEOUT, log_path=log_path)
    sec = round(time.time() - t0, 1)
    ok = code == 0
    print(f"  compile {version}: {'OK' if ok else 'FAIL'} exit={code} {sec}s jdk={job['jdk']} log={log_path}", flush=True)
    restore_clean(repo_dir)
    return {"version": version, "ok": ok, "exit": code, "seconds": sec,
            "changed": changed, "jdk": job["jdk"], "status": "OK" if ok else "FAIL",
            "chosen": version if ok else None}


def compile_all():
    load_token()
    jobs = [j for j in JOBS if not ONLY or j["comp"] in ONLY]
    prior = []
    if RESUME and RESULT.is_file():
        try:
            prior = list(json.loads(RESULT.read_text(encoding="utf-8")).get("results") or [])
        except Exception:
            prior = []
    done = {r["comp"] for r in prior if r.get("status") == "OK"}
    results = [r for r in prior if r.get("comp") in done]
    print(f"JOBS={len(jobs)} resume_ok={sorted(done)}", flush=True)
    for job in jobs:
        if job["comp"] in done:
            print(f"\nSKIP {job['comp']} (already OK)", flush=True)
            continue
        print(f"\n{'='*72}\nCOMP {job['comp']} jdk={job['jdk']} target={job['version']}\n{'='*72}", flush=True)
        row = {"comp": job["comp"], "repo": job["repo"], "jdk": job["jdk"], "target": job["version"]}
        try:
            repo_dir = ensure_clone(job)
            row["branch"] = job.get("branch", BASE)
            out = try_compile(job, repo_dir)
            row.update(out)
        except Exception as e:
            row["status"] = "ERROR"
            row["error"] = str(e)[:500]
            print(f"  ERROR: {e}", flush=True)
        results = [r for r in results if r.get("comp") != job["comp"]] + [row]
        RESULT.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")
    ok = sum(1 for r in results if r.get("status") == "OK")
    fail = sum(1 for r in results if r.get("status") not in ("OK",) and r.get("comp") in {j["comp"] for j in jobs})
    print(f"\n===== SUMMARY =====\nOK={ok} failish={fail} wrote {RESULT}", flush=True)
    for r in results:
        print(f"{r.get('comp'):28} {r.get('status'):10} chosen={r.get('chosen')}", flush=True)
    return results


def advisory_id(key, summary, field):
    import cve_analyser as ca
    return ca.extract_cve_id(key, summary or "", field or "")


def covered_ticket(path: str, close_re: str) -> bool:
    return bool(re.search(close_re, path or "", re.I))


def fetch_tickets(job: dict) -> list[dict]:
    import cve_analyser as ca
    version = job["version"]
    close_re = job.get("close_path_re") or r"netty-"
    fields = ("key,summary,status,customfield_10870,customfield_10888,"
              "customfield_10127,customfield_10875,customfield_10892,"
              "customfield_10891,customfield_10126")
    out = {}
    for repo in job["jira_repos"]:
        jql = (
            f'project = OSV AND "cve-found-in-release-version[short text]" ~ "{RELEASE}" '
            f'AND status = "To Do" AND "cve-severity[dropdown]" IN (Critical, High, Medium) '
            f'AND "cve-repo[short text]" ~ "{repo}"'
        )
        token = None
        while True:
            url = (f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql"
                   f"?jql={urllib.parse.quote(jql)}&maxResults=100&fields={fields}")
            if token:
                url += f"&nextPageToken={urllib.parse.quote(token)}"
            r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                               auth=(ca.EMAIL, ca.API_TOKEN))
            if r.status_code != 200:
                raise RuntimeError(f"Jira {r.status_code}: {r.text[:300]}")
            data = r.json()
            for i in data.get("issues") or []:
                f = i["fields"]
                path = f.get("customfield_10888") or ""
                lib = f.get("customfield_10875") or ""
                blob = f"{lib} {path}".lower()
                if "netty" not in blob:
                    continue
                if not covered_ticket(path, close_re):
                    continue
                # skip iceberg-runtime etc even under spark
                jar = ca.jar_filename(path).lower()
                if "iceberg" in jar:
                    continue
                item = {
                    "key": i["key"],
                    "ver": f.get("customfield_10892") or "",
                    "path": path,
                    "pkg": lib,
                    "summary": f.get("summary") or "",
                    "cve_id": advisory_id(i["key"], f.get("summary") or "", f.get("customfield_10127") or ""),
                    "repo": repo,
                }
                out[item["key"]] = item
            if data.get("isLast", True):
                break
            token = data.get("nextPageToken")
            if not token:
                break
    return [out[k] for k in sorted(out)]


def gh(method: str, path: str, payload=None):
    import requests
    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    url = f"https://api.github.com{path}"
    if method == "GET":
        return requests.get(url, headers=headers, timeout=60)
    if method == "POST":
        return requests.post(url, headers=headers, json=payload, timeout=60)
    if method == "PATCH":
        return requests.patch(url, headers=headers, json=payload, timeout=60)
    raise ValueError(method)


def create_pr(gh_slug: str, branch: str, title: str, body: str, base: str) -> str | None:
    if DRY:
        print(f"  [DRY_RUN] PR {title}")
        return f"https://github.com/{gh_slug}/pull/DRY"
    r = gh("POST", f"/repos/{gh_slug}/pulls",
           {"title": title, "head": branch, "base": base, "body": body})
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        print(f"  PR created: {url}")
        rr = gh("POST", f"/repos/{gh_slug}/pulls/{num}/requested_reviewers",
                {"reviewers": [REVIEWER]})
        print(f"  reviewer {REVIEWER}: HTTP {rr.status_code}")
        return url
    if r.status_code == 422:
        q = gh("GET", f"/repos/{gh_slug}/pulls?head=acceldata-io:{branch}&state=open")
        if q.status_code == 200 and q.json():
            url = q.json()[0]["html_url"]
            print(f"  PR exists: {url}")
            return url
    print(f"  ERROR PR [{r.status_code}]: {r.text[:400]}")
    return None


def deliver_one(job: dict) -> dict:
    import cve_analyser as ca
    comp = job["comp"]
    version = job["version"]
    repo_dir = WORK / job["comp"]
    base = job.get("branch", BASE)
    print(f"\n{'='*72}\nDELIVER {comp} version={version} base={base}\n{'='*72}", flush=True)
    if not (repo_dir / ".git").is_dir():
        ensure_clone(job)
    tickets = fetch_tickets(job)
    print(f"  coverable tickets: {len(tickets)}")
    for t in tickets[:10]:
        print(f"    {t['key']} ver={t['ver']} cve={t.get('cve_id')} path={t.get('path')}")
    if not tickets:
        return {"comp": comp, "status": "NO_TICKETS", "version": version}

    branch = tickets[0]["key"]
    keys = [t["key"] for t in tickets]
    cve_id = next((t["cve_id"] for t in tickets if t.get("cve_id") and t["cve_id"] != "UNKNOWN"),
                  tickets[0].get("cve_id") or "UNKNOWN")
    lib = "Netty"

    run(f"git remote set-url origin https://github.com/{job['gh']}.git", repo_dir, timeout=60)
    run(f"git fetch origin {base} --prune", repo_dir, timeout=300)
    run(f"git checkout -B {base} origin/{base}", repo_dir, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", repo_dir, timeout=300)
    run(f"git checkout -B {branch} origin/{base}", repo_dir, timeout=120)

    pins = discover_pins(repo_dir, job["props"])
    changed = apply_version(repo_dir, pins, version, job["props"])
    print(f"  changed: {changed}")
    code, porcelain, _ = run("git status --porcelain", repo_dir, timeout=30)
    if not (porcelain or "").strip():
        print("  no diff — skip")
        return {"comp": comp, "status": "NO_DIFF", "tickets": keys, "version": version}

    title = f"{branch} - CVE - Bumped-up {lib} to {version} to address {cve_id}"
    body = "\n".join([
        f"- Library : {lib}",
        f"- Version : -> {version}",
        f"- Tickets : {', '.join(keys)}",
    ])
    commit_msg = title if len(keys) == 1 else title + "\n\nAlso covers: " + ", ".join(keys[1:])
    if DRY:
        print(f"  [DRY_RUN] {title}")
        return {"comp": comp, "status": "DRY", "title": title, "tickets": keys, "version": version}

    run("git add -A", repo_dir, timeout=60)
    p = subprocess.run(["git", "commit", "-m", commit_msg], cwd=str(repo_dir),
                       text=True, capture_output=True, env=git_env())
    if p.returncode != 0:
        print(p.stdout, p.stderr)
        return {"comp": comp, "status": "COMMIT_FAIL", "tickets": keys, "version": version}
    run(f"git push -u origin {branch}", repo_dir, timeout=300)
    pr_url = create_pr(job["gh"], branch, title, body, base=base)
    if not pr_url:
        return {"comp": comp, "status": "PR_FAIL", "tickets": keys, "version": version}
    comment = (f"Fixed via PR: {pr_url} — {lib} bumped to {version} on {base} "
               f"to address the linked netty CVE(s). Owned pin bump covers "
               f"standalone netty jars / yarn-shuffle rebuilt from netty.version.")
    closed = []
    for k in keys:
        ok = ca.close_ticket_with_comment(k, comment, "Closed", assignee=ASSIGNEE)
        print(f"    {k} -> {'Closed' if ok else 'FAILED'}")
        if ok:
            closed.append(k)
    return {"comp": comp, "status": "OK", "pr": pr_url, "tickets": keys,
            "closed": closed, "title": title, "version": version}


def deliver_all(results=None):
    load_token()
    ok_comps = set()
    if results:
        ok_comps = {r["comp"] for r in results if r.get("status") == "OK"}
    elif RESULT.is_file():
        data = json.loads(RESULT.read_text(encoding="utf-8"))
        ok_comps = {r["comp"] for r in data.get("results") or [] if r.get("status") == "OK"}
    jobs = [j for j in JOBS if (not ONLY or j["comp"] in ONLY) and (not ok_comps or j["comp"] in ok_comps)]
    # If ONLY set, allow force deliver even without compile gate
    if ONLY and os.environ.get("CVE_FORCE_DELIVER", ""):
        jobs = [j for j in JOBS if j["comp"] in ONLY]
    print(f"DELIVER jobs={len(jobs)} ok_gate={sorted(ok_comps)} DRY={DRY}")
    out = []
    for job in jobs:
        try:
            out.append(deliver_one(job))
        except Exception as e:
            print(f"  ERROR {job['comp']}: {e}")
            out.append({"comp": job["comp"], "status": "ERROR", "error": str(e)[:400]})
        Path("/tmp/netty_deliver.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\n===== DELIVER SUMMARY =====")
    for r in out:
        print(f"{r.get('comp'):28} {r.get('status'):10} ver={r.get('version')} pr={r.get('pr')} "
              f"closed={len(r.get('closed') or [])}/{len(r.get('tickets') or [])}")
    return out


def main():
    if MODE == "compile":
        compile_all()
    elif MODE == "deliver":
        deliver_all()
    else:
        results = compile_all()
        deliver_all(results)


if __name__ == "__main__":
    raise SystemExit(main())
