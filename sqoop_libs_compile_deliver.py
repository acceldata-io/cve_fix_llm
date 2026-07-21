#!/usr/bin/env python3
"""Sqoop CVE bumps (Gradle) + Exception for shaded/jetty.

Medium owned:
  jackson* -> 2.18.6 (OSV-23405)
  commons-lang3 -> 3.18.0 (OSV-23399)

Exception:
  parquet-jackson shaded jackson-core (OSV-23403)
  commons-io inside velocity-engine-core (OSV-23409)
  jetty 9.4 LOW no public same-major fix (OSV-23407, OSV-23402)

  CVE_MODE=compile|deliver|both|exceptions
  CVE_ONLY_JOBS=jackson,commons-lang3
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

WORK = Path("/root/3.3.6.5")
BASE = "nightly/ODP-3.3.6.5"
RESULT = Path("/tmp/sqoop_libs_compile_matrix.json")
REVIEWER = "basapuram-kumar"
ASSIGNEE = "senthil.kumar"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
ONLY = [x.strip() for x in os.environ.get("CVE_ONLY_JOBS", "").split(",") if x.strip()]
RESUME = os.environ.get("CVE_RESUME", "1") == "1"
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "5400"))
MODE = os.environ.get("CVE_MODE", "both")
TOKEN = ""

GH = "acceldata-io/sqoop"
COMP = "sqoop"
# Hive 4.0.1.3.3.6.5-SNAPSHOT jars (e.g. hive-storage-api) are Java 11 bytecode;
# JDK 8 javac cannot read them. Compile with JDK 11 while sourceCompatibility stays 1.8.
JDK = 11
GRADLE_PROPS = (
    "-PsnapMavenUrl=https://repo1.acceldata.dev/repository/odp-staging-snapshot/ "
    "-PmavenUrl=https://repo1.acceldata.dev/repository/odp-staging-release/ "
    "-PmavenUsername=x -PmavenPassword=x"
)
BUILD = f"./gradlew jar -x test --no-daemon {GRADLE_PROPS}"

EXCEPTIONS = [
    {
        "key": "OSV-23403",
        "details": (
            "Sqoop jackson-core finding is inside parquet-jackson-*.jar (Parquet "
            "shaded Jackson), not the standalone jackson-core jar managed by "
            "Sqoop's jacksonVersion force. Local Jackson bump cannot rewrite "
            "parquet-jackson relocated classes. Fix requires upgrading/rebuilding "
            "parquet. Exception Request (Deferred)."
        ),
    },
    {
        "key": "OSV-23409",
        "details": (
            "Sqoop commons-io CVE path is velocity-engine-core-*.jar (shaded/"
            "bundled commons-io 2.8.0). Sqoop already pins commons-io 2.12.0 for "
            "direct deps; component bump cannot replace classes inside Velocity. "
            "Fix requires upgrading velocity-engine-core. Exception Request "
            "(Deferred)."
        ),
    },
    {
        "key": "OSV-23407",
        "details": (
            "Sqoop jetty-http on 9.4.57; CVE-2025-11143 needs Jetty >=9.4.59 which "
            "is not published as a public Maven Central 9.4.x release (Jetty 9 EOL; "
            "supported OSS fixes are Jetty 12.x). No safe same-major bump. "
            "Exception Request (Deferred)."
        ),
    },
    {
        "key": "OSV-23402",
        "details": (
            "Sqoop jetty-io on 9.4.57; CVE-2026-5795 needs Jetty >=9.4.61 which is "
            "not available as a public Maven Central 9.4.x release (Jetty 9 EOL; "
            "supported OSS fixes are Jetty 12.x). No safe same-major bump. "
            "Exception Request (Deferred)."
        ),
    },
]

JOBS = [
    {
        "id": "jackson",
        "lib": "Jackson",
        "version": "2.18.6",
        "tickets": ["OSV-23405"],
        "cve": "GHSA-72hv-8253-57qq",
        "apply": "jackson",
    },
    {
        "id": "commons-lang3",
        "lib": "commons-lang3",
        "version": "3.18.0",
        "tickets": ["OSV-23399"],
        "cve": "CVE-2025-48924",
        "apply": "lang3",
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
        "#!/bin/sh\ncase \"$1\" in\n*Username*) echo x-access-token ;;\n"
        "*Password*) echo \"$GITHUB_TOKEN\" ;;\nesac\n",
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
    for c in [f"/usr/lib/jvm/java-1.{major}.0-openjdk", f"/usr/lib/jvm/java-{major}-openjdk",
              f"/usr/lib/jvm/java-{major}"]:
        if Path(c).exists():
            return c
    for p in Path("/usr/lib/jvm").glob(f"java*{major}*"):
        if p.is_dir():
            return str(p)
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


def ensure_repo() -> Path:
    path = WORK / COMP
    env = git_env()
    url = f"https://github.com/{GH}.git"
    if (path / ".git").is_dir():
        run(f"git remote set-url origin {url}", path, env=env, timeout=60)
        run(f"git fetch origin {BASE} --prune", path, env=env, timeout=300)
        run(f"git checkout -B {BASE} origin/{BASE}", path, env=env, timeout=120)
        return path
    code, _, err = run(
        f"git clone --branch {BASE} --single-branch {url} {COMP}",
        WORK, env=env, timeout=900,
    )
    if code != 0:
        raise RuntimeError(err[-800:])
    return path


def restore_clean(repo_dir: Path):
    run("git reset --hard HEAD && git clean -fdx", repo_dir, env=git_env(), timeout=300)
    run(f"git checkout -B {BASE} origin/{BASE}", repo_dir, env=git_env(), timeout=120)


def _set_prop_file(path: Path, key: str, value: str) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    pat = rf"(?m)^{re.escape(key)}=.*$"
    if re.search(pat, text):
        text2 = re.sub(pat, f"{key}={value}", text)
    else:
        text2 = text.rstrip() + f"\n{key}={value}\n"
    if text2 != text:
        path.write_text(text2, encoding="utf-8")
        return True
    return False


def apply_jackson(repo_dir: Path, version: str) -> list[str]:
    changed = []
    if _set_prop_file(repo_dir / "gradle.properties", "jacksonVersion", version):
        changed.append("gradle.properties")
    if _set_prop_file(repo_dir / "ivy" / "libraries.properties", "jackson-databind.version", version):
        changed.append("ivy/libraries.properties")
    return changed


def apply_lang3(repo_dir: Path, version: str) -> list[str]:
    changed = []
    if _set_prop_file(repo_dir / "gradle.properties", "commonslang3Version", version):
        changed.append("gradle.properties")
    if _set_prop_file(repo_dir / "ivy" / "libraries.properties", "commons-lang3.version", version):
        if "ivy/libraries.properties" not in changed:
            changed.append("ivy/libraries.properties")
    # Ensure Gradle resolutionStrategy forces lang3 (may be missing)
    bg = repo_dir / "build.gradle"
    text = bg.read_text(encoding="utf-8", errors="replace")
    force_line = (
        "        force group: 'org.apache.commons', name: 'commons-lang3', "
        "version: commonslang3Version"
    )
    if "commons-lang3" not in text or "force group: 'org.apache.commons', name: 'commons-lang3'" not in text:
        # insert after jackson-annotations force
        text2 = text.replace(
            "        force group: 'com.fasterxml.jackson.core', name: 'jackson-annotations', version: jacksonVersion\n",
            "        force group: 'com.fasterxml.jackson.core', name: 'jackson-annotations', version: jacksonVersion\n"
            + force_line + "\n",
            1,
        )
        if text2 == text:
            # fallback: after snakeyaml force
            text2 = text.replace(
                "        force group: 'org.yaml', name: 'snakeyaml', version: snakeyamlVersion\n",
                "        force group: 'org.yaml', name: 'snakeyaml', version: snakeyamlVersion\n"
                + force_line + "\n",
                1,
            )
        if text2 != text:
            bg.write_text(text2, encoding="utf-8")
            changed.append("build.gradle")
    return changed


def apply_job(repo_dir: Path, job: dict) -> list[str]:
    if job["apply"] == "jackson":
        return apply_jackson(repo_dir, job["version"])
    if job["apply"] == "lang3":
        return apply_lang3(repo_dir, job["version"])
    raise ValueError(job["apply"])


def apply_exceptions():
    load_token()
    import cve_analyser as ca
    ca.DRY_RUN = DRY
    for item in EXCEPTIONS:
        key = item["key"]
        url = f"{ca.JIRA_BASE_URL}/rest/api/3/issue/{key}?fields=status"
        r = ca.SESSION.get(url, headers={"Accept": "application/json"}, auth=(ca.EMAIL, ca.API_TOKEN))
        st = ((r.json().get("fields") or {}).get("status") or {}).get("name") or "?"
        print(f"EXCEPTION {key} current={st}", flush=True)
        if st.lower() == "exception request":
            ca.assign_issue(key, ca.resolve_assignee(ASSIGNEE))
            continue
        if st.lower() == "closed":
            continue
        ok = ca.update_ticket_exception(key, item["details"], reason="Deferred", assignee=ASSIGNEE)
        try:
            ca.add_comment(key, f"Exception Request (Deferred): {item['details']}")
        except Exception as e:
            print(f"  comment warn: {e}")
        ca.assign_issue(key, ca.resolve_assignee(ASSIGNEE))
        print(f"  ok={ok}", flush=True)


def try_compile(job: dict) -> dict:
    row = {"id": job["id"], "lib": job["lib"], "version": job["version"],
           "tickets": job["tickets"], "status": "PENDING"}
    repo_dir = ensure_repo()
    restore_clean(repo_dir)
    changed = apply_job(repo_dir, job)
    print(f"  applied {changed}", flush=True)
    if not changed:
        row["status"] = "NO_PIN"
        return row
    row["changed"] = changed
    java = jdk_home(JDK)
    env = git_env()
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log = f"/tmp/sqoop_build_{job['id']}_{job['version']}.log"
    code, out, err = run(BUILD, repo_dir, env=env, timeout=TIMEOUT, log_path=log)
    text = Path(log).read_text(errors="replace") if Path(log).exists() else (out + err)
    ok = code == 0 and ("BUILD SUCCESSFUL" in text or "BUILD SUCCESS" in text)
    row["exit"] = code
    row["log"] = log
    row["status"] = "OK" if ok else "FAIL"
    print(f"  compile {job['lib']} {job['version']}: {row['status']} exit={code}", flush=True)
    if not ok:
        for ln in text.splitlines()[-30:]:
            if any(x in ln for x in ("FAILED", "FAILURE", "error:", "ERROR", "BUILD")):
                print("   ", ln[:200], flush=True)
    return row


def compile_all() -> list[dict]:
    load_token()
    prev = {}
    if RESUME and RESULT.is_file():
        try:
            prev = {r["id"]: r for r in json.loads(RESULT.read_text()).get("results", [])}
        except Exception:
            prev = {}
    jobs = [j for j in JOBS if not ONLY or j["id"] in ONLY]
    results = []
    for job in jobs:
        print(f"\n{'='*72}\nJOB {job['id']} -> {job['version']}\n{'='*72}", flush=True)
        if RESUME and prev.get(job["id"], {}).get("status") == "OK":
            results.append(prev[job["id"]])
            continue
        try:
            row = try_compile(job)
        except Exception as e:
            row = {"id": job["id"], "status": "ERROR", "error": str(e)[:400],
                   "tickets": job["tickets"], "lib": job["lib"], "version": job["version"]}
            print(f"  ERROR {e}", flush=True)
        results.append(row)
        RESULT.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")
    print("\n===== COMPILE SUMMARY =====")
    for r in results:
        print(f"{r.get('id'):20} {r.get('status'):10} ver={r.get('version')}")
    return results


def gh(method: str, path: str, payload=None):
    import requests
    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    url = f"https://api.github.com{path}"
    if method == "POST":
        return requests.post(url, headers=headers, json=payload, timeout=60)
    raise ValueError(method)


def create_pr(branch: str, title: str, body: str) -> str | None:
    if DRY:
        return f"https://github.com/{GH}/pull/DRY"
    r = gh("POST", f"/repos/{GH}/pulls",
           {"title": title, "head": branch, "base": BASE, "body": body})
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        print(f"  PR created: {url}")
        rr = gh("POST", f"/repos/{GH}/pulls/{num}/requested_reviewers",
                {"reviewers": [REVIEWER]})
        print(f"  reviewer {REVIEWER}: HTTP {rr.status_code}")
        return url
    print(f"  PR fail HTTP {r.status_code}: {r.text[:400]}")
    return None


def ticket_still_todo(key: str) -> bool:
    import cve_analyser as ca
    url = f"{ca.JIRA_BASE_URL}/rest/api/3/issue/{key}?fields=status"
    r = ca.SESSION.get(url, headers={"Accept": "application/json"}, auth=(ca.EMAIL, ca.API_TOKEN))
    if r.status_code != 200:
        return True
    return r.json()["fields"]["status"]["name"] == "To Do"


def deliver_one(job: dict) -> dict:
    import cve_analyser as ca
    jid, lib, version = job["id"], job["lib"], job["version"]
    keys = [k for k in job["tickets"] if ticket_still_todo(k)]
    print(f"\n{'='*72}\nDELIVER {jid} {lib}->{version}\n{'='*72}", flush=True)
    if not keys:
        return {"id": jid, "status": "NO_TODO", "tickets": job["tickets"]}
    repo_dir = ensure_repo()
    restore_clean(repo_dir)
    branch = keys[0]
    run(f"git checkout -B {branch} origin/{BASE}", repo_dir, env=git_env(), timeout=120)
    changed = apply_job(repo_dir, job)
    print(f"  changed: {changed}")
    _, porcelain, _ = run("git status --porcelain", repo_dir, timeout=30)
    if not (porcelain or "").strip():
        return {"id": jid, "status": "NO_DIFF", "tickets": keys}
    cve_id = job.get("cve") or "UNKNOWN"
    title = f"{branch} - CVE - Bumped-up {lib} to {version} to address {cve_id}"
    body = "\n".join([
        f"- Library : {lib}",
        f"- Version : -> {version}",
        f"- Tickets : {', '.join(keys)}",
    ])
    if DRY:
        return {"id": jid, "status": "DRY", "title": title, "tickets": keys}
    run("git add -A", repo_dir, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title], cwd=str(repo_dir),
        text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        print(p.stdout, p.stderr)
        return {"id": jid, "status": "COMMIT_FAIL", "tickets": keys}
    run(f"git push -u origin {branch}", repo_dir, timeout=300)
    pr_url = create_pr(branch, title, body)
    if not pr_url:
        return {"id": jid, "status": "PR_FAIL", "tickets": keys}
    comment = (
        f"Fixed via PR: {pr_url} — {lib} bumped to {version} on {BASE} "
        f"to address the linked {lib} CVE(s)."
    )
    closed = []
    for k in keys:
        ok = ca.close_ticket_with_comment(k, comment, "Closed", assignee=ASSIGNEE)
        print(f"    {k} -> {'Closed' if ok else 'FAILED'}")
        if ok:
            closed.append(k)
    return {"id": jid, "status": "OK", "pr": pr_url, "tickets": keys, "closed": closed,
            "version": version, "lib": lib}


def deliver_all(results=None):
    load_token()
    if results is None and RESULT.is_file():
        results = json.loads(RESULT.read_text()).get("results") or []
    ok_ids = {r["id"] for r in (results or []) if r.get("status") == "OK"}
    jobs = [j for j in JOBS if j["id"] in ok_ids and (not ONLY or j["id"] in ONLY)]
    print(f"DELIVER jobs={len(jobs)} ok_gate={sorted(ok_ids)}")
    out = []
    for job in jobs:
        try:
            out.append(deliver_one(job))
        except Exception as e:
            out.append({"id": job["id"], "status": "ERROR", "error": str(e)[:400]})
            print(f"  ERROR {job['id']}: {e}")
        Path("/tmp/sqoop_libs_deliver.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\n===== DELIVER SUMMARY =====")
    for r in out:
        print(f"{r.get('id'):20} {r.get('status'):10} pr={r.get('pr')} "
              f"closed={len(r.get('closed') or [])}/{len(r.get('tickets') or [])}")
    return out


def main():
    load_token()
    if MODE in ("exceptions", "both"):
        apply_exceptions()
    results = None
    if MODE in ("compile", "both"):
        results = compile_all()
    if MODE in ("deliver", "both"):
        deliver_all(results)


if __name__ == "__main__":
    main()
