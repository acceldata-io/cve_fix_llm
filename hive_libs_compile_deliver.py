#!/usr/bin/env python3
"""Hive multi-lib CVE bump: compile-gate then PR + close Jira.

Policy: try each bump independently from clean nightly/ODP-3.3.6.5.
Only deliver (PR + close) libs whose compile succeeds. Failures leave Jiras alone.

  CVE_MODE=compile|deliver|both
  CVE_ONLY_JOBS=commons-lang3,spring-5.3.41,...
  CVE_DRY_RUN=1
  CVE_RESUME=1
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

WORK = Path("/root/3.3.6.5")
BASE = "nightly/ODP-3.3.6.5"
RESULT = Path("/tmp/hive_libs_compile_matrix.json")
REVIEWER = "basapuram-kumar"
ASSIGNEE = "senthil.kumar"
RELEASE = "3.3.6.4"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
ONLY = [x.strip() for x in os.environ.get("CVE_ONLY_JOBS", "").split(",") if x.strip()]
RESUME = os.environ.get("CVE_RESUME", "1") == "1"
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
MODE = os.environ.get("CVE_MODE", "compile")
TOKEN = ""

GH = "acceldata-io/hive"
COMP = "hive"
REPO = "hive"
JDK = 11
JIRA_REPOS = ["sehajsandhu/hive"]

# Shared Hive smoke build (drop slow/broken modules for compile only)
HIVE_BUILD = (
    "mvn -DskipTests -Dtar -Pdist -Dmaven.javadoc.skip=true -Dallow.root.build "
    "-Denforcer.skip=true -Drat.skip=true install"
)
DROP = ["kudu-handler", "packaging"]

# Focused builds where a full install is unnecessary
FOCUS = {
    "ql": "mvn -DskipTests -Dmaven.javadoc.skip=true -Dallow.root.build -Denforcer.skip=true "
          "-Drat.skip=true package -pl ql -am",
    "druid": "mvn -DskipTests -Dmaven.javadoc.skip=true -Dallow.root.build -Denforcer.skip=true "
             "-Drat.skip=true package -pl druid-handler -am",
    "ms": "mvn -DskipTests -Dmaven.javadoc.skip=true -Dallow.root.build -Denforcer.skip=true "
          "-Drat.skip=true package -pl standalone-metastore/metastore-common,"
          "standalone-metastore/metastore-server -am",
    "jdbc": "mvn -DskipTests -Dmaven.javadoc.skip=true -Dallow.root.build -Denforcer.skip=true "
            "-Drat.skip=true package -pl jdbc,standalone-metastore/metastore-common,"
            "standalone-metastore/metastore-server,common -am",
}

JOBS = [
    {
        "id": "commons-lang3",
        "lib": "commons-lang3",
        "version": "3.18.0",
        "props": ["commons-lang3.version"],
        "tickets": ["OSV-21150"],
        "build": FOCUS["jdbc"],
        "cve": "CVE-2025-48924",
    },
    {
        "id": "spring-5.3.41",
        "lib": "spring-core",
        "version": "5.3.41",
        "props": ["spring.version"],
        "tickets": ["OSV-21247"],
        "build": FOCUS["ms"],
        "cve": "CVE-2024-38820",
    },
    {
        "id": "grpc",
        "lib": "grpc-netty-shaded",
        "version": "1.75.0",
        "props": ["io.grpc.version"],
        "tickets": ["OSV-21258"],
        "build": FOCUS["ms"],
        "cve": "CVE-2025-55163",
    },
    {
        "id": "async-http-client",
        "lib": "async-http-client",
        "version": "3.0.10",
        "props": [],
        "inject_dm": [
            {"groupId": "org.asynchttpclient", "artifactId": "async-http-client", "version": "3.0.10"},
        ],
        "inject_props": {"async-http-client.version": "3.0.10"},
        "tickets": ["OSV-21252", "OSV-21253"],
        "build": FOCUS["druid"],
        "cve": "CVE-2026-40490",
    },
    {
        "id": "commons-configuration2",
        "lib": "commons-configuration2",
        "version": "2.15.0",
        "props": [],
        "inject_dm": [
            {
                "groupId": "org.apache.commons",
                "artifactId": "commons-configuration2",
                "version": "2.15.0",
            },
        ],
        "inject_props": {"commons-configuration2.version": "2.15.0"},
        "tickets": ["OSV-21185"],
        "build": FOCUS["druid"],
        "cve": "CVE-2026-45205",
    },
    {
        "id": "aircompressor",
        "lib": "aircompressor",
        "version": "2.0.3",
        "props": [],
        "inject_dm": [
            {"groupId": "io.airlift", "artifactId": "aircompressor", "version": "2.0.3"},
        ],
        "inject_props": {"aircompressor.version": "2.0.3"},
        "tickets": ["OSV-21268"],
        "build": FOCUS["ql"],
        "cve": "CVE-2025-67721",
    },
    {
        "id": "pac4j",
        "lib": "pac4j-core",
        "version": "5.7.10",
        "props": ["pac4j-core.version"],
        "tickets": ["OSV-21260"],
        "build": FOCUS["ms"],
        "cve": "CVE-2026-40458",
    },
    {
        "id": "spring-6.2.11",
        "lib": "spring-core",
        "version": "6.2.11",
        "props": ["spring.version"],
        "tickets": ["OSV-21246"],
        "build": FOCUS["ms"],
        "cve": "CVE-2025-41249",
    },
    # Already at/above target on nightly — recorded for reporting only (no bump attempt).
    {
        "id": "avro-already",
        "lib": "avro",
        "version": "1.11.4",
        "already": "1.12.0 (iceberg.avro.version / avro.version on nightly)",
        "tickets": ["OSV-21183"],
        "cve": "CVE-2024-47561",
    },
    {
        "id": "parquet-avro-already",
        "lib": "parquet-avro",
        "version": "1.15.2",
        "already": "1.15.2 (parquet.version on nightly; resolved in iceberg-handler)",
        "tickets": ["OSV-21162", "OSV-21163"],
        "cve": "CVE-2025-30065",
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
    for c in [f"/usr/lib/jvm/java-{major}-openjdk", f"/usr/lib/jvm/java-{major}"]:
        if Path(c).exists():
            return c
    for p in Path("/usr/lib/jvm").glob(f"java-{major}*"):
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


def ensure_hive() -> Path:
    path = WORK / COMP
    WORK.mkdir(parents=True, exist_ok=True)
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
        raise RuntimeError(f"clone hive failed: {err[-800:]}")
    return path


def restore_clean(repo_dir: Path):
    run("git reset --hard HEAD && git clean -fdx", repo_dir, env=git_env(), timeout=300)
    run(f"git checkout -B {BASE} origin/{BASE}", repo_dir, env=git_env(), timeout=120)


def hive_expand_odp_version(repo_dir: Path):
    root = repo_dir / "pom.xml"
    text = root.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"<odp\.release\.version>([^<]+)</odp\.release\.version>", text)
    if not m:
        return
    ver = m.group(1).strip()
    for pom in repo_dir.rglob("pom.xml"):
        if "/target/" in str(pom):
            continue
        t = pom.read_text(encoding="utf-8", errors="replace")
        if "${odp.release.version}" not in t:
            continue
        pom.write_text(t.replace("${odp.release.version}", ver), encoding="utf-8")


def drop_pom_modules(repo_dir: Path, modules: list[str]):
    pom = repo_dir / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text
    for mod in modules:
        text = re.sub(
            rf"<module>\s*{re.escape(mod)}\s*</module>",
            f"<!-- CVE smoke skipped: {mod} -->",
            text,
        )
    if text != orig:
        pom.write_text(text, encoding="utf-8")


def apply_props(repo_dir: Path, props: list[str], version: str) -> list[str]:
    changed = []
    for pom in repo_dir.rglob("pom.xml"):
        if "/target/" in str(pom):
            continue
        text = pom.read_text(encoding="utf-8", errors="replace")
        orig = text
        for prop in props:
            text = re.sub(
                rf"<{re.escape(prop)}>[^<]+</{re.escape(prop)}>",
                f"<{prop}>{version}</{prop}>",
                text,
            )
        if text != orig:
            pom.write_text(text, encoding="utf-8")
            changed.append(str(pom.relative_to(repo_dir)))
    return changed


def inject_properties(repo_dir: Path, props: dict[str, str]) -> list[str]:
    pom = repo_dir / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text
    for name, ver in props.items():
        if re.search(rf"<{re.escape(name)}>[^<]+</{re.escape(name)}>", text):
            text = re.sub(
                rf"<{re.escape(name)}>[^<]+</{re.escape(name)}>",
                f"<{name}>{ver}</{name}>",
                text,
            )
        else:
            # insert before </properties>
            text = text.replace(
                "</properties>",
                f"    <{name}>{ver}</{name}>\n  </properties>",
                1,
            )
    if text != orig:
        pom.write_text(text, encoding="utf-8")
        return ["pom.xml"]
    return []


def inject_dm(repo_dir: Path, deps: list[dict]) -> list[str]:
    pom = repo_dir / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text
    for d in deps:
        gid, aid, ver = d["groupId"], d["artifactId"], d["version"]
        # replace existing DM entry version if present
        pat = (
            rf"(<dependency>\s*<groupId>{re.escape(gid)}</groupId>\s*"
            rf"<artifactId>{re.escape(aid)}</artifactId>\s*)"
            rf"<version>[^<]+</version>"
        )
        if re.search(pat, text, re.S):
            text = re.sub(pat, rf"\1<version>{ver}</version>", text, count=1, flags=re.S)
            continue
        # also handle version with property already set via inject
        block = (
            f"\n      <dependency>\n"
            f"        <groupId>{gid}</groupId>\n"
            f"        <artifactId>{aid}</artifactId>\n"
            f"        <version>{ver}</version>\n"
            f"      </dependency>"
        )
        # Insert inside <dependencyManagement><dependencies>...</dependencies>
        if not re.search(r"<dependencyManagement>.*</dependencyManagement>", text, re.S):
            raise RuntimeError("no dependencyManagement in root pom")
        text2, n = re.subn(
            r"(</dependencies>\s*</dependencyManagement>)",
            block + r"\n    \1",
            text,
            count=1,
            flags=re.S,
        )
        if n != 1:
            raise RuntimeError("failed to insert into dependencyManagement/dependencies")
        text = text2
    if text != orig:
        pom.write_text(text, encoding="utf-8")
        return ["pom.xml"]
    return []


def apply_job(repo_dir: Path, job: dict) -> list[str]:
    changed: list[str] = []
    if job.get("props"):
        changed += apply_props(repo_dir, job["props"], job["version"])
    if job.get("inject_props"):
        changed += inject_properties(repo_dir, job["inject_props"])
    if job.get("inject_dm"):
        # Prefer property references when inject_props present
        deps = []
        for d in job["inject_dm"]:
            dd = dict(d)
            prop_key = None
            for k in (job.get("inject_props") or {}):
                if d["artifactId"].replace("-", ".") in k or d["artifactId"] in k:
                    prop_key = k
                    break
            if prop_key:
                dd["version"] = f"${{{prop_key}}}"
            deps.append(dd)
        # If version is property ref, keep literal version in DM for reliability
        deps = job["inject_dm"]
        changed += inject_dm(repo_dir, deps)
    # uniq
    out, seen = [], set()
    for c in changed:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def try_compile(job: dict) -> dict:
    row = {
        "id": job["id"], "lib": job["lib"], "version": job["version"],
        "tickets": job["tickets"], "status": "PENDING",
    }
    if job.get("already"):
        row["status"] = "ALREADY"
        row["note"] = job["already"]
        print(f"  ALREADY at {job['already']} — skip bump (leave Jira)", flush=True)
        return row

    repo_dir = ensure_hive()
    restore_clean(repo_dir)
    hive_expand_odp_version(repo_dir)
    drop_pom_modules(repo_dir, DROP)
    changed = apply_job(repo_dir, job)
    print(f"  applied {job['lib']}->{job['version']} in {changed}", flush=True)
    if not changed:
        row["status"] = "NO_PIN"
        return row
    row["changed"] = changed

    java = jdk_home(JDK)
    env = git_env()
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log = f"/tmp/hive_build_{job['id']}_{job['version']}.log"
    code, out, err = run(job["build"], repo_dir, env=env, timeout=TIMEOUT, log_path=log)
    # also append last errors to stdout summary
    ok = code == 0 and "BUILD SUCCESS" in (out + err)
    if not ok and code == 0:
        # some mvn versions put SUCCESS only in out
        ok = "BUILD SUCCESS" in Path(log).read_text(errors="replace")[-4000:]
    row["exit"] = code
    row["log"] = log
    row["status"] = "OK" if ok else "FAIL"
    print(f"  compile {job['lib']} {job['version']}: {row['status']} exit={code} log={log}", flush=True)
    if not ok:
        # print last failure lines
        try:
            tail = Path(log).read_text(errors="replace").splitlines()[-30:]
            for ln in tail:
                if "ERROR" in ln or "FAILURE" in ln or "BUILD" in ln:
                    print("   ", ln[:200], flush=True)
        except Exception:
            pass
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
    print(f"JOBS={len(jobs)} resume={sorted(k for k,v in prev.items() if v.get('status')=='OK')}")
    for job in jobs:
        print(f"\n{'='*72}\nJOB {job['id']} target={job['version']}\n{'='*72}", flush=True)
        if RESUME and prev.get(job["id"], {}).get("status") in ("OK", "ALREADY"):
            print(f"  resume skip {job['id']} status={prev[job['id']]['status']}")
            results.append(prev[job["id"]])
            continue
        try:
            row = try_compile(job)
        except Exception as e:
            row = {"id": job["id"], "lib": job["lib"], "version": job["version"],
                   "tickets": job["tickets"], "status": "ERROR", "error": str(e)[:500]}
            print(f"  ERROR {e}", flush=True)
        results.append(row)
        RESULT.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")
    print("\n===== COMPILE SUMMARY =====")
    for r in results:
        print(f"{r.get('id'):28} {r.get('status'):10} ver={r.get('version')} tickets={r.get('tickets')}")
    print(f"wrote {RESULT}")
    return results


def gh(method: str, path: str, payload=None):
    import requests
    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    url = f"https://api.github.com{path}"
    if method == "GET":
        return requests.get(url, headers=headers, timeout=60)
    if method == "POST":
        return requests.post(url, headers=headers, json=payload, timeout=60)
    raise ValueError(method)


def create_pr(branch: str, title: str, body: str) -> str | None:
    if DRY:
        print(f"  [DRY_RUN] PR {title}")
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
    jid = job["id"]
    lib = job["lib"]
    version = job["version"]
    keys = [k for k in job["tickets"] if ticket_still_todo(k)]
    print(f"\n{'='*72}\nDELIVER {jid} {lib}->{version}\n{'='*72}", flush=True)
    if not keys:
        return {"id": jid, "status": "NO_TODO", "tickets": job["tickets"]}

    repo_dir = ensure_hive()
    restore_clean(repo_dir)
    branch = keys[0]
    run(f"git checkout -B {branch} origin/{BASE}", repo_dir, env=git_env(), timeout=120)
    changed = apply_job(repo_dir, job)
    print(f"  changed: {changed}")
    code, porcelain, _ = run("git status --porcelain", repo_dir, timeout=30)
    if not (porcelain or "").strip():
        return {"id": jid, "status": "NO_DIFF", "tickets": keys}

    cve_id = job.get("cve") or "UNKNOWN"
    title = f"{branch} - CVE - Bumped-up {lib} to {version} to address {cve_id}"
    body = "\n".join([
        f"- Library : {lib}",
        f"- Version : -> {version}",
        f"- Tickets : {', '.join(keys)}",
    ])
    commit_msg = title if len(keys) == 1 else title + "\n\nAlso covers: " + ", ".join(keys[1:])
    if DRY:
        print(f"  [DRY_RUN] {title}")
        return {"id": jid, "status": "DRY", "title": title, "tickets": keys}

    run("git add -A", repo_dir, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", commit_msg], cwd=str(repo_dir),
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
            "title": title, "version": version, "lib": lib}


def deliver_all(results=None):
    load_token()
    if results is None and RESULT.is_file():
        results = json.loads(RESULT.read_text()).get("results") or []
    ok_ids = {r["id"] for r in (results or []) if r.get("status") == "OK"}
    jobs = [j for j in JOBS if j["id"] in ok_ids and (not ONLY or j["id"] in ONLY)]
    print(f"DELIVER jobs={len(jobs)} ok_gate={sorted(ok_ids)} DRY={DRY}")
    out = []
    for job in jobs:
        try:
            out.append(deliver_one(job))
        except Exception as e:
            print(f"  ERROR {job['id']}: {e}")
            out.append({"id": job["id"], "status": "ERROR", "error": str(e)[:400]})
        Path("/tmp/hive_libs_deliver.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\n===== DELIVER SUMMARY =====")
    for r in out:
        print(f"{r.get('id'):28} {r.get('status'):10} pr={r.get('pr')} "
              f"closed={len(r.get('closed') or [])}/{len(r.get('tickets') or [])}")
    return out


def main():
    load_token()
    results = None
    if MODE in ("compile", "both"):
        results = compile_all()
    if MODE in ("deliver", "both"):
        deliver_all(results)


if __name__ == "__main__":
    main()
