#!/usr/bin/env python3
"""spark3_3_3_3: libthrift 0.16.0 + remove Tomcat pin → compile → PR → close Tomcat CVEs.

Matches spark 3.5.1 behavior: libthrift 0.16.0 dropped tomcat-embed; ODP pin
OSV-12192 (tomcat-embed 8.5.99) is removed so Tomcat leaves the dist entirely.

Status file: /tmp/spark3_333_thrift_status.json
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

WORK = Path("/root/3.3.6.5")
BASE = "nightly/ODP-3.3.3.3.3.6.5"
COMP = "spark3_3_3_3"
GH = "acceldata-io/spark3"
JDK = 11
REVIEWER = "basapuram-kumar"
ASSIGNEE = "senthil.kumar"
STATUS = Path("/tmp/spark3_333_thrift_status.json")
BRANCH = "OSV-23914"  # lead Tomcat ticket
LIBTHRIFT = "0.16.0"
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
MAX_COMPILE_ATTEMPTS = int(os.environ.get("CVE_COMPILE_ATTEMPTS", "2"))
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
TOKEN = ""

BUILD = (
    "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver "
    "-DskipTests -DskipSparkTests "
    "-Dmaven.javadoc.skip=true -Dmaven.scaladoc.skip=true -Dcyclonedx.skip=true"
)

TOMCAT_TICKETS = [
    # Medium+ previously Exception'd
    "OSV-23914", "OSV-23915", "OSV-23916", "OSV-23917", "OSV-23918",
    "OSV-23920", "OSV-23921", "OSV-23922", "OSV-23923", "OSV-23924",
    "OSV-23925",
    # LOW still To Do
    "OSV-23919", "OSV-20791",
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
    print(f"STATUS: {json.dumps(kwargs)}", flush=True)


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


def git_env() -> dict:
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    return env


def jdk_home() -> str:
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


def ensure_repo() -> Path:
    path = WORK / COMP
    env = git_env()
    url = f"https://github.com/{GH}.git"
    run(f"git remote set-url origin {url}", path, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", path, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", path, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", path, env=env, timeout=300)
    run(f"git checkout -B {BASE} origin/{BASE}", path, env=env, timeout=120)
    return path


def apply_patch(repo_dir: Path) -> list[str]:
    pom = repo_dir / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text

    # 1) bump libthrift
    text2, n = re.subn(
        r"(<libthrift\.version>)([^<]+)(</libthrift\.version>)",
        rf"\g<1>{LIBTHRIFT}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("libthrift.version property not found")
    text = text2

    # 2) remove tomcat-embed.version property + comment
    text = re.sub(
        r"\n\s*<!-- CVE-2024-24549: override transitive tomcat-embed-core from libthrift; 8\.5\.99\+ required -->\n"
        r"\s*<tomcat-embed\.version>8\.5\.99</tomcat-embed\.version>\n",
        "\n",
        text,
    )
    # fallback if comment text differs slightly
    text = re.sub(r"\n\s*<tomcat-embed\.version>[^<]+</tomcat-embed\.version>\n", "\n", text)

    # 3) remove DM tomcat-embed-core + tomcat-annotations-api block
    text = re.sub(
        r"\n\s*<!-- CVE-2024-24549: override transitive tomcat-embed-core from libthrift -->\n"
        r"\s*<dependency>\n"
        r"\s*<groupId>org\.apache\.tomcat\.embed</groupId>\n"
        r"\s*<artifactId>tomcat-embed-core</artifactId>\n"
        r"\s*<version>\$\{tomcat-embed\.version\}</version>\n"
        r"\s*</dependency>\n"
        r"\s*<dependency>\n"
        r"\s*<groupId>org\.apache\.tomcat</groupId>\n"
        r"\s*<artifactId>tomcat-annotations-api</artifactId>\n"
        r"\s*<version>\$\{tomcat-embed\.version\}</version>\n"
        r"\s*</dependency>\n",
        "\n",
        text,
    )
    # fallback: remove any remaining tomcat-embed DM deps with property version
    if "tomcat-embed-core" in text or "tomcat-embed.version" in text:
        # try looser removal of the two dependency blocks
        text = re.sub(
            r"\s*<dependency>\s*"
            r"<groupId>org\.apache\.tomcat\.embed</groupId>\s*"
            r"<artifactId>tomcat-embed-core</artifactId>\s*"
            r"<version>[^<]+</version>\s*"
            r"</dependency>\s*",
            "\n",
            text,
        )
        text = re.sub(
            r"\s*<dependency>\s*"
            r"<groupId>org\.apache\.tomcat</groupId>\s*"
            r"<artifactId>tomcat-annotations-api</artifactId>\s*"
            r"<version>\$\{tomcat-embed\.version\}</version>\s*"
            r"</dependency>\s*",
            "\n",
            text,
        )

    if "tomcat-embed.version" in text or "tomcat-embed-core" in text:
        raise RuntimeError("Tomcat pin still present after patch attempt")
    if f"<libthrift.version>{LIBTHRIFT}</libthrift.version>" not in text:
        raise RuntimeError("libthrift bump did not apply")

    if text == orig:
        raise RuntimeError("no changes applied")
    pom.write_text(text, encoding="utf-8")
    return ["pom.xml"]


def verify_no_tomcat(repo_dir: Path) -> dict:
    dist = repo_dir / "dist" / "jars"
    found = []
    if dist.is_dir():
        found = sorted(p.name for p in dist.glob("*tomcat*"))
    return {"dist_jars_dir": str(dist), "tomcat_jars": found, "clean": len(found) == 0}


def compile_once(repo_dir: Path, attempt: int) -> tuple[bool, str]:
    java = jdk_home()
    env = git_env()
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log = f"/tmp/spark3_333_thrift_compile_attempt{attempt}.log"
    write_status(phase="compile", attempt=attempt, log=log)
    code, out, err = run(BUILD, repo_dir, env=env, timeout=TIMEOUT, log_path=log)
    ok = code == 0
    write_status(phase="compile_done", attempt=attempt, exit=code, ok=ok, log=log)
    if not ok:
        text = Path(log).read_text(errors="replace") if Path(log).exists() else (out + err)
        for ln in text.splitlines()[-50:]:
            if any(x in ln for x in ("ERROR", "FAILURE", "error:", "BUILD")):
                print("   ", ln[:220], flush=True)
    return ok, log


def create_pr(branch: str, title: str, body: str) -> str | None:
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
        print(f"  PR created: {url}", flush=True)
        rr = requests.post(
            f"https://api.github.com/repos/{GH}/pulls/{num}/requested_reviewers",
            headers=headers, json={"reviewers": [REVIEWER]}, timeout=60,
        )
        print(f"  reviewer {REVIEWER}: HTTP {rr.status_code}", flush=True)
        return url
    print(f"  PR fail HTTP {r.status_code}: {r.text[:500]}", flush=True)
    return None


def close_tomcat_tickets(pr_url: str) -> dict:
    import cve_analyser as ca
    ca.DRY_RUN = DRY
    comment = (
        f"Fixed via PR: {pr_url} — bumped libthrift to {LIBTHRIFT} and removed the "
        f"ODP tomcat-embed 8.5.99 pin (OSV-12192) on {BASE}. libthrift 0.16.0 no "
        f"longer depends on tomcat-embed (same approach as spark 3.5.1), so "
        f"tomcat-embed-core leaves the Spark distribution and these CVEs no longer apply."
    )
    closed, failed = [], []
    for k in TOMCAT_TICKETS:
        url = f"{ca.JIRA_BASE_URL}/rest/api/3/issue/{k}?fields=status"
        r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                           auth=(ca.EMAIL, ca.API_TOKEN))
        st = ((r.json().get("fields") or {}).get("status") or {}).get("name") or "?"
        print(f"  {k} current={st}", flush=True)
        if st.lower() == "closed":
            ca.assign_issue(k, ca.resolve_assignee(ASSIGNEE))
            closed.append(k)
            continue
        ok = ca.close_ticket_with_comment(k, comment, "Closed", assignee=ASSIGNEE)
        print(f"    -> {'Closed' if ok else 'FAILED'}", flush=True)
        (closed if ok else failed).append(k)
    return {"closed": closed, "failed": failed, "comment": comment}


def main():
    write_status(
        phase="start",
        plan="libthrift->0.16.0 + remove tomcat pin; compile; PR; close Tomcat tickets",
        tickets=TOMCAT_TICKETS,
        base=BASE,
    )
    load_token()
    repo = ensure_repo()
    run(f"git checkout -B {BRANCH} origin/{BASE}", repo, env=git_env(), timeout=120)
    changed = apply_patch(repo)
    write_status(phase="patched", changed=changed, branch=BRANCH, libthrift=LIBTHRIFT)

    ok = False
    log = ""
    for attempt in range(1, MAX_COMPILE_ATTEMPTS + 1):
        # re-apply cleanly each attempt
        ensure_repo()
        run(f"git checkout -B {BRANCH} origin/{BASE}", repo, env=git_env(), timeout=120)
        apply_patch(repo)
        ok, log = compile_once(repo, attempt)
        if ok:
            break
        write_status(phase="compile_retry", attempt=attempt, next_attempt=attempt + 1)
        time.sleep(5)

    if not ok:
        write_status(phase="FAILED_COMPILE", ok=False, log=log,
                     message="compile failed after retries; no PR created")
        raise SystemExit(2)

    verify = verify_no_tomcat(repo)
    write_status(phase="verify_tomcat", **verify)
    if not verify["clean"]:
        write_status(phase="FAILED_VERIFY", ok=False,
                     message=f"tomcat jars still in dist: {verify['tomcat_jars']}")
        raise SystemExit(3)

    title = (
        f"{BRANCH} - CVE - Bumped-up libthrift to {LIBTHRIFT} and removed "
        f"tomcat-embed pin to address Tomcat CVEs"
    )
    body = "\n".join([
        f"- Library : libthrift (removes transitive tomcat-embed)",
        f"- Version : 0.14.1 -> {LIBTHRIFT}",
        f"- Also    : removed OSV-12192 tomcat-embed 8.5.99 dependencyManagement pin",
        f"- Tickets : {', '.join(TOMCAT_TICKETS)}",
        f"- Component: spark3_3_3_3 ({BASE})",
        "",
        "Rationale: Spark 3.5.1 uses libthrift 0.16.0 which no longer depends on "
        "tomcat-embed-core. Spark 3.3.3 was on 0.14.1 (pulls tomcat-embed 8.5.46) "
        "plus an ODP force to 8.5.99. Aligning thrift + dropping the pin clears "
        "Tomcat from the distribution without a major Tomcat 9+ upgrade.",
    ])

    if DRY:
        write_status(phase="DRY", title=title)
        return

    run("git add -A", repo, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title], cwd=str(repo),
        text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        write_status(phase="FAILED_COMMIT", stdout=p.stdout[-400:], stderr=p.stderr[-400:])
        raise SystemExit(4)
    code, _, err = run(f"git push -u origin {BRANCH}", repo, timeout=300)
    if code != 0:
        write_status(phase="FAILED_PUSH", error=err[-500:])
        raise SystemExit(5)

    pr_url = create_pr(BRANCH, title, body)
    if not pr_url:
        write_status(phase="FAILED_PR")
        raise SystemExit(6)

    write_status(phase="closing_tickets", pr=pr_url)
    result = close_tomcat_tickets(pr_url)
    write_status(
        phase="DONE",
        ok=True,
        pr=pr_url,
        closed=result["closed"],
        failed=result["failed"],
        verify=verify,
        message="libthrift 0.16.0 + Tomcat pin removed; PR opened; Tomcat tickets closed",
    )
    print("DONE", pr_url, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", ok=False, error=str(e)[:800])
        raise
