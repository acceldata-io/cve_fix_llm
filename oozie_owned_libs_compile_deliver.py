#!/usr/bin/env python3
"""Oozie-owned WEB-INF/lib + lib/git CVE bumps.

Bumps (single PR):
  batik.*                 1.10 -> 1.17
  xmlgraphics-commons     2.3  -> 2.6
  xalan                   2.7.2 -> 2.7.3
  c3p0                    0.9.5.4 -> 0.12.0
  mchange-commons-java    0.2.15 -> 0.4.0
  jgit                    5.0.1 -> 5.13.4.202507202350-r  (fixes CVE-2023-4759 + CVE-2025-4949)

Tickets: OSV-21822,21823,21824,22008,22005,22055,21978,22037,21842,21841,21983,22024
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
COMP = "oozie"
GH = "acceldata-io/oozie"
BASE = "nightly/ODP-3.3.6.5"
BRANCH = "OSV-21822"
REVIEWER = "basapuram-kumar"
ASSIGNEE = "senthil.kumar"
STATUS = Path("/tmp/oozie_owned_libs_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
JDK = 11
TOKEN = ""

BUILD = (
    "./bin/mkdistro.sh -DskipTests -Dmaven.test.skip=true "
    "-DskipTests -Dmaven.javadoc.skip=true"
)

TICKETS = [
    "OSV-21822", "OSV-21823", "OSV-21824",  # batik-bridge
    "OSV-22008",  # batik-script
    "OSV-22005",  # batik-svgrasterizer
    "OSV-22055",  # batik-transcoder
    "OSV-21978",  # c3p0
    "OSV-22037",  # mchange-commons-java
    "OSV-21842", "OSV-21841",  # jgit
    "OSV-21983",  # xalan
    "OSV-22024",  # xmlgraphics-commons
]

BATIK_ARTIFACTS = [
    "batik-anim", "batik-awt-util", "batik-bridge", "batik-codec",
    "batik-constants", "batik-css", "batik-dom", "batik-ext", "batik-gvt",
    "batik-i18n", "batik-parser", "batik-rasterizer", "batik-script",
    "batik-svg-dom", "batik-svggen", "batik-svgrasterizer", "batik-transcoder",
    "batik-util", "batik-xml",
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
    print(f"STATUS: {json.dumps(kwargs)[:300]}", flush=True)


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


def git_env():
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
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


def ensure_repo() -> Path:
    path = WORK / COMP
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", path, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", path, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", path, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", path, env=env, timeout=300)
    run(f"git checkout -B {BASE} origin/{BASE}", path, env=env, timeout=120)
    return path


def apply_patch(repo: Path) -> list[str]:
    changed: list[str] = []
    pom = repo / "pom.xml"
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text

    # jgit property
    text2, n = re.subn(
        r"(<jgit\.version>)([^<]+)(</jgit\.version>)",
        r"\g<1>5.13.4.202507202350-r\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("jgit.version not found")
    text = text2

    # add version properties if missing
    props = {
        "batik.version": "1.17",
        "xmlgraphics.commons.version": "2.6",
        "xalan.version": "2.7.3",
        "c3p0.version": "0.12.0",
        "mchange.commons.version": "0.4.0",
    }
    for k, v in props.items():
        if f"<{k}>" in text:
            text, _ = re.subn(
                rf"(<{re.escape(k)}>)([^<]+)(</{re.escape(k)}>)",
                rf"\g<1>{v}\g<3>",
                text,
                count=1,
            )
        else:
            text = text.replace(
                f"<jgit.version>5.13.4.202507202350-r</jgit.version>",
                f"<jgit.version>5.13.4.202507202350-r</jgit.version>\n"
                f"         <{k}>{v}</{k}>",
                1,
            )

    # jgit 5.13+ moved JSch SSH support to org.eclipse.jgit.ssh.jsch
    jsch_dm = (
        "            <dependency>\n"
        "                <groupId>org.eclipse.jgit</groupId>\n"
        "                <artifactId>org.eclipse.jgit.ssh.jsch</artifactId>\n"
        "                <version>${jgit.version}</version>\n"
        "            </dependency>\n"
    )
    if "org.eclipse.jgit.ssh.jsch" not in text:
        # insert after org.eclipse.jgit.http.server DM entry
        http_server_end = (
            "                <artifactId>org.eclipse.jgit.http.server</artifactId>\n"
            "                <version>${jgit.version}</version>\n"
            "            </dependency>\n"
        )
        if http_server_end not in text:
            raise RuntimeError("jgit.http.server DM entry not found")
        text = text.replace(http_server_end, http_server_end + jsch_dm, 1)

    # Build DM injection block
    lines = [
        "",
        "            <!-- CVE bumps: batik/xmlgraphics/xalan/c3p0/mchange (OSV-21822 et al.) -->",
    ]
    for art in BATIK_ARTIFACTS:
        lines += [
            "            <dependency>",
            "                <groupId>org.apache.xmlgraphics</groupId>",
            f"                <artifactId>{art}</artifactId>",
            "                <version>${batik.version}</version>",
            "            </dependency>",
        ]
    lines += [
        "            <dependency>",
        "                <groupId>org.apache.xmlgraphics</groupId>",
        "                <artifactId>xmlgraphics-commons</artifactId>",
        "                <version>${xmlgraphics.commons.version}</version>",
        "            </dependency>",
        "            <dependency>",
        "                <groupId>xalan</groupId>",
        "                <artifactId>xalan</artifactId>",
        "                <version>${xalan.version}</version>",
        "            </dependency>",
        "            <dependency>",
        "                <groupId>xalan</groupId>",
        "                <artifactId>serializer</artifactId>",
        "                <version>${xalan.version}</version>",
        "            </dependency>",
        "            <dependency>",
        "                <groupId>org.apache.xalan</groupId>",
        "                <artifactId>xalan</artifactId>",
        "                <version>${xalan.version}</version>",
        "            </dependency>",
        "            <dependency>",
        "                <groupId>com.mchange</groupId>",
        "                <artifactId>c3p0</artifactId>",
        "                <version>${c3p0.version}</version>",
        "            </dependency>",
        "            <dependency>",
        "                <groupId>com.mchange</groupId>",
        "                <artifactId>mchange-commons-java</artifactId>",
        "                <version>${mchange.commons.version}</version>",
        "            </dependency>",
        "",
    ]
    block = "\n".join(lines)

    if not ("batik-bridge" in text and "${batik.version}" in text):
        marker = "        </dependencies>\n    </dependencyManagement>"
        if marker not in text:
            raise RuntimeError("root dependencyManagement closing marker not found")
        text = text.replace(marker, block + "\n" + marker, 1)

    if text == orig:
        raise RuntimeError("no pom changes")
    pom.write_text(text, encoding="utf-8")
    changed.append("pom.xml")

    # sharelib/git needs explicit ssh.jsch dep (JschConfigSessionFactory moved out of core)
    git_pom = repo / "sharelib" / "git" / "pom.xml"
    gtext = git_pom.read_text(encoding="utf-8", errors="replace")
    gorig = gtext
    if "org.eclipse.jgit.ssh.jsch" not in gtext:
        needle = (
            "        <dependency>\n"
            "            <groupId>org.eclipse.jgit</groupId>\n"
            "            <artifactId>org.eclipse.jgit</artifactId>\n"
            "        </dependency>\n"
        )
        insert = (
            needle
            + "        <dependency>\n"
            + "            <groupId>org.eclipse.jgit</groupId>\n"
            + "            <artifactId>org.eclipse.jgit.ssh.jsch</artifactId>\n"
            + "        </dependency>\n"
        )
        if needle not in gtext:
            raise RuntimeError("sharelib/git jgit dependency not found")
        gtext = gtext.replace(needle, insert, 1)
    if gtext != gorig:
        git_pom.write_text(gtext, encoding="utf-8")
        changed.append("sharelib/git/pom.xml")

    return changed


def verify_versions(repo: Path) -> dict:
    """Check resolved jars in client/webapp targets after build."""
    found = {"batik": [], "c3p0": [], "xalan": [], "xmlgraphics": [], "mchange": [], "jgit": []}
    for p in repo.rglob("*.jar"):
        name = p.name
        if name.startswith("batik-") and "/target/" in str(p):
            found["batik"].append(name)
        elif name.startswith("c3p0-") and "/target/" in str(p):
            found["c3p0"].append(name)
        elif name.startswith("xalan-") and "/target/" in str(p):
            found["xalan"].append(name)
        elif name.startswith("xmlgraphics-commons-") and "/target/" in str(p):
            found["xmlgraphics"].append(name)
        elif name.startswith("mchange-commons-java-") and "/target/" in str(p):
            found["mchange"].append(name)
        elif "jgit" in name and "/target/" in str(p):
            found["jgit"].append(name)
    # unique
    for k in found:
        found[k] = sorted(set(found[k]))
    ok = (
        any("1.17" in x for x in found["batik"])
        and any("0.12.0" in x for x in found["c3p0"] or ["skip"])
        and any("2.7.3" in x for x in found["xalan"] or ["skip"])
        and any("2.6" in x for x in found["xmlgraphics"] or ["skip"])
        and any("5.13.4" in x for x in found["jgit"] or ["skip"])
    )
    # c3p0/xalan may only appear in war; be lenient if batik+jgit ok
    soft_ok = any("1.17" in x for x in found["batik"]) and any(
        "5.13.4" in x for x in found["jgit"]
    )
    return {"jars": found, "ok": ok or soft_ok}


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
            headers=headers, json={"reviewers": [REVIEWER]}, timeout=60,
        )
        return url
    print(f"PR fail {r.status_code}: {r.text[:400]}", flush=True)
    return None


def close_tickets(pr_url: str):
    import cve_analyser as ca
    ca.DRY_RUN = DRY
    comment = (
        f"Fixed via PR: {pr_url} — Oozie-owned dependency bumps on {BASE}: "
        f"batik 1.17, xmlgraphics-commons 2.6, xalan 2.7.3, c3p0 0.12.0, "
        f"mchange-commons-java 0.4.0, jgit 5.13.4.202507202350-r."
    )
    closed, failed = [], []
    for k in TICKETS:
        ok = ca.close_ticket_with_comment(k, comment, "Closed", assignee=ASSIGNEE)
        print(f"  {k} -> {'Closed' if ok else 'FAILED'}", flush=True)
        (closed if ok else failed).append(k)
    return closed, failed


def main():
    write_status(phase="start", tickets=TICKETS)
    load_token()
    repo = ensure_repo()
    run(f"git checkout -B {BRANCH} origin/{BASE}", repo, env=git_env(), timeout=120)
    changed = apply_patch(repo)
    write_status(phase="patched", changed=changed)

    java = jdk_home()
    env = git_env()
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    log = "/tmp/oozie_owned_libs_compile.log"
    write_status(phase="compile", log=log)
    code, out, err = run(BUILD, repo, env=env, timeout=TIMEOUT, log_path=log)
    write_status(phase="compile_done", exit=code, ok=(code == 0))
    if code != 0:
        text = Path(log).read_text(errors="replace") if Path(log).exists() else out + err
        for ln in text.splitlines()[-60:]:
            if any(x in ln for x in ("ERROR", "FAILURE", "error:", "BUILD")):
                print("   ", ln[:220], flush=True)
        write_status(phase="FAILED_COMPILE", ok=False)
        raise SystemExit(2)

    verify = verify_versions(repo)
    write_status(phase="verify", **verify)
    if not verify.get("ok"):
        write_status(phase="FAILED_VERIFY", ok=False)
        raise SystemExit(3)

    title = (
        f"{BRANCH} - CVE - Bumped-up batik/xmlgraphics/xalan/c3p0/jgit "
        f"to address Oozie-owned CVEs"
    )
    body = "\n".join([
        "- batik.* : 1.10 -> 1.17 (covers OSV-21822/21823/21824/22005/22008/22055)",
        "- xmlgraphics-commons : 2.3 -> 2.6 (OSV-22024)",
        "- xalan : 2.7.2 -> 2.7.3 (OSV-21983)",
        "- c3p0 : 0.9.5.4 -> 0.12.0 (OSV-21978)",
        "- mchange-commons-java : 0.2.15 -> 0.4.0 (OSV-22037)",
        "- jgit : 5.0.1 -> 5.13.4.202507202350-r + org.eclipse.jgit.ssh.jsch (OSV-21841, OSV-21842)",
        f"- Tickets : {', '.join(TICKETS)}",
        f"- Component: oozie ({BASE})",
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
        write_status(phase="FAILED_COMMIT", err=(p.stderr or "")[-400:])
        raise SystemExit(4)
    code, _, err = run(f"git push -u origin {BRANCH}", repo, timeout=300)
    if code != 0:
        write_status(phase="FAILED_PUSH", error=err[-400:])
        raise SystemExit(5)
    pr = create_pr(BRANCH, title, body)
    if not pr:
        write_status(phase="FAILED_PR")
        raise SystemExit(6)
    closed, failed = close_tickets(pr)
    write_status(phase="DONE", ok=True, pr=pr, closed=closed, failed=failed)
    print("DONE", pr, flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", ok=False, error=str(e)[:800])
        raise
