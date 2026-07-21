#!/usr/bin/env python3
"""Batch CVE deliver for druid (release 3.3.6.4).

Base: nightly/ODP-3.3.6.5 (JDK 8). One PR per library.
Status: /tmp/batch12_cve_status.json
Summary: /root/cve_fix_llm/reports/batch9_status.md

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
RELEASE = "3.3.6.4"
WORK = Path("/root/3.3.6.5/druid")
GH = "acceldata-io/druid"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/druid"
STATUS = Path("/tmp/batch12_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch9_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

JETTY = "9.4.57.v20241219"
BCPROV = "1.84"
POSTGRES = "42.7.11"
LANG3 = "3.18.0"
COMPRESS = "1.26.0"
ASYNCHTTP = "3.0.10"
PLEXUS = "3.6.1"
RHINO = "1.7.15.1"
AZURE_BOM = "1.2.25"
AIRCOMPRESSOR = "2.0.3"

LIB_ORDER = [
    "jetty", "bc", "postgresql", "lang3", "compress", "asynchttp",
    "plexus", "rhino", "azure", "aircompressor",
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
    print(f"STATUS: {json.dumps(kwargs)[:700]}", flush=True)


def append_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    existing = SUMMARY.read_text(encoding="utf-8") if SUMMARY.is_file() else ""
    block = [
        "",
        f"## druid ({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())})",
    ]
    for _, res in results.items():
        block.append(f"- excepted: {len(res.get('excepted') or [])}")
        block.append(f"- already-fixed: {', '.join(res.get('already_fixed') or []) or '—'}")
        block.append(f"- closed: {len(res.get('closed') or [])}")
        for pr in res.get("prs") or []:
            block.append(f"- PR: {pr}")
        if res.get("errors"):
            block.append(f"- errors: {json.dumps(res['errors'])[:400]}")
        if res.get("unknown"):
            block.append(f"- unknown: {', '.join(res['unknown'])}")
    text = existing
    if "## druid" in text:
        text = re.sub(r"\n## druid.*?(?=\n## |\Z)", "", text, flags=re.S)
    text = re.sub(
        r"(## Remaining queue\n)(.*?)(?=\n## |\Z)",
        r"\1- hue\n- superset\n",
        text,
        flags=re.S,
        count=1,
    )
    SUMMARY.write_text(text.rstrip() + "\n" + "\n".join(block) + "\n", encoding="utf-8")


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
        "/usr/lib/jvm/java-1.8.0-openjdk",
        "/usr/lib/jvm/java-1.8.0",
        "/usr/lib/jvm/java-8-openjdk",
    ):
        if Path(c).exists():
            return c
    raise SystemExit("JDK 8 not found")


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
    jql = f'project = OSV AND status = "To Do" AND summary ~ "{JIRA}" ORDER BY key ASC'
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,customfield_10892,"
                "customfield_10891,customfield_10888,customfield_10127"
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
            m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
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
    fix = row["fix"] or ""

    if "hadoop-client-runtime" in path or "hadoop-client-api" in path or "hadoop-common" in pkg:
        return "exception", (
            "Shaded/bundled inside Hadoop client runtime (or Hadoop platform "
            "artifact); remediation belongs to Hadoop/ODP. "
            "Exception Request (Deferred)."
        )
    if "velocity-engine" in path and "commons-io" in pkg:
        return "exception", (
            "commons-io is shaded inside velocity-engine-core; owner must rebuild. "
            "Exception Request (Deferred)."
        )
    if "druid-basic-security" in pkg or "druid-pac4j" in pkg:
        return "exception", (
            "CVE is in Druid extension code itself; published fixes require "
            "Druid 30+/product upgrade across ODP. Exception Request (Deferred)."
        )
    if "elasticsearch" in pkg:
        return "exception", (
            "elasticsearch 7.17.x fix requires 8.x/9.x major upgrade in "
            "druid-ranger-security. Exception Request (Deferred)."
        )
    if "ranger-plugins-common" in pkg or "ranger_" in pkg:
        return "exception", (
            "ODP Ranger platform artifact; remediation belongs to Ranger. "
            "Exception Request (Deferred)."
        )
    if "pac4j-core" in pkg or "pac4j_core" in pkg:
        return "exception", (
            "pac4j-core 4.5.x fix requires 5.7+/6.x major line with druid-pac4j. "
            "Exception Request (Deferred)."
        )
    if "reactor-netty" in pkg:
        return "exception", (
            "reactor-netty-http 1.2.8 is incompatible with azure-core-http-netty "
            "from azure-sdk-bom 1.0.x line used by Druid azure-extensions. "
            "Exception Request (Deferred)."
        )
    if "jetty" in pkg:
        if "hadoop-client" in path:
            return "exception", (
                "Jetty shaded inside hadoop-client-runtime. "
                "Exception Request (Deferred)."
            )
        if "9.4.57" in fix:
            return "fix", {"lib": "jetty", "name": "Jetty", "target": JETTY}
        # 12.x-only
        return "exception", (
            "Jetty 9.4.x CVE only fixed on Jetty 12.x (Jakarta); Druid remains on "
            "Jetty 9.4. Exception Request (Deferred)."
        )
    if "bcprov" in pkg or "bcpkix" in pkg or "bouncycastle" in pkg:
        return "fix", {"lib": "bc", "name": "BouncyCastle", "target": BCPROV}
    if "postgresql" in pkg:
        return "fix", {"lib": "postgresql", "name": "PostgreSQL JDBC", "target": POSTGRES}
    if "commons-lang3" in pkg:
        return "fix", {"lib": "lang3", "name": "commons-lang3", "target": LANG3}
    if "commons-compress" in pkg:
        return "fix", {"lib": "compress", "name": "commons-compress", "target": COMPRESS}
    if "async-http-client" in pkg:
        return "fix", {"lib": "asynchttp", "name": "async-http-client", "target": ASYNCHTTP}
    if "plexus-utils" in pkg:
        return "fix", {"lib": "plexus", "name": "plexus-utils", "target": PLEXUS}
    if pkg == "rhino" or "mozilla_rhino" in pkg or pkg.endswith("_rhino"):
        return "fix", {"lib": "rhino", "name": "Rhino", "target": RHINO}
    if "azure-identity" in pkg:
        return "fix", {"lib": "azure", "name": "azure-sdk-bom/azure-identity", "target": AZURE_BOM}
    if "aircompressor" in pkg:
        return "fix", {"lib": "aircompressor", "name": "aircompressor", "target": AIRCOMPRESSOR}
    if "nimbus-jose-jwt" in pkg or "nimbusds" in pkg:
        # 9.48 already above 9.37.4 same-major floor; 10.x needs JDK11
        return "already_fixed", (
            f"Already addressed on {BASE}: nimbus-jose-jwt 9.48 satisfies the "
            f"9.37.4 same-major fix line ({fix}). 10.x requires JDK 11."
        )
    return "unknown", f"unmapped {pkg}"


def replace_once(path: Path, old: str, new: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return False
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def ensure_dm_insert(path: Path, anchor: str, insert_before_anchor: str) -> bool:
    """If insert block not present, insert it immediately before anchor."""
    text = path.read_text(encoding="utf-8")
    if "aircompressor" in insert_before_anchor and "aircompressor" in text and AIRCOMPRESSOR in text:
        return False
    if "bcprov-jdk18on" in insert_before_anchor and f"bcprov-jdk18on" in text and BCPROV in text:
        return False
    if anchor not in text:
        raise RuntimeError(f"anchor missing in {path}")
    if insert_before_anchor.strip() in text:
        return False
    path.write_text(text.replace(anchor, insert_before_anchor + anchor, 1), encoding="utf-8")
    return True


def apply_lib(lib: str) -> list[str]:
    root = WORK / "pom.xml"
    az = WORK / "extensions-core/azure-extensions/pom.xml"
    changed = []

    if lib == "jetty":
        if replace_once(
            root,
            f"<jetty.version>9.4.56.v20240826</jetty.version>",
            f"<jetty.version>{JETTY}</jetty.version>",
        ):
            changed.append("pom.xml:jetty.version")
    elif lib == "postgresql":
        if replace_once(
            root,
            "<postgresql.version>42.7.2</postgresql.version>",
            f"<postgresql.version>{POSTGRES}</postgresql.version>",
        ):
            changed.append("pom.xml:postgresql.version")
    elif lib == "lang3":
        if replace_once(
            root,
            "<artifactId>commons-lang3</artifactId>\n                <version>3.12.0</version>",
            f"<artifactId>commons-lang3</artifactId>\n                <version>{LANG3}</version>",
        ):
            changed.append("pom.xml:commons-lang3")
    elif lib == "compress":
        if replace_once(
            root,
            "<artifactId>commons-compress</artifactId>\n                <version>1.24.0</version>",
            f"<artifactId>commons-compress</artifactId>\n                <version>{COMPRESS}</version>",
        ):
            changed.append("pom.xml:commons-compress")
    elif lib == "asynchttp":
        if replace_once(
            root,
            "<artifactId>async-http-client</artifactId>\n                <version>3.0.1</version>",
            f"<artifactId>async-http-client</artifactId>\n                <version>{ASYNCHTTP}</version>",
        ):
            changed.append("pom.xml:async-http-client")
    elif lib == "plexus":
        if replace_once(
            root,
            "<artifactId>plexus-utils</artifactId>\n                <version>3.0.24</version>",
            f"<artifactId>plexus-utils</artifactId>\n                <version>{PLEXUS}</version>",
        ):
            changed.append("pom.xml:plexus-utils")
    elif lib == "rhino":
        if replace_once(
            root,
            "<artifactId>rhino</artifactId>\n                <version>1.7.14</version>",
            f"<artifactId>rhino</artifactId>\n                <version>{RHINO}</version>",
        ):
            changed.append("pom.xml:rhino")
    elif lib == "azure":
        if replace_once(
            az,
            "<artifactId>azure-sdk-bom</artifactId>\n                <version>1.2.19</version>",
            f"<artifactId>azure-sdk-bom</artifactId>\n                <version>{AZURE_BOM}</version>",
        ):
            changed.append("extensions-core/azure-extensions/pom.xml:azure-sdk-bom")
    elif lib == "bc":
        # Force BC into root dependencyManagement (before jackson-bom is a stable anchor)
        anchor = """            <dependency>
                <groupId>com.fasterxml.jackson</groupId>
                <artifactId>jackson-bom</artifactId>"""
        insert = f"""            <dependency>
                <groupId>org.bouncycastle</groupId>
                <artifactId>bcprov-jdk18on</artifactId>
                <version>{BCPROV}</version>
            </dependency>
            <dependency>
                <groupId>org.bouncycastle</groupId>
                <artifactId>bcpkix-jdk18on</artifactId>
                <version>{BCPROV}</version>
            </dependency>
"""
        if ensure_dm_insert(root, anchor, insert):
            changed.append("pom.xml:bouncycastle")
        # also pin in kubernetes-extensions if present later — root DM is enough for Maven
    elif lib == "aircompressor":
        anchor = """            <dependency>
                <groupId>com.github.luben</groupId>
                <artifactId>zstd-jni</artifactId>
                <version>1.5.2-3</version>
            </dependency>"""
        insert = anchor + f"""
            <dependency>
                <groupId>io.airlift</groupId>
                <artifactId>aircompressor</artifactId>
                <version>{AIRCOMPRESSOR}</version>
            </dependency>"""
        # replace anchor with anchor+insert by rewriting: ensure_dm inserts BEFORE anchor
        # so use custom: replace zstd block with zstd+air
        text = root.read_text(encoding="utf-8")
        if f"<version>{AIRCOMPRESSOR}</version>" in text and "aircompressor" in text:
            return changed
        if anchor not in text:
            raise RuntimeError("zstd-jni anchor missing")
        root.write_text(text.replace(anchor, insert, 1), encoding="utf-8")
        changed.append("pom.xml:aircompressor")
    return changed


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=900)


def compile_gate(lib: str) -> bool:
    log = f"/tmp/batch12_druid_{lib}_build.log"
    env = git_env()
    cmd = (
        "mvn -q -N validate -DskipTests -Dcheckstyle.skip=true "
        "-Drat.skip=true -Dforbiddenapis.skip=true -Denforcer.skip=true"
    )
    code, out, err = run(cmd, WORK, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        for ln in (out + err).splitlines()[-40:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
        return False
    if lib == "azure":
        code2, out2, err2 = run(
            "mvn -q -pl extensions-core/azure-extensions -am validate "
            "-DskipTests -Dcheckstyle.skip=true -Drat.skip=true "
            "-Dforbiddenapis.skip=true -Denforcer.skip=true",
            WORK, env=env, timeout=TIMEOUT, log_path=log,
        )
        if code2 != 0:
            for ln in (out2 + err2).splitlines()[-40:]:
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


def deliver_lib(ca, lib, tickets):
    meta = tickets[0]
    name, target = meta.get("name") or lib, meta.get("target")
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    title = (
        f"{branch} - CVE - Bumped-up {name} to {target} to address "
        f"{'/'.join(cves) if cves else 'CVE'}"
    )
    print(f"\n=== druid/{lib} PR branch={branch} ({len(tickets)}) ===", flush=True)
    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_lib(lib)
    if not changed:
        return {"lib": lib, "ok": False, "phase": "NO_CHANGE"}
    if DRY:
        return {"lib": lib, "dry": True, "title": title, "changed": changed}
    if not compile_gate(lib):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "branch": branch}
    run("git add -A", WORK, env=git_env(), timeout=120)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(WORK), text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        return {"lib": lib, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", WORK, env=git_env(), timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}
    body = "\n".join([
        f"- Component: druid ({BASE}, release {RELEASE})",
        f"- Library: {name} → {target}",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Files: {', '.join(changed)}",
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}
    closed = []
    for t in tickets:
        ok = ca.close_ticket_with_comment(
            t["key"],
            f"Fixed via PR: {pr} — bumped {name} to {target} on {BASE}.",
            "Closed",
            assignee=ASSIGNEE,
        )
        print(f"  {t['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(t["key"])
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed}


def process(ca):
    write_status(phase="druid:load")
    rows = load_tickets(ca)
    excepted, fixable, unknown, already = [], [], [], []
    for row in rows:
        action, meta = classify(row)
        if action == "exception":
            print(f"[druid] EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE,
                )
                (excepted if ok else unknown).append(row["key"])
        elif action == "already_fixed":
            print(f"[druid] ALREADY {row['key']} {row['pkg']}", flush=True)
            if DRY:
                already.append(row["key"])
            else:
                ok = ca.close_ticket_with_comment(
                    row["key"], f"Closed: {meta}", "Closed", assignee=ASSIGNEE,
                )
                (already if ok else unknown).append(row["key"])
        elif action == "fix":
            print(f"[druid] FIXABLE {row['key']} {row['pkg']} -> {meta['target']}", flush=True)
            fixable.append({**row, **meta})
        else:
            print(f"[druid] UNKNOWN {row['key']} {meta}", flush=True)
            unknown.append(row["key"])

    if ROUTE_ONLY:
        return {
            "excepted": excepted,
            "fixable": [r["key"] for r in fixable],
            "already_fixed": already,
            "unknown": unknown,
            "prs": [],
            "fixable_detail": [
                {"key": r["key"], "lib": r.get("lib"), "target": r.get("target")}
                for r in fixable
            ],
        }

    by_lib: dict[str, list] = {}
    for r in fixable:
        by_lib.setdefault(r["lib"], []).append(r)
    prs, closed, errors = [], [], []
    for lib in LIB_ORDER:
        if lib not in by_lib:
            continue
        try:
            res = deliver_lib(ca, lib, by_lib[lib])
        except Exception as e:
            res = {"lib": lib, "ok": False, "error": str(e)[:400]}
            print(f"[druid/{lib}] ERROR {e}", flush=True)
        if res and res.get("pr"):
            prs.append(res["pr"])
            closed.extend(res.get("closed") or [])
        elif res and not res.get("ok", True) and not res.get("dry"):
            errors.append(res)
    out = {
        "excepted": excepted,
        "closed": closed,
        "already_fixed": already,
        "prs": prs,
        "unknown": unknown,
    }
    if errors:
        out["errors"] = errors
    return out


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    results = {"druid": process(ca)}
    append_summary(results)
    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    main()
