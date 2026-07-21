#!/usr/bin/env python3
"""Batch CVE deliver for nifi, ozone, ozone2 (release 3.3.6.4).

Separate PR per library.
Status: /tmp/batch6_cve_status.json
Summary: /root/cve_fix_llm/reports/batch6_status.md

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_COMPONENTS=nifi,ozone,ozone2
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
ROOT = Path("/root/3.3.6.5")
STATUS = Path("/tmp/batch6_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch6_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
TOKEN = ""

LANG3 = "3.18.0"
LOGBACK13 = "1.3.16"
NIMBUS = "10.0.2"
CONFIG2 = "2.15.0"
MAIL = "1.6.8"
SPRING53 = "5.3.39"
NETTY = "4.1.133.Final"
OTEL = "1.62.0"
OKIO_MIN = "3.4.0"

COMPONENTS = {
    "nifi": {
        "jira": "sehajsandhu/nifi",
        "gh": "acceldata-io/nifi",
        "work": ROOT / "nifi",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
        "exclude_jira_substr": "nifi2",
    },
    "ozone": {
        "jira": "sehajsandhu/ozone",
        "gh": "acceldata-io/ozone",
        "work": ROOT / "ozone",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
        "exclude_jira_substr": "ozone2",
    },
    "ozone2": {
        "jira": "sehajsandhu/ozone2",
        "gh": "acceldata-io/ozone",
        "work": ROOT / "ozone2",
        "base": "nightly/ODP-2.1.0.3.3.6.5",
        "jdk": 11,
    },
}

FILTER = [
    c.strip()
    for c in os.environ.get("CVE_COMPONENTS", "nifi,ozone,ozone2").split(",")
    if c.strip()
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


def write_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Batch6 CVE status ({RELEASE})",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        "",
        "Google Sheet: not updated (no Sheets credentials). Paste from this file.",
        "",
    ]
    for comp, res in results.items():
        lines.append(f"## {comp}")
        lines.append(f"- excepted: {', '.join(res.get('excepted') or []) or '—'}")
        lines.append(f"- closed: {', '.join(res.get('closed') or []) or '—'}")
        if res.get("already_fixed"):
            lines.append(f"- already-fixed: {', '.join(res['already_fixed'])}")
        for pr in res.get("prs") or []:
            lines.append(f"- PR: {pr}")
        if res.get("unknown"):
            lines.append(f"- unknown: {', '.join(res['unknown'])}")
        if res.get("errors"):
            lines.append(f"- errors: {json.dumps(res['errors'])[:500]}")
        if res.get("error"):
            lines.append(f"- ERROR: {res['error']}")
        lines.append("")
    SUMMARY.write_text("\n".join(lines), encoding="utf-8")


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


def jdk_home(jdk: int):
    cands = [
        f"/usr/lib/jvm/java-{jdk}-openjdk",
        f"/usr/lib/jvm/java-{jdk}",
        f"/usr/lib/jvm/jdk-{jdk}",
    ]
    for c in cands:
        if Path(c).exists():
            return c
    jvm = Path("/usr/lib/jvm")
    if jvm.is_dir():
        for p in sorted(jvm.iterdir()):
            if p.is_dir() and str(jdk) in p.name:
                return str(p)
    raise SystemExit(f"JDK {jdk} not found")


def git_env(jdk: int = 11):
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    home = jdk_home(jdk)
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


def load_tickets(ca, cfg):
    jira = cfg["jira"]
    jql = f'project = OSV AND status = "To Do" AND summary ~ "{jira}" ORDER BY key ASC'
    issues, token = [], None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,customfield_10870,"
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
    excl = cfg.get("exclude_jira_substr")
    rows = []
    for i in issues:
        f = i["fields"]
        repo = field_text(f.get("customfield_10870"))
        if excl and excl in repo:
            continue
        if jira not in repo and jira not in (f.get("summary") or ""):
            continue
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
            "repo": repo,
        })
    return rows


def classify_nifi(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    fix = row["fix"] or ""

    if "ratis-thirdparty" in path:
        return "exception", (
            "Netty is shaded inside ratis-thirdparty-misc; bump requires a newer "
            "ratis-thirdparty release, not a NiFi property pin. "
            "Exception Request (Deferred)."
        )
    if "hadoop-common" in pkg:
        return "exception", (
            "hadoop-common is the ODP Hadoop platform artifact. "
            "Exception Request (Deferred)."
        )
    if "ranger-plugins" in pkg:
        return "exception", (
            "ranger-plugins-common fix requires Ranger 2.8.0; belongs to Ranger. "
            "Exception Request (Deferred)."
        )
    if "aircompressor" in pkg:
        return "exception", (
            "aircompressor fix is on 2.0.x (major from 0.27). "
            "Exception Request (Deferred)."
        )
    if "elasticsearch" in pkg:
        return "exception", (
            "Elasticsearch 7.17 line; advisory fixes are on 8.x/9.x. "
            "Exception Request (Deferred)."
        )
    if "nifi-framework-core" in pkg or "org.apache.nifi_nifi-framework" in pkg:
        return "exception", (
            "Advisory requires NiFi 2.x; this component is NiFi 1.28.x. "
            "Exception Request (Deferred)."
        )
    if "jgit" in pkg:
        return "exception", (
            "JGit fix requires 7.x (major from 5.13). Exception Request (Deferred)."
        )
    if "spring-boot" in pkg:
        return "exception", (
            "Spring Boot 2.7.x; advisory fixes are on 3.x/4.x (major). "
            "Exception Request (Deferred)."
        )
    if "spring-security" in pkg:
        return "exception", (
            "Spring Security 5.8.x; advisory fixes are on 6.x/7.x. "
            "Exception Request (Deferred)."
        )
    if pkg.startswith("spring-") or pkg in (
        "spring-web", "spring-core", "spring-webmvc", "spring-context", "spring-ldap-core"
    ):
        if "spring-ldap" in pkg:
            return "exception", (
                "spring-ldap is not a managed root property on this NiFi branch; "
                "fix versions are 2.4.4/3.x. Exception Request (Deferred)."
            )
        covered = any(v in fix for v in ("5.3.35", "5.3.36", "5.3.37", "5.3.38", "5.3.39"))
        if covered and row.get("ver", "").startswith("5.3.") and row["ver"] < "5.3.39":
            return "fix_spring", {
                "target": SPRING53, "lib": "spring", "name": "Spring Framework",
            }
        return "exception", (
            f"Spring Framework already on/near 5.3.39 max published line; "
            f"advisory needs 6.x/7.x or unpublished 5.3.41+ ({fix}). "
            "Exception Request (Deferred)."
        )
    if "logback" in pkg:
        if "1.3." in fix:
            return "fix_logback", {
                "target": LOGBACK13, "lib": "logback", "name": "logback",
            }
        return "exception", (
            "logback advisory fix is only on 1.5.x; NiFi stays on 1.3.x. "
            "Exception Request (Deferred)."
        )
    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {"target": LANG3, "lib": "lang3", "name": "commons-lang3"}
    if "nimbus" in pkg:
        return "fix_nimbus", {"target": NIMBUS, "lib": "nimbus", "name": "nimbus-jose-jwt"}
    if "configuration2" in pkg:
        return "fix_config2", {
            "target": CONFIG2, "lib": "config2", "name": "commons-configuration2",
        }
    if "jakarta.mail" in pkg or pkg.endswith("_jakarta.mail"):
        return "fix_mail", {"target": MAIL, "lib": "mail", "name": "jakarta.mail"}
    if "okio" in pkg:
        return "already_fixed", {
            "note": (
                f"NiFi already pins okio.version=3.9.1 (>= {OKIO_MIN}) on "
                f"{COMPONENTS['nifi']['base']}."
            ),
        }
    return "unknown", f"No rule for {pkg} path={path}"


def classify_ozone(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    fix = row["fix"] or ""

    if "ratis-thirdparty" in path:
        return "exception", (
            "Netty is shaded inside ratis-thirdparty-misc; requires newer "
            "ratis-thirdparty, not Ozone netty.version alone. "
            "Exception Request (Deferred)."
        )
    if "hadoop-common" in pkg or "hadoop-hdfs" in pkg:
        return "exception", (
            "Hadoop platform artifact; remediation belongs to Hadoop. "
            "Exception Request (Deferred)."
        )
    if "ranger-plugins" in pkg:
        return "exception", (
            "ranger-plugins-common fix requires Ranger 2.8.0. "
            "Exception Request (Deferred)."
        )
    if "aircompressor" in pkg:
        return "exception", (
            "aircompressor fix is on 2.0.x (major from 0.27). "
            "Exception Request (Deferred)."
        )
    if "jetty" in pkg:
        return "exception", (
            "Jetty CVE fix is only on 12.x; Ozone stays on Jetty 9.4.x. "
            "Exception Request (Deferred)."
        )
    if pkg.startswith("spring-") or pkg == "spring-core":
        covered = any(v in fix for v in ("5.3.35", "5.3.36", "5.3.37", "5.3.38", "5.3.39"))
        if covered:
            return "fix_spring", {
                "target": SPRING53, "lib": "spring", "name": "Spring Framework",
            }
        return "exception", (
            f"Spring Framework advisory needs 6.x/7.x or unpublished 5.3.41 "
            f"({fix}). Exception Request (Deferred)."
        )
    if "configuration2" in pkg:
        return "fix_config2", {
            "target": CONFIG2, "lib": "config2", "name": "commons-configuration2",
        }
    if "okio" in pkg:
        return "already_fixed", {
            "note": (
                f"Ozone already pins okio.version=3.6.0 (>= {OKIO_MIN}) on "
                f"{COMPONENTS['ozone']['base']}."
            ),
        }
    if "protobuf" in pkg:
        return "already_fixed", {
            "note": (
                "Ozone dependencyManagement already pins protobuf-java to "
                "proto3.hadooprpc.protobuf.version=3.25.5 on nightly/ODP-3.3.6.5."
            ),
        }
    if "netty" in pkg:
        # managed netty (e.g. ozone-filesystem client), not ratis-shaded
        return "fix_netty", {"target": NETTY, "lib": "netty", "name": "Netty"}
    return "unknown", f"No rule for {pkg} path={path}"


def classify_ozone2(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    fix = row["fix"] or ""

    if "ratis-thirdparty" in path:
        return "exception", (
            "Netty is shaded inside ratis-thirdparty-misc-1.0.9; requires newer "
            "ratis-thirdparty artifact. Exception Request (Deferred)."
        )
    if "hadoop-common" in pkg:
        return "exception", (
            "hadoop-common is the ODP Hadoop platform artifact. "
            "Exception Request (Deferred)."
        )
    if "ranger-plugins" in pkg:
        return "exception", (
            "ranger-plugins-common fix requires Ranger 2.8.0. "
            "Exception Request (Deferred)."
        )
    if "aircompressor" in pkg:
        return "exception", (
            "aircompressor fix is on 2.0.x (major from 0.27). "
            "Exception Request (Deferred)."
        )
    if pkg.startswith("spring-") or pkg == "spring-core":
        return "exception", (
            f"Ozone2 already on Spring 5.3.39 (max published 5.3.x); advisory "
            f"needs 6.x/7.x or unpublished 5.3.41 ({fix}). "
            "Exception Request (Deferred)."
        )
    if "configuration2" in pkg:
        return "fix_config2", {
            "target": CONFIG2, "lib": "config2", "name": "commons-configuration2",
        }
    if "opentelemetry" in pkg:
        return "fix_otel", {"target": OTEL, "lib": "otel", "name": "OpenTelemetry"}
    if "protobuf" in pkg:
        return "already_fixed", {
            "note": (
                "Ozone2 already pins protobuf.version=3.25.5 on "
                "nightly/ODP-2.1.0.3.3.6.5."
            ),
        }
    if "okio" in pkg:
        return "exception", (
            "okio appears via ozone-filesystem shading path without a simple "
            "root okio.version pin on this branch. Exception Request (Deferred)."
        )
    if "netty" in pkg:
        return "fix_netty", {"target": NETTY, "lib": "netty", "name": "Netty"}
    return "unknown", f"No rule for {pkg} path={path}"


CLASSIFY = {
    "nifi": classify_nifi,
    "ozone": classify_ozone,
    "ozone2": classify_ozone2,
}


def apply_pom_prop(work: Path, prop: str, ver: str, rel: str = "pom.xml"):
    pom = work / rel
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)",
        rf"\g<1>{ver}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError(f"{prop} not found in {rel}")
    pom.write_text(text2, encoding="utf-8")
    return [rel]


def apply_nifi_nimbus(work: Path):
    changed = []
    for p in work.rglob("pom.xml"):
        if "/target/" in str(p) or "/.git/" in str(p):
            continue
        text = p.read_text(encoding="utf-8")
        if "nimbus-jose-jwt" not in text:
            continue
        text2, n = re.subn(
            r"(<artifactId>nimbus-jose-jwt</artifactId>\s*<version>)([^<]+)(</version>)",
            rf"\g<1>{NIMBUS}\g<3>",
            text,
        )
        if n:
            p.write_text(text2, encoding="utf-8")
            changed.append(str(p.relative_to(work)))
    if not changed:
        raise RuntimeError("no nimbus-jose-jwt versions updated")
    return changed


def apply_nifi_config2(work: Path):
    changed = []
    for p in work.rglob("pom.xml"):
        if "/target/" in str(p) or "/.git/" in str(p):
            continue
        text = p.read_text(encoding="utf-8")
        if "commons-configuration2" not in text:
            continue
        text2, n = re.subn(
            r"(<artifactId>commons-configuration2</artifactId>\s*<version>)(2\.[0-9.]+)(</version>)",
            rf"\g<1>{CONFIG2}\g<3>",
            text,
        )
        if n:
            p.write_text(text2, encoding="utf-8")
            changed.append(str(p.relative_to(work)))
    if not changed:
        raise RuntimeError("no commons-configuration2 versions updated")
    return changed


def apply_nifi_mail(work: Path):
    pom = work / "nifi-bootstrap" / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<artifactId>jakarta\.mail(?:-api)?</artifactId>\s*<version>)1\.6\.7(</version>)",
        rf"\g<1>{MAIL}\g<2>",
        text,
    )
    if n < 1:
        raise RuntimeError("jakarta.mail 1.6.7 not found in nifi-bootstrap")
    pom.write_text(text2, encoding="utf-8")
    return ["nifi-bootstrap/pom.xml"]


def apply_ozone2_netty(work: Path):
    changed = []
    changed += apply_pom_prop(work, "netty.version", NETTY)
    # keep ratis-thirdparty.netty.version in sync for documentation / any rebuilds
    pom = work / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<ratis-thirdparty\.netty\.version>)([^<]+)(</ratis-thirdparty\.netty\.version>)",
        rf"\g<1>{NETTY}\g<3>",
        text,
        count=1,
    )
    if n == 1:
        pom.write_text(text2, encoding="utf-8")
    return ["pom.xml"]


APPLY = {
    ("nifi", "lang3"): lambda w: apply_pom_prop(
        w, "org.apache.commons.lang3.version", LANG3
    ),
    ("nifi", "logback"): lambda w: apply_pom_prop(w, "logback.version", LOGBACK13),
    ("nifi", "nimbus"): apply_nifi_nimbus,
    ("nifi", "config2"): apply_nifi_config2,
    ("nifi", "mail"): apply_nifi_mail,
    ("ozone", "spring"): lambda w: apply_pom_prop(w, "spring.version", SPRING53),
    ("ozone", "config2"): lambda w: apply_pom_prop(
        w, "commons-configuration2.version", CONFIG2
    ),
    ("ozone", "netty"): lambda w: apply_pom_prop(w, "netty.version", NETTY),
    ("ozone2", "config2"): lambda w: apply_pom_prop(
        w, "commons-configuration2.version", CONFIG2
    ),
    ("ozone2", "otel"): lambda w: apply_pom_prop(w, "opentelemetry.version", OTEL),
    ("ozone2", "netty"): apply_ozone2_netty,
}


def ensure_repo(work: Path, gh: str, base: str, jdk: int):
    env = git_env(jdk)
    run(f"git remote set-url origin https://github.com/{gh}.git", work, env=env, timeout=60)
    run(f"git fetch origin {base} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {base} origin/{base}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", work, env=env, timeout=900)


def compile_gate(comp: str, work: Path, lib: str, jdk: int) -> bool:
    log = f"/tmp/batch6_{comp}_{lib}_build.log"
    env = git_env(jdk)
    if comp == "nifi":
        cmd = (
            "mvn -q -DskipTests -Drat.skip=true -Dcheckstyle.skip=true "
            "-Denforcer.skip=true -Dmaven.javadoc.skip=true "
            "-pl nifi-bootstrap,nifi-commons/nifi-utils -am package"
        )
    elif comp in ("ozone", "ozone2"):
        cmd = (
            "mvn -q -DskipTests -DskipShade -Drat.skip=true -Dcheckstyle.skip=true "
            "-Dfindbugs.skip=true -Dspotbugs.skip=true -Denforcer.skip=true "
            "-Dmaven.javadoc.skip=true "
            "-pl hadoop-hdds/framework -am package"
        )
    else:
        raise RuntimeError(comp)
    code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        for ln in (out + err).splitlines()[-50:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
    return code == 0


def create_pr(gh, branch, title, body, base):
    import requests

    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    r = requests.post(
        f"https://api.github.com/repos/{gh}/pulls",
        headers=headers,
        json={"title": title, "head": branch, "base": base, "body": body},
        timeout=60,
    )
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        requests.post(
            f"https://api.github.com/repos/{gh}/pulls/{num}/requested_reviewers",
            headers=headers,
            json={"reviewers": [REVIEWER]},
            timeout=60,
        )
        return url
    print(f"PR fail {r.status_code}: {r.text[:500]}", flush=True)
    return None


def deliver_lib(ca, comp, cfg, lib, tickets):
    if not tickets:
        return None
    work = cfg["work"]
    gh = cfg["gh"]
    base = cfg["base"]
    jdk = cfg["jdk"]
    meta = tickets[0]
    name = meta.get("name") or lib
    target = meta.get("target")
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    cve_str = "/".join(cves) if cves else "CVE"
    title = f"{branch} - CVE - Bumped-up {name} to {target} to address {cve_str}"

    print(f"\n=== {comp}/{lib} PR branch={branch} ({len(tickets)} tickets) ===", flush=True)
    ensure_repo(work, gh, base, jdk)
    run(f"git checkout -B {branch} origin/{base}", work, env=git_env(jdk), timeout=120)

    applier = APPLY.get((comp, lib))
    if not applier:
        raise RuntimeError(f"no applier for {comp}/{lib}")
    changed = applier(work)
    if DRY:
        return {"lib": lib, "dry": True, "title": title, "tickets": [t["key"] for t in tickets]}

    if not compile_gate(comp, work, lib, jdk):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "branch": branch}

    run("git add -A", work, env=git_env(jdk), timeout=120)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(work), text=True, capture_output=True, env=git_env(jdk),
    )
    if p.returncode != 0:
        return {"lib": lib, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", work, env=git_env(jdk), timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: {comp} ({base}, release {RELEASE})",
        f"- Library: {name} → {target}",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Files: {', '.join(changed[:20])}{'...' if len(changed)>20 else ''}",
    ])
    pr = create_pr(gh, branch, title, body, base)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}

    closed = []
    for t in tickets:
        ok = ca.close_ticket_with_comment(
            t["key"],
            f"Fixed via PR: {pr} — bumped {name} to {target} on {base}.",
            "Closed",
            assignee=ASSIGNEE,
        )
        print(f"  {t['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(t["key"])
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed, "branch": branch}


LIB_ORDER = {
    "nifi": ["lang3", "logback", "nimbus", "config2", "mail"],
    "ozone": ["spring", "config2", "netty"],
    "ozone2": ["config2", "otel", "netty"],
}


def process_component(ca, comp: str):
    cfg = COMPONENTS[comp]
    write_status(phase=f"{comp}:load")
    rows = load_tickets(ca, cfg)
    write_status(**{f"{comp}_tickets": [r["key"] for r in rows]})

    excepted, fixable, unknown, already = [], [], [], []
    classify = CLASSIFY[comp]
    for row in rows:
        action, meta = classify(row)
        if action == "exception":
            print(f"[{comp}] EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE
                )
                (excepted if ok else unknown).append(row["key"])
        elif action == "already_fixed":
            print(f"[{comp}] ALREADY_FIXED {row['key']} {row['pkg']}", flush=True)
            note = meta.get("note") if isinstance(meta, dict) else str(meta)
            if DRY:
                already.append(row["key"])
            else:
                ok = ca.close_ticket_with_comment(
                    row["key"], note, "Closed", assignee=ASSIGNEE
                )
                (already if ok else unknown).append(row["key"])
        elif action.startswith("fix_"):
            print(
                f"[{comp}] FIXABLE {row['key']} {row['pkg']} -> {meta.get('target')}",
                flush=True,
            )
            fixable.append({**row, **meta, "action": action})
        else:
            print(f"[{comp}] UNKNOWN {row['key']} {meta}", flush=True)
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
    for lib in LIB_ORDER[comp]:
        if lib not in by_lib:
            continue
        try:
            res = deliver_lib(ca, comp, cfg, lib, by_lib[lib])
        except Exception as e:
            res = {"lib": lib, "ok": False, "error": str(e)[:400]}
            print(f"[{comp}/{lib}] ERROR {e}", flush=True)
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
    write_status(phase="start", components=FILTER)
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    results = {}
    for comp in FILTER:
        if comp not in COMPONENTS:
            print(f"skip unknown component {comp}", flush=True)
            continue
        try:
            results[comp] = process_component(ca, comp)
        except Exception as e:
            results[comp] = {"error": str(e)[:800]}
            write_status(phase=f"{comp}:ERROR", error=str(e)[:800])
        write_summary(results)
        write_status(phase=f"{comp}:done", results=results)

    write_status(phase="DONE", results=results)
    write_summary(results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
