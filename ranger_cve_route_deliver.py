#!/usr/bin/env python3
"""Ranger (sehajsandhu/ranger, release 3.3.6.4) CVE routing + per-lib PRs.

Branch: nightly/ODP-3.3.6.5 (JDK 11)

FIX (separate PR per library property bump in root pom.xml):
  - tomcat.embed.version          9.0.115 -> 9.0.120
  - commons.lang3.version         3.3.2   -> 3.18.0
  - commons.configuration.version 2.10.1  -> 2.15.0
  - nimbus-jose-jwt.version       10.0.1  -> 10.0.2
  - logback.version               1.3.14  -> 1.3.16
  - poi.version                   5.2.2   -> 5.4.0
  - io.opentelemetry.version      1.49.0  -> 1.62.0

EXCEPTION:
  - Spring Framework 5.3.39 (fixes need 5.3.41 unpublished / 6.x)
  - Spring Security 5.7.12 (fixes only on 6.x+)
  - logback CVE needing only 1.5.x
  - bouncycastle jdk15on 1.67 (line ends at 1.70; fixes on jdk18on 1.78+)
  - aircompressor 0.27 (fix only 2.0.3 major line)
  - elasticsearch 7.17 (fixes on 8.x/9.x)
  - netty / grpc-netty inside ozone/hbase/jersey shaded jars
  - hadoop-common, jetty in hadoop-client-runtime
  - ranger-plugins-common / nifi-registry-plugin (need Ranger 2.8.0)
  - commons-configuration 1.10 (no fix published)
  - okio / okio-jvm / underscore (not managed as Ranger properties)
  - hbase-shaded-netty (platform shaded; bump via hbase-thirdparty elsewhere)

Already open: Netty PR #167, Jackson PR #168 (tickets already Closed).

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_LIBS=tomcat,lang3,...
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
WORK = Path("/root/3.3.6.5/ranger")
GH = "acceldata-io/ranger"
BASE = "nightly/ODP-3.3.6.5"
JIRA = "sehajsandhu/ranger"
RELEASE = "3.3.6.4"
STATUS = Path("/tmp/ranger_cve_route_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/ranger_cve_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
TOKEN = ""
JDK = 11

TARGETS = {
    "tomcat": ("tomcat.embed.version", "9.0.120", "Tomcat", "tomcat"),
    "lang3": ("commons.lang3.version", "3.18.0", "commons-lang3", "commons-lang3"),
    "config2": ("commons.configuration.version", "2.15.0", "commons-configuration2", "commons-configuration"),
    "nimbus": ("nimbus-jose-jwt.version", "10.0.2", "nimbus-jose-jwt", "nimbus"),
    "logback": ("logback.version", "1.3.16", "logback", "logback"),
    "poi": ("poi.version", "5.4.0", "poi", "poi"),
    "otel": ("io.opentelemetry.version", "1.62.0", "opentelemetry", "opentelemetry"),
}

LIB_FILTER = {
    x.strip().lower()
    for x in os.environ.get("CVE_LIBS", ",".join(TARGETS)).split(",")
    if x.strip()
}

# lighter per-lib compile modules
BUILD_PL = {
    "tomcat": "embeddedwebserver,security-admin",
    "lang3": "agents-common,credentialbuilder,embeddedwebserver",
    "config2": "agents-common",
    "nimbus": "agents-common,credentialbuilder,embeddedwebserver",
    "logback": "security-admin,embeddedwebserver",
    "poi": "security-admin",
    "otel": "hbase-agent",
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


def write_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Ranger CVE status ({RELEASE} → {BASE})",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        "",
        f"- excepted: {len(results.get('excepted') or [])}",
        f"- closed: {', '.join(results.get('closed') or []) or '—'}",
    ]
    for pr in results.get("prs") or []:
        lines.append(f"- PR: {pr}")
    if results.get("errors"):
        lines.append(f"- errors: {results['errors']}")
    SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


def has_prefix_fix(fix_field: str, prefixes: tuple[str, ...]) -> bool:
    return any(any(v.startswith(p) for p in prefixes) for v in parse_fix_versions(fix_field))


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
                "customfield_10127,customfield_10870"
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
        repo = field_text(f.get("customfield_10870"))
        if JIRA not in repo and JIRA not in (f.get("summary") or ""):
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
    fix = row.get("fix") or ""

    # --- shaded / platform ---
    if any(
        x in path
        for x in (
            "ozone-filesystem",
            "jersey-shaded",
            "hbase-shaded-netty",
            "hbase-shaded-client",
            "hadoop-client-runtime",
            "grpc-netty-shaded",
        )
    ):
        return "exception", (
            f"Flagged inside third-party/shaded jar ({Path(path).name}); not a "
            "Ranger-managed standalone dependency pin. Exception Request (Deferred)."
        )

    if "hadoop-common" in pkg:
        return "exception", (
            "hadoop-common is the ODP Hadoop platform artifact; remediation "
            "belongs to Hadoop. Exception Request (Deferred)."
        )

    if "jetty" in pkg:
        return "exception", (
            "Jetty CVE fix is only on 12.x; stack stays on 9.4.x. "
            "Exception Request (Deferred)."
        )

    if "ranger-plugins-common" in pkg or "ranger-nifi-registry" in pkg:
        return "exception", (
            "Advisory fix requires Ranger 2.8.0 (component minor-line upgrade), "
            "out of scope for a dependency CVE bump on 2.5.0.3.3.6.x. "
            "Exception Request (Deferred)."
        )

    if "elasticsearch" in pkg:
        return "exception", (
            "Elasticsearch 7.17.x fixes are only published on 8.x/9.x; upgrading "
            "the ES client line is out of scope. Exception Request (Deferred)."
        )

    if "aircompressor" in pkg:
        return "exception", (
            "aircompressor fix is only on 2.0.x while Ranger pins 0.27; major-line "
            "bump is out of scope. Exception Request (Deferred)."
        )

    if "bouncycastle" in pkg or "bcprov" in pkg or "bcpkix" in pkg:
        return "exception", (
            "bcprov/bcpkix-jdk15on line ends at 1.70 on Maven Central; advisory "
            "fixes are on bcprov-jdk18on 1.78+. Artifact migration is out of "
            "scope for this bump. Exception Request (Deferred)."
        )

    if "commons-configuration" in pkg and "configuration2" not in pkg:
        return "exception", (
            "commons-configuration 1.10 has no published fix (ticket fix field "
            "open). Exception Request (Deferred)."
        )

    if "okio" in pkg:
        return "exception", (
            "okio is not managed via a Ranger root property; jar appears as a "
            "transitive/standalone copy. Exception Request (Deferred)."
        )

    if "underscore" in pkg:
        return "exception", (
            "underscore is a JS UI dependency without a managed Maven property "
            "bump path in this delivery. Exception Request (Deferred)."
        )

    if "spring" in pkg and "jersey-spring" not in pkg:
        return "exception", (
            "Spring Framework / Spring Security CVEs on the 5.3 / 5.7 lines "
            "either require unpublished 5.3.41, Spring 6.x (jakarta), or have "
            "no same-major fix. Exception Request (Deferred)."
        )

    # --- fixable ---
    if "tomcat" in pkg:
        return "fix_tomcat", {"lib": "tomcat", "target": TARGETS["tomcat"][1], "name": TARGETS["tomcat"][2]}

    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {"lib": "lang3", "target": TARGETS["lang3"][1], "name": TARGETS["lang3"][2]}

    if "commons-configuration2" in pkg or "commons_configuration2" in pkg:
        return "fix_config2", {"lib": "config2", "target": TARGETS["config2"][1], "name": TARGETS["config2"][2]}

    if "nimbus" in pkg:
        return "fix_nimbus", {"lib": "nimbus", "target": TARGETS["nimbus"][1], "name": TARGETS["nimbus"][2]}

    if "logback" in pkg:
        if has_prefix_fix(fix, ("1.3.",)):
            return "fix_logback", {"lib": "logback", "target": TARGETS["logback"][1], "name": TARGETS["logback"][2]}
        return "exception", (
            "logback-core CVE fix is only on 1.5.x; Ranger stays on 1.3.x line. "
            "Exception Request (Deferred)."
        )

    if "poi" in pkg:
        return "fix_poi", {"lib": "poi", "target": TARGETS["poi"][1], "name": TARGETS["poi"][2]}

    if "opentelemetry" in pkg:
        return "fix_otel", {"lib": "otel", "target": TARGETS["otel"][1], "name": TARGETS["otel"][2]}

    return "unknown", f"No rule for {pkg} path={path}"


def ensure_ambari_wrap():
    """Shim expected by ranger-util antrun (from jackson matrix)."""
    wrap = Path("/usr/bin/ambari-python-wrap")
    if wrap.exists():
        return
    # local shim in PATH
    shim = Path("/tmp/ambari-python-wrap")
    shim.write_text("#!/bin/sh\nexec python3 \"$@\"\n", encoding="utf-8")
    shim.chmod(0o755)
    # also try /usr/bin if writable
    try:
        if not wrap.exists():
            wrap.write_text("#!/bin/sh\nexec python3 \"$@\"\n", encoding="utf-8")
            wrap.chmod(0o755)
    except Exception:
        pass
    os.environ["PATH"] = f"/tmp:{os.environ.get('PATH', '')}"


def ensure_repo():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", WORK, env=env, timeout=600)
    ensure_ambari_wrap()


def apply_lib(lib: str) -> list[str]:
    prop, ver, _, _ = TARGETS[lib]
    pom = WORK / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    pat = rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)"
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n != 1:
        raise RuntimeError(f"property {prop} not found in pom.xml")
    pom.write_text(text2, encoding="utf-8")
    return ["pom.xml"]


def compile_lib(lib: str) -> bool:
    ensure_ambari_wrap()
    pl = BUILD_PL.get(lib, "agents-common")
    log = f"/tmp/ranger_cve_{lib}_build.log"
    cmd = (
        f"mvn -Dmaven.test.skip=true -DskipJSTests -DskipTests -Drat.skip=true "
        f"-Dmaven.javadoc.skip=true -Denforcer.skip=true -Dcheckstyle.skip=true "
        f"-Pall,ranger-jdk11 -pl {pl} -am package"
    )
    code, out, err = run(cmd, WORK, timeout=TIMEOUT, log_path=log)
    if code != 0:
        for ln in (out + err).splitlines()[-50:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
    # verify property
    prop, ver, _, _ = TARGETS[lib]
    pom = (WORK / "pom.xml").read_text(encoding="utf-8")
    m = re.search(rf"<{re.escape(prop)}>([^<]+)</{re.escape(prop)}>", pom)
    if not m or m.group(1) != ver:
        print(f"  FAIL: pom {prop} expected {ver} got {m.group(1) if m else None}", flush=True)
        return False
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


def deliver_lib(ca, lib: str, tickets: list[dict]):
    if not tickets:
        return None
    prop, ver, name, _ = TARGETS[lib]
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    cve_str = "/".join(cves[:6]) + ("/..." if len(cves) > 6 else "")
    title = f"{branch} - CVE - Bumped-up {name} to {ver} to address {cve_str or 'CVE'}"

    print(f"\n=== DELIVER {lib} ({len(tickets)}) branch={branch} ===", flush=True)
    ensure_repo()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_lib(lib)
    write_status(delivering=lib, branch=branch, tickets=[t["key"] for t in tickets])

    if DRY:
        return {"lib": lib, "dry": True, "title": title, "tickets": [t["key"] for t in tickets]}

    if not compile_lib(lib):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "branch": branch}

    run("git add pom.xml", WORK, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(WORK), text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        return {"lib": lib, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", WORK, timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: ranger ({BASE}, release {RELEASE})",
        f"- Property: `{prop}` → `{ver}`",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Advisories: {', '.join(cves) if cves else 'n/a'}",
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}

    closed = []
    for t in tickets:
        ok = ca.close_ticket_with_comment(
            t["key"],
            f"Fixed via PR: {pr} — bumped {name} ({prop}) to {ver} on {BASE}.",
            "Closed",
            assignee=ASSIGNEE,
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
    write_status(phase="loaded", count=len(rows))

    excepted, fixable, unknown = [], [], []
    for row in rows:
        action, meta = classify(row)
        if action == "exception":
            print(f"EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE
                )
                (excepted if ok else unknown).append(row["key"])
        elif action.startswith("fix_"):
            print(
                f"FIXABLE {row['key']} {row['pkg']} -> {meta.get('target')} ({meta.get('lib')})",
                flush=True,
            )
            fixable.append({**row, **meta})
        else:
            print(f"UNKNOWN {row['key']} {meta}", flush=True)
            unknown.append(row["key"])

    write_status(
        phase="routed",
        excepted=excepted,
        fixable=[r["key"] for r in fixable],
        unknown=unknown,
    )
    results = {
        "excepted": excepted,
        "closed": [],
        "prs": [],
        "unknown": unknown,
        "errors": [],
    }
    write_summary(results)

    if ROUTE_ONLY:
        write_status(phase="ROUTE_ONLY_DONE")
        return

    by_lib: dict[str, list] = {}
    for r in fixable:
        by_lib.setdefault(r["lib"], []).append(r)

    for lib in ("tomcat", "lang3", "config2", "nimbus", "logback", "poi", "otel"):
        if lib not in LIB_FILTER:
            continue
        if lib not in by_lib:
            print(f"SKIP {lib} (no tickets)", flush=True)
            continue
        try:
            res = deliver_lib(ca, lib, by_lib[lib])
        except Exception as e:
            res = {"lib": lib, "ok": False, "error": str(e)[:400]}
            print(f"ERROR {lib}: {e}", flush=True)
        if res and res.get("pr"):
            results["prs"].append(res["pr"])
            results["closed"].extend(res.get("closed") or [])
        elif res and not res.get("ok", True) and not res.get("dry"):
            results["errors"].append(res)
        write_summary(results)
        write_status(phase=f"after_{lib}", results=results)

    write_status(phase="DONE", results=results)
    write_summary(results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        write_status(phase="ERROR", error=str(e)[:800])
        raise
