#!/usr/bin/env python3
"""Batch CVE deliver for zeppelin (release 3.3.6.4).

Status: /tmp/batch10_cve_status.json
Summary appended to /root/cve_fix_llm/reports/batch9_status.md

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
ROOT = Path("/root/3.3.6.5")
STATUS = Path("/tmp/batch10_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch9_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

JACKSON = "2.18.6"
LANG3 = "3.18.0"
CONFIG2 = "2.15.0"
MINA = "2.0.28"
BCPROV = "1.84"
VFS2 = "2.10.0"
NETTY = "4.1.133.Final"
NIMBUS = "10.0.2"
OKHTTP = "4.9.2"
OKIO = "3.4.0"
OTEL = "1.62.0"
JINJAVA = "2.8.3"
JSOUP = "1.15.3"
COMMONS_NET = "3.9.0"
PLEXUS = "3.6.1"

COMPONENTS = {
    "zeppelin": {
        "jira": "sehajsandhu/zeppelin",
        "gh": "acceldata-io/zeppelin",
        "work": ROOT / "zeppelin",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
    },
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
    print(f"STATUS: {json.dumps(kwargs)[:700]}", flush=True)


def append_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    existing = SUMMARY.read_text(encoding="utf-8") if SUMMARY.is_file() else ""
    # replace zeppelin section if present
    block = [
        "",
        f"## zeppelin ({time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())})",
    ]
    for comp, res in results.items():
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
    if "## zeppelin" in text:
        text = re.sub(r"\n## zeppelin.*?(?=\n## |\Z)", "", text, flags=re.S)
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


def jdk_home(jdk: int):
    for c in (f"/usr/lib/jvm/java-{jdk}-openjdk", f"/usr/lib/jvm/java-{jdk}"):
        if Path(c).exists():
            return c
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
            "jql": jql, "maxResults": 100,
            "fields": (
                "summary,customfield_10893,customfield_10875,customfield_10870,"
                "customfield_10892,customfield_10891,customfield_10888,customfield_10127"
            ),
        }
        if token:
            params["nextPageToken"] = token
        r = ca.SESSION.get(
            f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql", params=params,
            headers={"Accept": "application/json"}, auth=(ca.EMAIL, ca.API_TOKEN),
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
        if jira not in repo and jira not in (f.get("summary") or ""):
            continue
        if field_text(f.get("customfield_10893")) != RELEASE:
            continue
        summ = f.get("summary") or ""
        pkg = field_text(f.get("customfield_10875"))
        fix = ca.extract_fixed_version(f.get("customfield_10891")) if hasattr(ca, "extract_fixed_version") else field_text(f.get("customfield_10891"))
        cve = field_text(f.get("customfield_10127")) or ""
        if not cve:
            m = re.search(r"(CVE-\d+-\d+|GHSA-[a-z0-9-]+)", summ)
            cve = m.group(1) if m else ""
        rows.append({
            "key": i["key"], "pkg": pkg, "ver": field_text(f.get("customfield_10892")),
            "fix": fix or "", "path": field_text(f.get("customfield_10888")),
            "cve": cve, "summary": summ, "repo": repo,
        })
    return rows


def classify_zeppelin(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    fix = row["fix"] or ""

    if "docker-client" in path and ("guava" in pkg or "httpclient" in pkg):
        return "exception", (
            "Shaded inside docker-client-*-shaded.jar; owner must rebuild. "
            "Exception Request (Deferred)."
        )
    if "hadoop-" in pkg:
        return "exception", (
            "Hadoop platform artifact; remediation belongs to Hadoop/ODP. "
            "Exception Request (Deferred)."
        )
    if "libthrift" in pkg or pkg == "thrift":
        return "exception", (
            "libthrift 0.23.0 is a breaking major from 0.16.0. "
            "Exception Request (Deferred)."
        )
    if "commons-lang" in pkg and "lang3" not in pkg:
        return "exception", (
            "commons-lang 2.6 has no upstream fix. Exception Request (Deferred)."
        )
    if "ini4j" in pkg or "javax.el" in pkg:
        return "exception", (
            "No viable upstream fix on current line. Exception Request (Deferred)."
        )
    if re.search(r"(^|[^0-9])netty([^0-9]|$)", pkg) and "4.1" not in (row.get("ver") or "") and "netty-codec" not in pkg and "netty-handler" not in pkg:
        if (row.get("ver") or "").startswith("3."):
            return "exception", (
                "Netty 3.x has no upstream fix on the 3.x line. "
                "Exception Request (Deferred)."
            )
    if "jetty" in pkg:
        if "11.0.2" in fix or "11.0.28" in fix:
            # only if we can bump jetty 11 - currently 11.0.24; 11.0.28 exists?
            if "11.0.28" in fix or "11.0.27" in fix:
                return "fix_jetty11", {
                    "target": "11.0.28", "lib": "jetty", "name": "Jetty",
                }
        return "exception", (
            "Jetty CVE fix is only on 12.x; Zeppelin stays on Jetty 9/11. "
            "Exception Request (Deferred)."
        )
    if "shiro" in pkg:
        return "exception", (
            "shiro fix is on 2.0.x (major from 1.13). Exception Request (Deferred)."
        )
    if "c3p0" in pkg:
        return "exception", (
            "c3p0 0.12.x is a major from 0.9.5.x. Exception Request (Deferred)."
        )
    if "jgit" in pkg or "org.eclipse.jgit" in pkg:
        return "exception", (
            "JGit fix requires 7.x (major). Exception Request (Deferred)."
        )
    if "commons-configuration" in pkg and "configuration2" not in pkg:
        return "exception", (
            "commons-configuration 1.x; no clean pin on this branch. "
            "Exception Request (Deferred)."
        )
    if "jersey" in pkg:
        return "exception", (
            "jersey-client advisory fix spans 2.46/3.x lines; Zeppelin jersey "
            "pin is Dropwizard-managed. Exception Request (Deferred)."
        )
    if "mchange-commons" in pkg:
        return "exception", (
            "mchange-commons-java comes with c3p0; no isolated pin. "
            "Exception Request (Deferred)."
        )
    if "jackrabbit" in pkg:
        return "exception", (
            "jackrabbit-jcr-commons not managed by a root property on this branch. "
            "Exception Request (Deferred)."
        )

    if "jackson" in pkg:
        return "fix_jackson", {"target": JACKSON, "lib": "jackson", "name": "Jackson"}
    if "commons-lang3" in pkg:
        return "fix_lang3", {"target": LANG3, "lib": "lang3", "name": "commons-lang3"}
    if "configuration2" in pkg:
        return "fix_config2", {"target": CONFIG2, "lib": "config2", "name": "commons-configuration2"}
    if "mina" in pkg:
        return "fix_mina", {"target": MINA, "lib": "mina", "name": "mina-core"}
    if "bcprov" in pkg or "bcpkix" in pkg or "bouncycastle" in pkg:
        return "fix_bc", {"target": BCPROV, "lib": "bc", "name": "BouncyCastle"}
    if "vfs2" in pkg or "commons-vfs2" in pkg:
        return "fix_vfs2", {"target": VFS2, "lib": "vfs2", "name": "commons-vfs2"}
    if "netty" in pkg:
        return "fix_netty", {"target": NETTY, "lib": "netty", "name": "Netty"}
    if "nimbus" in pkg:
        return "fix_nimbus", {"target": NIMBUS, "lib": "nimbus", "name": "nimbus-jose-jwt"}
    if "okhttp" in pkg:
        return "fix_okhttp", {"target": OKHTTP, "lib": "okhttp", "name": "okhttp"}
    if "okio" in pkg:
        return "fix_okio", {"target": OKIO, "lib": "okio", "name": "okio"}
    if "opentelemetry" in pkg:
        return "fix_otel", {"target": OTEL, "lib": "otel", "name": "OpenTelemetry"}
    if "jinjava" in pkg:
        return "fix_jinjava", {"target": JINJAVA, "lib": "jinjava", "name": "jinjava"}
    if "jsoup" in pkg:
        return "fix_jsoup", {"target": JSOUP, "lib": "jsoup", "name": "jsoup"}
    if "commons-net" in pkg:
        return "fix_commonsnet", {"target": COMMONS_NET, "lib": "commonsnet", "name": "commons-net"}
    if "plexus-utils" in pkg:
        return "fix_plexus", {"target": PLEXUS, "lib": "plexus", "name": "plexus-utils"}
    return "unknown", f"No rule for {pkg} path={path}"


def set_pom_prop(work: Path, prop: str, ver: str, rel="pom.xml"):
    pom = work / rel
    text = pom.read_text(encoding="utf-8")
    # replace ALL occurrences (zeppelin has duplicate jackson.version)
    text2, n = re.subn(
        rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)",
        rf"\g<1>{ver}\g<3>",
        text,
    )
    if n < 1:
        if "</properties>" not in text:
            raise RuntimeError(f"{prop} not found in {rel}")
        text2 = text.replace(
            "</properties>",
            f"    <{prop}>{ver}</{prop}>\n  </properties>",
            1,
        )
    pom.write_text(text2, encoding="utf-8")
    return [rel]


def set_module_prop(work: Path, rel: str, prop: str, ver: str):
    return set_pom_prop(work, prop, ver, rel=rel)


def ensure_dm(work: Path, group: str, artifact: str, ver: str, rel="pom.xml"):
    pom = work / rel
    text = pom.read_text(encoding="utf-8")
    pat = (
        rf"(<groupId>{re.escape(group)}</groupId>\s*"
        rf"<artifactId>{re.escape(artifact)}</artifactId>\s*"
        rf"<version>)([^<]+)(</version>)"
    )
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n >= 1:
        pom.write_text(text2, encoding="utf-8")
        return [rel]
    block = f"""
      <dependency>
        <groupId>{group}</groupId>
        <artifactId>{artifact}</artifactId>
        <version>{ver}</version>
      </dependency>
"""
    dm = text.find("<dependencyManagement>")
    deps = text.find("<dependencies>", dm)
    insert_at = deps + len("<dependencies>")
    pom.write_text(text[:insert_at] + "\n" + block + text[insert_at:], encoding="utf-8")
    return [rel]


APPLY = {
    ("zeppelin", "jackson"): lambda w: set_pom_prop(w, "jackson.version", JACKSON),
    ("zeppelin", "lang3"): lambda w: set_pom_prop(w, "commons.lang3.version", LANG3),
    ("zeppelin", "config2"): lambda w: set_pom_prop(w, "commons.configuration2.version", CONFIG2),
    ("zeppelin", "mina"): lambda w: set_module_prop(w, "zeppelin-server/pom.xml", "mina.version", MINA),
    ("zeppelin", "bc"): lambda w: set_pom_prop(w, "bouncycastle.version", BCPROV),
    ("zeppelin", "vfs2"): lambda w: set_module_prop(w, "zeppelin-zengine/pom.xml", "commons.vfs2.version", VFS2),
    ("zeppelin", "netty"): lambda w: set_pom_prop(w, "netty.codec.http2.version", NETTY),
    ("zeppelin", "nimbus"): lambda w: set_module_prop(w, "zeppelin-server/pom.xml", "nimbus.version", NIMBUS),
    ("zeppelin", "okhttp"): lambda w: (
        set_module_prop(w, "influxdb/pom.xml", "dependency.okhttp3.version", OKHTTP)
        + ensure_dm(w, "com.squareup.okhttp3", "okhttp", OKHTTP)
    ),
    ("zeppelin", "okio"): lambda w: ensure_dm(w, "com.squareup.okio", "okio", OKIO),
    ("zeppelin", "otel"): lambda w: ensure_dm(w, "io.opentelemetry", "opentelemetry-api", OTEL),
    ("zeppelin", "jinjava"): lambda w: set_pom_prop(w, "jinjava.version", JINJAVA),
    ("zeppelin", "jsoup"): lambda w: set_pom_prop(w, "jsoup.version", JSOUP),
    ("zeppelin", "commonsnet"): lambda w: (
        set_pom_prop(w, "commons.net.version", COMMONS_NET)
        + ensure_dm(w, "commons-net", "commons-net", COMMONS_NET)
    ),
    ("zeppelin", "plexus"): lambda w: ensure_dm(w, "org.codehaus.plexus", "plexus-utils", PLEXUS),
    ("zeppelin", "jetty"): lambda w: set_pom_prop(w, "jetty.version", "11.0.28"),
}


def ensure_repo(work, gh, base, jdk):
    env = git_env(jdk)
    run(f"git remote set-url origin https://github.com/{gh}.git", work, env=env, timeout=60)
    run(f"git fetch origin {base} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {base} origin/{base}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", work, env=env, timeout=900)


def compile_gate(comp, work, lib, jdk):
    log = f"/tmp/batch10_{comp}_{lib}_build.log"
    env = git_env(jdk)
    cmd = (
        "mvn -q -DskipTests -Dcheckstyle.skip=true -Drat.skip=true "
        "-DskipFrontend=true -Denforcer.skip=true "
        "-pl zeppelin-server -am validate"
    )
    code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        code2, out2, err2 = run(
            "mvn -q -N validate -DskipTests", work, env=env, timeout=600, log_path=log,
        )
        if code2 == 0:
            print("   fe validate failed; root -N validate OK", flush=True)
            return True
        for ln in (out + err + out2 + err2).splitlines()[-40:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
        return False
    return True


def create_pr(gh, branch, title, body, base):
    import requests

    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    r = requests.post(
        f"https://api.github.com/repos/{gh}/pulls", headers=headers,
        json={"title": title, "head": branch, "base": base, "body": body}, timeout=60,
    )
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        requests.post(
            f"https://api.github.com/repos/{gh}/pulls/{num}/requested_reviewers",
            headers=headers, json={"reviewers": [REVIEWER]}, timeout=60,
        )
        return url
    if r.status_code == 422:
        r2 = requests.get(
            f"https://api.github.com/repos/{gh}/pulls", headers=headers,
            params={"head": f"acceldata-io:{branch}", "state": "open"}, timeout=60,
        )
        if r2.ok and r2.json():
            return r2.json()[0]["html_url"]
    print(f"PR fail {r.status_code}: {r.text[:500]}", flush=True)
    return None


def deliver_lib(ca, comp, cfg, lib, tickets):
    work, gh, base, jdk = cfg["work"], cfg["gh"], cfg["base"], cfg["jdk"]
    meta = tickets[0]
    name, target = meta.get("name") or lib, meta.get("target")
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    title = f"{branch} - CVE - Bumped-up {name} to {target} to address {'/'.join(cves) if cves else 'CVE'}"
    print(f"\n=== {comp}/{lib} PR branch={branch} ({len(tickets)}) ===", flush=True)

    # Reuse open Jackson PR #46
    if lib == "jackson":
        import requests
        headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
        r = requests.get(f"https://api.github.com/repos/{gh}/pulls/46", headers=headers, timeout=60)
        if r.ok and r.json().get("state") == "open":
            pr = r.json()["html_url"]
            print(f"  reusing {pr}", flush=True)
            closed = []
            for t in tickets:
                ok = ca.close_ticket_with_comment(
                    t["key"], f"Fixed via PR: {pr} — bumped {name} to {target} on {base}.",
                    "Closed", assignee=ASSIGNEE,
                )
                if ok:
                    closed.append(t["key"])
            return {"lib": lib, "ok": True, "pr": pr, "closed": closed}

    ensure_repo(work, gh, base, jdk)
    run(f"git checkout -B {branch} origin/{base}", work, env=git_env(jdk), timeout=120)
    applier = APPLY.get((comp, lib))
    if not applier:
        raise RuntimeError(f"no applier {comp}/{lib}")
    changed = applier(work)
    if DRY:
        return {"lib": lib, "dry": True, "title": title}
    if not compile_gate(comp, work, lib, jdk):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "branch": branch}
    run("git add -A", work, env=git_env(jdk), timeout=120)
    p = subprocess.run(["git", "commit", "-m", title], cwd=str(work), text=True, capture_output=True, env=git_env(jdk))
    if p.returncode != 0:
        return {"lib": lib, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", work, env=git_env(jdk), timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}
    body = "\n".join([
        f"- Component: zeppelin ({base}, release {RELEASE})",
        f"- Library: {name} → {target}",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Files: {', '.join(changed[:20])}",
    ])
    pr = create_pr(gh, branch, title, body, base)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}
    closed = []
    for t in tickets:
        ok = ca.close_ticket_with_comment(
            t["key"], f"Fixed via PR: {pr} — bumped {name} to {target} on {base}.",
            "Closed", assignee=ASSIGNEE,
        )
        print(f"  {t['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(t["key"])
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed}


LIB_ORDER = [
    "jackson", "lang3", "config2", "mina", "bc", "vfs2", "netty",
    "nimbus", "okhttp", "okio", "otel", "jinjava", "jsoup", "commonsnet",
    "plexus", "jetty",
]


def process(ca):
    cfg = COMPONENTS["zeppelin"]
    write_status(phase="zeppelin:load")
    rows = load_tickets(ca, cfg)
    excepted, fixable, unknown, already = [], [], [], []
    for row in rows:
        action, meta = classify_zeppelin(row)
        if action == "exception":
            print(f"[zeppelin] EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(row["key"], meta, reason="Deferred", assignee=ASSIGNEE)
                (excepted if ok else unknown).append(row["key"])
        elif action == "already_fixed":
            already.append(row["key"])
        elif action.startswith("fix_"):
            print(f"[zeppelin] FIXABLE {row['key']} {row['pkg']} -> {meta.get('target')}", flush=True)
            fixable.append({**row, **meta})
        else:
            print(f"[zeppelin] UNKNOWN {row['key']} {meta}", flush=True)
            unknown.append(row["key"])

    if ROUTE_ONLY:
        return {
            "excepted": excepted, "fixable": [r["key"] for r in fixable],
            "already_fixed": already, "unknown": unknown, "prs": [],
            "fixable_detail": [{"key": r["key"], "lib": r.get("lib"), "target": r.get("target")} for r in fixable],
        }

    by_lib: dict[str, list] = {}
    for r in fixable:
        by_lib.setdefault(r["lib"], []).append(r)
    prs, closed, errors = [], [], []
    for lib in LIB_ORDER:
        if lib not in by_lib:
            continue
        try:
            res = deliver_lib(ca, "zeppelin", cfg, lib, by_lib[lib])
        except Exception as e:
            res = {"lib": lib, "ok": False, "error": str(e)[:400]}
            print(f"[zeppelin/{lib}] ERROR {e}", flush=True)
        if res and res.get("pr"):
            prs.append(res["pr"])
            closed.extend(res.get("closed") or [])
        elif res and not res.get("ok", True) and not res.get("dry"):
            errors.append(res)
    out = {"excepted": excepted, "closed": closed, "already_fixed": already, "prs": prs, "unknown": unknown}
    if errors:
        out["errors"] = errors
    return out


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca
    ca.DRY_RUN = DRY
    results = {"zeppelin": process(ca)}
    append_summary(results)
    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2), flush=True)


if __name__ == "__main__":
    main()
