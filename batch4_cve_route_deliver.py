#!/usr/bin/env python3
"""Batch CVE deliver for phoenix, cruise-control, kafka, cruise-control3 (3.3.6.4).

Separate PR per library. Status: /tmp/batch4_cve_status.json
Summary: /root/cve_fix_llm/reports/batch4_status.md

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_COMPONENTS=phoenix,kafka
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
BASE = "nightly/ODP-3.3.6.5"
ROOT = Path("/root/3.3.6.5")
STATUS = Path("/tmp/batch4_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch4_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
TOKEN = ""
JDK = 11

LANG3 = "3.18.0"
NIMBUS = "10.0.2"
VERTX = "4.5.24"

COMPONENTS = {
    "phoenix": {
        "jira": "sehajsandhu/phoenix",
        "gh": "acceldata-io/phoenix",
        "work": ROOT / "phoenix",
    },
    "cruise-control": {
        "jira": "sehajsandhu/cruise-control",
        "gh": "acceldata-io/cruise-control",
        "work": ROOT / "cruise-control",
        # exclude cruise-control3 tickets matched by substring
        "exclude_jira_substr": "cruise-control3",
    },
    "kafka": {
        "jira": "sehajsandhu/kafka",
        "gh": "acceldata-io/kafka",
        "work": ROOT / "kafka",
        "exclude_jira_substr": "kafka3",
    },
    "cruise-control3": {
        "jira": "sehajsandhu/cruise-control3",
        "gh": "acceldata-io/cruise-control3",
        "work": ROOT / "cruise-control3",
    },
}

FILTER = [
    c.strip()
    for c in os.environ.get(
        "CVE_COMPONENTS", "phoenix,cruise-control,kafka,cruise-control3"
    ).split(",")
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
    print(f"STATUS: {json.dumps(kwargs)[:600]}", flush=True)


def write_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Batch4 CVE status ({RELEASE} → {BASE})",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        "",
    ]
    for comp, res in results.items():
        lines.append(f"## {comp}")
        lines.append(f"- excepted: {', '.join(res.get('excepted') or []) or '—'}")
        lines.append(f"- closed: {', '.join(res.get('closed') or []) or '—'}")
        for pr in res.get("prs") or []:
            lines.append(f"- PR: {pr}")
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


def classify(comp: str, row: dict):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()

    if "hadoop-common" in pkg:
        return "exception", (
            "hadoop-common is the ODP Hadoop platform artifact; remediation "
            "belongs to the Hadoop component. Exception Request (Deferred)."
        )

    if "jetty" in pkg:
        return "exception", (
            "Jetty CVE fix is only published on 12.x; component stays on "
            "Jetty 9.4.x (javax stack) with no same-major 9.4.x fix. "
            "Exception Request (Deferred)."
        )

    if "logback" in pkg:
        return "exception", (
            "logback-core is on the 1.3.x line; advisory fix is only on 1.5.x. "
            "Crossing 1.3→1.5 is not a safe pin for this component. "
            "Exception Request (Deferred)."
        )

    # Shaded connector / uber jars in kafka libs
    if comp == "kafka" and any(
        x in path
        for x in (
            "pubsub-group-kafka-connector",
            "amazon-kinesis-kafka-connecter",
            "camel-aws-sqs",
            "uber-kafka",
        )
    ):
        return "exception", (
            f"Flagged inside connector/uber jar ({Path(path).name}), not a "
            "Kafka-managed standalone dependency pin. Exception Request (Deferred)."
        )

    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {"target": LANG3, "lib": "lang3", "name": "commons-lang3"}

    if "nimbus" in pkg:
        return "fix_nimbus", {"target": NIMBUS, "lib": "nimbus", "name": "nimbus-jose-jwt"}

    if "vertx" in pkg:
        return "fix_vertx", {"target": VERTX, "lib": "vertx", "name": "vertx"}

    return "unknown", f"No rule for {pkg} path={path}"


def ensure_repo(work: Path, gh: str):
    env = git_env()
    run(f"git remote set-url origin https://github.com/{gh}.git", work, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", work, env=env, timeout=600)


def apply_phoenix_lang3(work: Path):
    pom = work / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<commons-lang3\.version>)([^<]+)(</commons-lang3\.version>)",
        rf"\g<1>{LANG3}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("phoenix commons-lang3.version not found")
    pom.write_text(text2, encoding="utf-8")
    return ["pom.xml"]


def apply_cc_lang3(work: Path):
    """Force commons-lang3 via resolutionStrategy (transitive from kafka)."""
    bg = work / "build.gradle"
    text = bg.read_text(encoding="utf-8")
    force_line = f"       force 'org.apache.commons:commons-lang3:{LANG3}'\n"
    if f"commons-lang3:{LANG3}" in text:
        return []
    # Insert after existing slf4j force inside first configurations.all resolutionStrategy
    text2, n = re.subn(
        r"(force 'org\.slf4j:slf4j-api:[^']+'\n)",
        rf"\1{force_line}",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("could not insert commons-lang3 force in build.gradle")
    # Also add explicit api dep near nimbus if present, for clarity in dependant-libs
    if "commons-lang3:" not in text2:
        text2 = text2.replace(
            "api 'com.nimbusds:nimbus-jose-jwt:",
            f"api 'org.apache.commons:commons-lang3:{LANG3}'\n    api 'com.nimbusds:nimbus-jose-jwt:",
            1,
        )
        text2 = text2.replace(
            "implementation 'com.nimbusds:nimbus-jose-jwt:",
            f"implementation 'org.apache.commons:commons-lang3:{LANG3}'\n    implementation 'com.nimbusds:nimbus-jose-jwt:",
            1,
        )
    bg.write_text(text2, encoding="utf-8")
    return ["build.gradle"]


def apply_cc_nimbus(work: Path):
    bg = work / "build.gradle"
    text = bg.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(nimbus-jose-jwt:)([0-9.]+)",
        rf"\g<1>{NIMBUS}",
        text,
    )
    if n < 1:
        raise RuntimeError("nimbus-jose-jwt pin not found")
    bg.write_text(text2, encoding="utf-8")
    return ["build.gradle"]


def apply_cc3_vertx(work: Path):
    gp = work / "gradle.properties"
    text = gp.read_text(encoding="utf-8")
    text2, n = re.subn(r"(vertxVersion=)([^\n]+)", rf"\g<1>{VERTX}", text, count=1)
    if n != 1:
        raise RuntimeError("vertxVersion not found")
    gp.write_text(text2, encoding="utf-8")
    return ["gradle.properties"]


def apply_kafka_lang3(work: Path):
    bg = work / "build.gradle"
    text = bg.read_text(encoding="utf-8")
    needle = "force(\n"
    insert = f'            "org.apache.commons:commons-lang3:{LANG3}",\n'
    if f"commons-lang3:{LANG3}" in text:
        return []
    # Prefer adding inside existing force( block near javassist
    if "libs.javassist" in text and insert.strip() not in text:
        text2 = text.replace(
            "libs.javassist,\n",
            f"libs.javassist,\n{insert}",
            1,
        )
        if text2 == text:
            raise RuntimeError("failed to insert kafka lang3 force")
        bg.write_text(text2, encoding="utf-8")
        return ["build.gradle"]
    raise RuntimeError("kafka force() block not found")


APPLY = {
    ("phoenix", "lang3"): apply_phoenix_lang3,
    ("cruise-control", "lang3"): apply_cc_lang3,
    ("cruise-control", "nimbus"): apply_cc_nimbus,
    ("cruise-control3", "lang3"): apply_cc_lang3,
    ("cruise-control3", "nimbus"): apply_cc_nimbus,
    ("cruise-control3", "vertx"): apply_cc3_vertx,
    ("kafka", "lang3"): apply_kafka_lang3,
}


def compile_gate(comp: str, work: Path, lib: str) -> bool:
    log = f"/tmp/batch4_{comp}_{lib}_build.log"
    env = git_env()
    if comp == "phoenix":
        cmd = (
            "mvn -q -DskipTests -Dhbase.profile=2.6 -Drat.skip=true "
            "-Denforcer.skip=true -Dcheckstyle.skip=true "
            "-pl phoenix-pherf -am package"
        )
        code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    elif comp in ("cruise-control", "cruise-control3"):
        # semantic-versioning plugin needs a semver git tag (bigtop tags before build)
        tag = "2.5.141" if comp == "cruise-control" else "2.5.137"
        run(f"git tag -f {tag}", work, env=env, timeout=30)
        # copyDependantLibs pulls testRuntimeClasspath (needs kafka *-test.jar);
        # gate on main jars + dependency resolution instead.
        cmd = (
            "./gradlew :cruise-control-core:jar :cruise-control-metrics-reporter:jar "
            ":cruise-control:jar -x test -x copyDependantLibs -x compileTestJava "
            "-x compileTestScala --no-daemon"
        )
        code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
        if code == 0 and lib == "lang3":
            c2, o2, _ = run(
                "./gradlew -q :cruise-control:dependencies --configuration runtimeClasspath",
                work, env=env, timeout=600,
            )
            print("  lang3 deps:\n  " + "\n  ".join(
                ln for ln in (o2 or "").splitlines() if "commons-lang3" in ln
            )[:800], flush=True)
            if LANG3 not in (o2 or ""):
                print(f"  FAIL: runtimeClasspath missing commons-lang3:{LANG3}", flush=True)
                code = 1
        if code == 0 and lib == "nimbus":
            c2, o2, _ = run(
                "./gradlew -q :cruise-control:dependencies --configuration runtimeClasspath",
                work, env=env, timeout=600,
            )
            if NIMBUS not in (o2 or ""):
                print(f"  FAIL: runtimeClasspath missing nimbus-jose-jwt:{NIMBUS}", flush=True)
                code = 1
        if code == 0 and lib == "vertx":
            c2, o2, _ = run(
                "./gradlew -q :cruise-control-core:dependencies --configuration runtimeClasspath",
                work, env=env, timeout=600,
            )
            if VERTX not in (o2 or ""):
                print(f"  FAIL: runtimeClasspath missing vertx:{VERTX}", flush=True)
                code = 1
    elif comp == "kafka":
        # Full :connect:runtime:jar needs missing aiven SNAPSHOT; gate via deps + clients.
        cmd = "./gradlew :clients:jar -x test --no-daemon"
        code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
        if code == 0 and lib == "lang3":
            c2, o2, _ = run(
                "./gradlew -q :connect:runtime:dependencies --configuration compileClasspath",
                work, env=env, timeout=900,
            )
            print("  lang3 deps:\n  " + "\n  ".join(
                ln for ln in (o2 or "").splitlines() if "commons-lang3" in ln
            )[:800], flush=True)
            if LANG3 not in (o2 or "") and f"-> {LANG3}" not in (o2 or ""):
                # accept either direct or forced arrow form
                if not re.search(rf"commons-lang3.*{re.escape(LANG3)}", o2 or ""):
                    print(f"  FAIL: compileClasspath missing commons-lang3:{LANG3}", flush=True)
                    code = 1
    else:
        raise RuntimeError(comp)
    if code != 0:
        for ln in (out + err).splitlines()[-40:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
    return code == 0


def create_pr(gh, branch, title, body):
    import requests

    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    r = requests.post(
        f"https://api.github.com/repos/{gh}/pulls",
        headers=headers,
        json={"title": title, "head": branch, "base": BASE, "body": body},
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
    print(f"PR fail {r.status_code}: {r.text[:400]}", flush=True)
    return None


def deliver_lib(ca, comp, cfg, lib, tickets):
    if not tickets:
        return None
    work = cfg["work"]
    gh = cfg["gh"]
    meta = tickets[0]
    name = meta.get("name") or lib
    target = meta.get("target")
    branch = tickets[0]["key"]
    cves = sorted({t["cve"] for t in tickets if t.get("cve")})
    cve_str = "/".join(cves) if cves else "CVE"
    title = f"{branch} - CVE - Bumped-up {name} to {target} to address {cve_str}"

    print(f"\n=== {comp}/{lib} PR branch={branch} ({len(tickets)} tickets) ===", flush=True)
    ensure_repo(work, gh)
    run(f"git checkout -B {branch} origin/{BASE}", work, env=git_env(), timeout=120)

    applier = APPLY.get((comp, lib))
    if not applier:
        raise RuntimeError(f"no applier for {comp}/{lib}")
    changed = applier(work)
    if DRY:
        return {"lib": lib, "dry": True, "title": title, "tickets": [t["key"] for t in tickets]}

    if not compile_gate(comp, work, lib):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "branch": branch}

    run(f"git add {' '.join(changed)}", work, timeout=60)
    p = subprocess.run(
        ["git", "commit", "-m", title],
        cwd=str(work), text=True, capture_output=True, env=git_env(),
    )
    if p.returncode != 0:
        return {"lib": lib, "ok": False, "commit_err": (p.stderr or p.stdout or "")[-400:]}
    code, _, err = run(f"git push -u origin {branch}", work, timeout=300)
    if code != 0:
        return {"lib": lib, "ok": False, "push_err": err[-400:]}

    body = "\n".join([
        f"- Component: {comp} ({BASE}, release {RELEASE})",
        f"- Library: {name} → {target}",
        f"- Tickets: {', '.join(t['key'] for t in tickets)}",
        f"- Files: {', '.join(changed)}",
    ])
    pr = create_pr(gh, branch, title, body)
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
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed, "branch": branch}


def process_component(ca, comp: str):
    cfg = COMPONENTS[comp]
    write_status(phase=f"{comp}:load")
    rows = load_tickets(ca, cfg)
    write_status(**{f"{comp}_tickets": [r["key"] for r in rows]})

    excepted, fixable, unknown = [], [], []
    for row in rows:
        action, meta = classify(comp, row)
        if action == "exception":
            print(f"[{comp}] EXCEPTION {row['key']} {row['pkg']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE
                )
                (excepted if ok else unknown).append(row["key"])
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
        return {"excepted": excepted, "fixable": [r["key"] for r in fixable], "unknown": unknown, "prs": []}

    by_lib: dict[str, list] = {}
    for r in fixable:
        by_lib.setdefault(r["lib"], []).append(r)

    # stable order — continue other libs even if one fails
    order = ["lang3", "nimbus", "vertx"]
    prs, closed, errors = [], [], []
    for lib in order:
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

    out = {"excepted": excepted, "closed": closed, "prs": prs, "unknown": unknown}
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
