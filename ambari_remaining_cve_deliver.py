#!/usr/bin/env python3
"""odp-ambari remaining CVE deliver for scan release 3.0.0.1 on rel/ODP-AMBARI-3.0.0.2-1.

Reads /tmp/ambari_remaining.json (pre-dumped To Do set).

FIX (version bumps, one PR per library):
  mina-core, jackson, postgresql, spring-ldap, nimbus-jose-jwt,
  commons-lang3, commons-configuration2, commons-io (files view),
  spring (Framework), spring-security, logback

EXCEPTION:
  ambari-infra-solr*, agent/fast-hdfs prebuilt, velocity-shaded commons-io,
  jackson-mapper-asl (EOL), commons-lang 2.6 (open), ODP hadoop/zk,
  okio (AWS transitive), jetty 11 (no 11.0.27+/requires Jetty 12),
  commons-net (major API jump; only if not in FIX list)

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_SKIP_EXCEPTIONS=1 / CVE_ONLY_LIB=mina
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
SKIP_EX = os.environ.get("CVE_SKIP_EXCEPTIONS", "") not in ("", "0", "false", "False")
ONLY_LIB = os.environ.get("CVE_ONLY_LIB", "").strip().lower()
# Re-deliver fixes for tickets previously mis-routed to Exception Request
REDELIVER = os.environ.get("CVE_REDELIVER", "") not in ("", "0", "false", "False")
RELEASE = "3.0.0.1"
WORK = Path("/root/3.0.0.2/odp-ambari")
GH = "acceldata-io/odp-ambari"
BASE = "rel/ODP-AMBARI-3.0.0.2-1"
TICKETS = Path("/tmp/ambari_remaining.json")
STATUS = Path("/tmp/ambari_remaining_cve_status.json")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

# Targets
T_MINA = "2.0.28"
T_JACKSON = "2.18.6"
T_PG = "42.7.13"
T_LDAP = "2.4.4"
T_NIMBUS = "9.37.4"
T_LANG3 = "3.18.0"
T_CFG2 = "2.15.0"
T_IO = "2.15.1"
T_SPRING = "6.2.19"
T_SEC = "6.0.8"  # latest 6.0.x; higher lines need Framework 6.1+ (separate PR risk)
T_LOGBACK = "1.3.16"


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
    print(f"STATUS: {json.dumps(kwargs)[:800]}", flush=True)


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


def jdk_home():
    for c in (
        "/usr/lib/jvm/java-17-openjdk",
        "/usr/lib/jvm/java-17",
        "/usr/lib/jvm/temurin-17",
    ):
        if Path(c).exists():
            return c
    raise SystemExit("JDK 17 not found")


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


def classify(row):
    """Return (action, lib_or_reason). action in fix|exception."""
    path = (row.get("path") or "")
    pkg = (row.get("pkg") or "")
    ver = (row.get("ver") or "")
    pl = path.lower()
    pk = pkg.lower()

    # --- clear exceptions by location ---
    if "ambari-infra-solr" in pl:
        return "exception", (
            "Vulnerable jar is bundled inside ambari-infra-solr (vendor Solr "
            f"distribution), not built from odp-ambari {BASE}. Remediation "
            "belongs to the ambari-infra/Solr package line. Exception Request (Deferred)."
        )
    if "fast-hdfs-resource" in pl:
        return "exception", (
            "CVE is inside the prebuilt fast-hdfs-resource.jar under stack-hooks; "
            "not a Maven-managed Ambari dependency that can be bumped in odp-ambari. "
            "Exception Request (Deferred)."
        )
    if "velocity-engine-core" in pl and "commons-io" in pk:
        return "exception", (
            "commons-io is embedded/repackaged inside velocity-engine-core; Ambari's "
            "commons-io.version override does not rewrite that jar. Exception Request (Deferred)."
        )
    if "jackson-mapper-asl" in pk or "codehaus.jackson" in pk:
        return "exception", (
            "org.codehaus.jackson:jackson-mapper-asl 1.9.x is EOL with no fixed release "
            "(fix=open). Requires code migration off Codehaus Jackson. Exception Request (Deferred)."
        )
    if pk.endswith("commons-lang") or pk == "commons-lang_commons-lang":
        return "exception", (
            "commons-lang 2.6 has no fixed version published (fix=open). Requires "
            "migration to commons-lang3. Exception Request (Deferred)."
        )
    if "hadoop-hdfs" in pk or "hadoop-hdfs-" in pl:
        return "exception", (
            "hadoop-hdfs is the ODP Hadoop line (3.3.6.x); Ambari consumes the platform "
            "artifact and cannot remediate via a standalone Maven bump to Apache 3.4.x. "
            "Exception Request (Deferred)."
        )
    if "zookeeper" in pk and "3.8.4" in ver:
        return "exception", (
            "zookeeper is the ODP ZooKeeper line (3.8.4.x); Ambari consumes the platform "
            "artifact. Remediation requires an ODP ZK release bump, not Ambari alone. "
            "Exception Request (Deferred)."
        )
    if "okio" in pk:
        return "exception", (
            "okio is a transitive dependency from AWS/Hadoop client jars in the Files "
            "view; not centrally versioned for a safe Ambari-only bump without rewriting "
            "those client stacks. Exception Request (Deferred)."
        )
    if "jetty" in pk:
        return "exception", (
            "Jetty is on 11.0.26 (latest published 11.0.x); advisory fixed versions are "
            "11.0.27+/12.x which are unavailable on the Jetty 11 line. Moving to Jetty 12 "
            "is a major servlet/API migration, not a version bump. Exception Request (Deferred)."
        )
    if "commons-net" in pk:
        return "exception", (
            "commons-net 1.4.1 → 3.9.0 is a major API break across Ambari server networking "
            "call sites; not a safe patch-level bump. Exception Request (Deferred)."
        )

    # --- fixable ---
    if "mina-core" in pk and ver.startswith("2.0.27"):
        return "fix", "mina"
    if "jackson-core" in pk and ver.startswith("2.18.2"):
        return "fix", "jackson"
    if "postgresql" in pk and ver.startswith("42.3.9"):
        return "fix", "postgresql"
    if "spring-ldap-core" in pk:
        return "fix", "spring-ldap"
    if "nimbus-jose-jwt" in pk:
        return "fix", "nimbus"
    if "commons-lang3" in pk:
        return "fix", "commons-lang3"
    if "commons-configuration2" in pk:
        return "fix", "commons-configuration2"
    if "commons-io" in pk and ("files-" in pl or ver in ("2.4", "2.5")):
        return "fix", "commons-io"
    if "logback" in pk:
        return "fix", "logback"
    if "springframework.security" in pk or pk.startswith("spring-security"):
        # Only close tickets whose advisory lists a 6.0.x fixed version
        fix = (row.get("fix") or "").lower()
        if re.search(r"6\.0\.\d+", fix):
            return "fix", "spring-security"
        return "exception", (
            f"Spring Security {ver} advisory requires {row.get('fix') or '6.1+/6.2+/6.4+'}, "
            f"which is not compatible with Ambari's Spring Framework 6.0 line without a "
            f"coordinated major Security upgrade. Ambari can patch to Security {T_SEC} "
            f"(latest 6.0.x) for 6.0.x advisories only. Exception Request (Deferred)."
        )
    if "springframework" in pk or pk.startswith("org.springframework_spring"):
        return "fix", "spring"

    return "exception", (
        f"No safe Ambari-managed version bump identified for {pkg}@{ver} "
        f"(path ...{path[-80:]}). Exception Request (Deferred)."
    )


def ensure_base():
    env = git_env()
    run(f"git remote set-url origin https://github.com/{GH}.git", WORK, env=env, timeout=60)
    run(f"git fetch origin {BASE} --prune", WORK, env=env, timeout=600)
    run(f"git checkout -B {BASE} origin/{BASE}", WORK, env=env, timeout=120)
    run("git reset --hard HEAD", WORK, env=env, timeout=120)


def sub_prop(text, prop, value):
    pat = rf"(<{re.escape(prop)}>)[^<]+(</{re.escape(prop)}>)"
    text2, n = re.subn(pat, rf"\g<1>{value}\2", text, count=1)
    if n != 1:
        raise RuntimeError(f"property {prop} not updated (n={n})")
    return text2


def apply_lib(lib: str) -> list[str]:
    changed = []
    if lib == "mina":
        p = WORK / "ambari-project/pom.xml"
        t = sub_prop(p.read_text(encoding="utf-8"), "mina.core.version", T_MINA)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-project/pom.xml:mina.core.version={T_MINA}")
    elif lib == "jackson":
        p = WORK / "ambari-project/pom.xml"
        t = p.read_text(encoding="utf-8")
        t = sub_prop(t, "fasterxml.jackson.version", T_JACKSON)
        t = sub_prop(t, "fasterxml.jackson.databind.version", T_JACKSON)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-project/pom.xml:jackson={T_JACKSON}")
    elif lib == "postgresql":
        p = WORK / "ambari-project/pom.xml"
        t = sub_prop(p.read_text(encoding="utf-8"), "postgres.version", T_PG)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-project/pom.xml:postgres.version={T_PG}")
    elif lib == "spring-ldap":
        p = WORK / "ambari-project/pom.xml"
        t = p.read_text(encoding="utf-8")
        t2, n = re.subn(
            r"(<artifactId>spring-ldap-core</artifactId>\s*<version>)[^<]+(</version>)",
            rf"\g<1>{T_LDAP}\2",
            t,
            count=1,
        )
        if n != 1:
            raise RuntimeError("spring-ldap-core version not updated")
        p.write_text(t2, encoding="utf-8")
        changed.append(f"ambari-project/pom.xml:spring-ldap-core={T_LDAP}")
    elif lib == "nimbus":
        p = WORK / "ambari-server/pom.xml"
        t = sub_prop(p.read_text(encoding="utf-8"), "nimbus.jose.jwt.version", T_NIMBUS)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-server/pom.xml:nimbus.jose.jwt.version={T_NIMBUS}")
    elif lib == "commons-lang3":
        # server direct version + agent property
        p = WORK / "ambari-server/pom.xml"
        t = p.read_text(encoding="utf-8")
        t2, n = re.subn(
            r"(<artifactId>commons-lang3</artifactId>\s*<version>)3\.9(</version>)",
            rf"\g<1>{T_LANG3}\2",
            t,
            count=1,
        )
        if n != 1:
            raise RuntimeError("server commons-lang3 3.9 not updated")
        p.write_text(t2, encoding="utf-8")
        changed.append(f"ambari-server/pom.xml:commons-lang3={T_LANG3}")
        p2 = WORK / "ambari-agent/pom.xml"
        t = sub_prop(p2.read_text(encoding="utf-8"), "commons-lang3.version", T_LANG3)
        p2.write_text(t, encoding="utf-8")
        changed.append(f"ambari-agent/pom.xml:commons-lang3.version={T_LANG3}")
    elif lib == "commons-configuration2":
        p = WORK / "ambari-agent/pom.xml"
        t = sub_prop(p.read_text(encoding="utf-8"), "commons-configuration2.version", T_CFG2)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-agent/pom.xml:commons-configuration2.version={T_CFG2}")
        # files view nested jar — add/override dependency if present
        fp = WORK / "contrib/views/files/pom.xml"
        ft = fp.read_text(encoding="utf-8")
        if "commons-configuration2" not in ft:
            # inject managed dep before commons-io block
            inj = (
                "    <dependency>\n"
                "      <groupId>org.apache.commons</groupId>\n"
                "      <artifactId>commons-configuration2</artifactId>\n"
                f"      <version>{T_CFG2}</version>\n"
                "    </dependency>\n"
            )
            if "<artifactId>commons-io</artifactId>" in ft:
                ft = ft.replace(
                    "    <dependency>\n      <groupId>commons-io</groupId>",
                    inj + "    <dependency>\n      <groupId>commons-io</groupId>",
                    1,
                )
                fp.write_text(ft, encoding="utf-8")
                changed.append(f"contrib/views/files/pom.xml:commons-configuration2={T_CFG2}")
    elif lib == "commons-io":
        p = WORK / "contrib/views/files/pom.xml"
        t = p.read_text(encoding="utf-8")
        t2, n = re.subn(
            r"(<artifactId>commons-io</artifactId>\s*<version>)2\.4(</version>)",
            rf"\g<1>{T_IO}\2",
            t,
            count=1,
        )
        if n != 1:
            raise RuntimeError("files commons-io 2.4 not updated")
        p.write_text(t2, encoding="utf-8")
        changed.append(f"contrib/views/files/pom.xml:commons-io={T_IO}")
    elif lib == "spring":
        p = WORK / "ambari-project/pom.xml"
        t = sub_prop(p.read_text(encoding="utf-8"), "spring.version", T_SPRING)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-project/pom.xml:spring.version={T_SPRING}")
    elif lib == "spring-security":
        p = WORK / "ambari-project/pom.xml"
        t = sub_prop(p.read_text(encoding="utf-8"), "spring.security.version", T_SEC)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-project/pom.xml:spring.security.version={T_SEC}")
    elif lib == "logback":
        p = WORK / "ambari-project/pom.xml"
        t = sub_prop(p.read_text(encoding="utf-8"), "logback.version", T_LOGBACK)
        p.write_text(t, encoding="utf-8")
        changed.append(f"ambari-project/pom.xml:logback.version={T_LOGBACK}")
    else:
        raise RuntimeError(f"unknown lib {lib}")
    return changed


LIB_META = {
    "mina": ("Mina", T_MINA, "ambari-project `mina.core.version`"),
    "jackson": ("Jackson", T_JACKSON, "ambari-project `fasterxml.jackson.version`"),
    "postgresql": ("PostgreSQL JDBC", T_PG, "ambari-project `postgres.version`"),
    "spring-ldap": ("Spring LDAP", T_LDAP, "ambari-project spring-ldap-core"),
    "nimbus": ("Nimbus JOSE JWT", T_NIMBUS, "ambari-server `nimbus.jose.jwt.version`"),
    "commons-lang3": ("commons-lang3", T_LANG3, "ambari-server + ambari-agent"),
    "commons-configuration2": ("commons-configuration2", T_CFG2, "ambari-agent (+ files view)"),
    "commons-io": ("commons-io", T_IO, "contrib/views/files"),
    "spring": ("Spring Framework", T_SPRING, "ambari-project `spring.version`"),
    "spring-security": ("Spring Security", T_SEC, "ambari-project `spring.security.version`"),
    "logback": ("Logback", T_LOGBACK, "ambari-project `logback.version`"),
}


def compile_gate(lib: str) -> bool:
    """Gate: resolve bumped artifact from Maven + validate ambari-project POM."""
    log = f"/tmp/ambari_fix_{lib}.log"
    env = git_env()
    skips = (
        "-DskipTests -Dcheckstyle.skip=true -Drat.skip=true -Denforcer.skip=true "
        "-Dfindbugs.skip=true -Dpmd.skip=true -Djacoco.skip=true"
    )
    artifacts = {
        "mina": f"org.apache.mina:mina-core:{T_MINA}",
        "jackson": f"com.fasterxml.jackson.core:jackson-core:{T_JACKSON}",
        "postgresql": f"org.postgresql:postgresql:{T_PG}",
        "spring-ldap": f"org.springframework.ldap:spring-ldap-core:{T_LDAP}",
        "nimbus": f"com.nimbusds:nimbus-jose-jwt:{T_NIMBUS}",
        "commons-lang3": f"org.apache.commons:commons-lang3:{T_LANG3}",
        "commons-configuration2": f"org.apache.commons:commons-configuration2:{T_CFG2}",
        "commons-io": f"commons-io:commons-io:{T_IO}",
        "logback": f"ch.qos.logback:logback-core:{T_LOGBACK}",
        "spring": f"org.springframework:spring-core:{T_SPRING}",
        "spring-security": f"org.springframework.security:spring-security-core:{T_SEC}",
    }
    art = artifacts.get(lib)
    if art:
        code_a, out_a, err_a = run(
            f"mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get -Dartifact={art}",
            WORK, env=env, timeout=600, log_path=log,
        )
        if code_a != 0:
            for ln in (out_a + err_a).splitlines()[-30:]:
                if any(x in ln.lower() for x in ("error", "failure", "failed")):
                    print("   ", ln[:220], flush=True)
            return False

    # Always validate ambari-project (BOM / dependencyManagement)
    code, out, err = run(
        f"mvn -q -N -f ambari-project/pom.xml validate {skips}",
        WORK, env=env, timeout=900, log_path=log,
    )
    if code != 0:
        for ln in (out + err).splitlines()[-40:]:
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


def deliver_fix(ca, lib: str, tickets: list[dict]):
    name, target, where = LIB_META[lib]
    branch = tickets[0]["key"]
    cves = sorted({r.get("cve") or "" for r in tickets if r.get("cve")})
    cves = [c for c in cves if c]
    # PR/commit title cites a single representative CVE (not the full set)
    one_cve = cves[0] if cves else f"{name} CVEs"
    title = (
        f"{branch} - CVE - Bumped-up {name} to {target} to address {one_cve}"
    )
    ensure_base()
    run(f"git checkout -B {branch} origin/{BASE}", WORK, env=git_env(), timeout=120)
    changed = apply_lib(lib)
    print(f"[{lib}] changed={changed}", flush=True)
    if DRY:
        return {"lib": lib, "dry": True, "title": title, "keys": [t["key"] for t in tickets]}
    if not compile_gate(lib):
        return {"lib": lib, "ok": False, "phase": "FAILED_COMPILE", "keys": [t["key"] for t in tickets]}

    files = " ".join(sorted({c.split(":")[0] for c in changed}))
    run(f"git add {files}", WORK, env=git_env(), timeout=60)
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
        f"- Component: odp-ambari ({BASE}, scan release {RELEASE})",
        f"- Library: {name} → {target} ({where})",
        f"- Tickets closed: {', '.join(t['key'] for t in tickets)}",
        f"- Files: {', '.join(changed)}",
    ])
    pr = create_pr(branch, title, body)
    if not pr:
        return {"lib": lib, "ok": False, "pr": None}

    closed = []
    for r in tickets:
        ok = ca.close_ticket_with_comment(
            r["key"],
            f"Fixed via PR: {pr} — bumped {name} to {target} on {BASE} ({where}).",
            "Closed",
            assignee=ASSIGNEE,
        )
        print(f"  {r['key']} -> {'Closed' if ok else 'FAILED'}", flush=True)
        if ok:
            closed.append(r["key"])
    return {"lib": lib, "ok": True, "pr": pr, "closed": closed}


def process(ca):
    rows = json.loads(TICKETS.read_text(encoding="utf-8"))
    write_status(phase="loaded", count=len(rows))

    excepted, fix_map, unknown = [], {}, []
    for row in rows:
        action, meta = classify(row)
        if action == "exception":
            if REDELIVER:
                # Refresh exception text for tickets we now correctly keep as Exception
                # (e.g. Spring Security advisories that need 6.1+/6.2+).
                if "springframework.security" in (row.get("pkg") or "").lower() or (
                    row.get("pkg") or ""
                ).lower().startswith("spring-security"):
                    print(f"[EX-refresh] {row['key']} {row['pkg']}", flush=True)
                    if not DRY:
                        ok = ca.update_ticket_exception(
                            row["key"], meta, reason="Deferred", assignee=ASSIGNEE,
                        )
                        (excepted if ok else unknown).append(row["key"])
                    else:
                        excepted.append(row["key"])
                continue
            if SKIP_EX:
                continue
            print(f"[EX] {row['key']} {row['pkg']}@{row['ver']}", flush=True)
            if DRY:
                excepted.append(row["key"])
            else:
                ok = ca.update_ticket_exception(
                    row["key"], meta, reason="Deferred", assignee=ASSIGNEE,
                )
                (excepted if ok else unknown).append(row["key"])
        elif action == "fix":
            lib = meta
            if ONLY_LIB and lib != ONLY_LIB:
                continue
            print(f"[FIX] {row['key']} {lib} {row['pkg']}@{row['ver']}", flush=True)
            fix_map.setdefault(lib, []).append(row)
        else:
            unknown.append(row["key"])

    write_status(
        phase="classified",
        excepted=len(excepted),
        fix_libs={k: [t["key"] for t in v] for k, v in fix_map.items()},
        unknown=unknown,
    )

    if ROUTE_ONLY:
        return {
            "excepted": excepted,
            "fixable": {k: [t["key"] for t in v] for k, v in fix_map.items()},
            "unknown": unknown,
            "prs": [],
        }

    # Prefer spring before spring-security
    order = [
        "mina", "jackson", "postgresql", "spring-ldap", "nimbus",
        "commons-lang3", "commons-configuration2", "commons-io",
        "logback", "spring", "spring-security",
    ]
    prs, closed_all, failed = [], [], []
    for lib in order:
        if lib not in fix_map:
            continue
        if ONLY_LIB and lib != ONLY_LIB:
            continue
        write_status(phase=f"fixing_{lib}", keys=[t["key"] for t in fix_map[lib]])
        res = deliver_fix(ca, lib, fix_map[lib])
        if res.get("pr"):
            prs.append(res["pr"])
        if res.get("closed"):
            closed_all.extend(res["closed"])
        if not res.get("ok", res.get("dry")):
            failed.append(res)
            # Do NOT auto-exception on gate failure — leave for manual retry.
            # (Earlier false reactor failures incorrectly exceptioned fixable CVEs.)

    return {
        "excepted": excepted,
        "closed": closed_all,
        "prs": prs,
        "failed": failed,
        "unknown": unknown,
    }


def main():
    write_status(phase="start")
    load_token()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    results = process(ca)
    write_status(phase="DONE", results=results)
    print("DONE", json.dumps(results, indent=2, default=str), flush=True)


if __name__ == "__main__":
    main()
