#!/usr/bin/env python3
"""Batch CVE deliver for knox, kafka3, registry, nifi2 (release 3.3.6.4).

Separate PR per library. Status: /tmp/batch5_cve_status.json
Summary: /root/cve_fix_llm/reports/batch5_status.md

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_COMPONENTS=knox,kafka3
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
time = __import__("time")
from pathlib import Path

ASSIGNEE = "senthil.kumar"
REVIEWER = "basapuram-kumar"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
ROUTE_ONLY = os.environ.get("CVE_ROUTE_ONLY", "") not in ("", "0", "false", "False")
RELEASE = "3.3.6.4"
ROOT = Path("/root/3.3.6.5")
STATUS = Path("/tmp/batch5_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch5_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
TOKEN = ""

# Targets
LANG3 = "3.18.0"
NIMBUS_9 = "9.37.4"
NIMBUS_10 = "10.0.2"
SPRING53 = "5.3.39"  # latest published 5.3.x (5.3.41 does not exist on Maven Central)
SPRING62 = "6.2.18"
SPRING_SEC = "6.5.10"
SPRING_BOOT = "3.5.14"
JETTY121 = "12.1.8"
JETTY94 = "9.4.58.v20250814"  # already on registry branch; used for close-as-fixed
PG = "42.7.11"
MINA = "2.0.28"
MAIL = "1.6.8"
LZ4 = "1.8.1"
PLEXUS = "3.6.1"
LOGBACK13 = "1.3.16"
LOGBACK15 = "1.5.25"
JACKSON_NIFI = "2.21.1"
UNDERTOW = "2.3.21.Final"

COMPONENTS = {
    "knox": {
        "jira": "sehajsandhu/knox",
        "gh": "acceldata-io/knox",
        "work": ROOT / "knox",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
    },
    "kafka3": {
        "jira": "sehajsandhu/kafka3",
        "gh": "acceldata-io/kafka3",
        "work": ROOT / "kafka3",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
    },
    "registry": {
        "jira": "sehajsandhu/registry",
        "gh": "acceldata-io/registry",
        "work": ROOT / "registry",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
    },
    "nifi2": {
        "jira": "sehajsandhu/nifi2",
        "gh": "acceldata-io/nifi",
        "work": ROOT / "nifi2",
        "base": "nightly/ODP-2.7.2.3.3.6.5",
        "jdk": 21,
    },
}

FILTER = [
    c.strip()
    for c in os.environ.get("CVE_COMPONENTS", "knox,kafka3,registry,nifi2").split(",")
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
        f"# Batch5 CVE status ({RELEASE})",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        "",
    ]
    for comp, res in results.items():
        lines.append(f"## {comp}")
        lines.append(f"- excepted: {', '.join(res.get('excepted') or []) or '—'}")
        lines.append(f"- closed: {', '.join(res.get('closed') or []) or '—'}")
        for pr in res.get("prs") or []:
            lines.append(f"- PR: {pr}")
        if res.get("already_fixed"):
            lines.append(f"- already-fixed closed: {', '.join(res['already_fixed'])}")
        if res.get("unknown"):
            lines.append(f"- unknown: {', '.join(res['unknown'])}")
        if res.get("error"):
            lines.append(f"- ERROR: {res['error']}")
        if res.get("errors"):
            lines.append(f"- errors: {json.dumps(res['errors'])[:400]}")
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
        f"/usr/lib/jvm/temurin-{jdk}-jdk",
        f"/usr/lib/jvm/temurin-{jdk}-jdk-amd64",
    ]
    for c in cands:
        if Path(c).exists():
            return c
    jvm = Path("/usr/lib/jvm")
    if jvm.is_dir():
        for p in sorted(jvm.iterdir()):
            if p.is_dir() and str(jdk) in p.name:
                return str(p)
    raise SystemExit(f"JDK {jdk} not found under /usr/lib/jvm")


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


def fix_has_line(fix: str, *prefixes: str) -> bool:
    fl = (fix or "").lower()
    return any(p.lower() in fl for p in prefixes)


# ---------- classifiers ----------

def classify_knox(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    fix = row["fix"] or ""

    if "hadoop-common" in pkg:
        return "exception", (
            "hadoop-common is the ODP Hadoop platform artifact; remediation "
            "belongs to Hadoop. Exception Request (Deferred)."
        )
    if "jetty" in pkg:
        return "exception", (
            "Jetty CVE fix is only on 12.x; Knox stays on Jetty 9.4.x (javax). "
            "Exception Request (Deferred)."
        )
    if "logback" in pkg:
        return "exception", (
            "logback-core is on 1.3.x; advisory fix is only on 1.5.x. "
            "Exception Request (Deferred)."
        )
    if "commons-configuration" in pkg and "configuration2" not in pkg:
        return "exception", (
            "commons-configuration 1.10 has no published fix (advisory open). "
            "Exception Request (Deferred)."
        )
    if "configuration2" in pkg:
        return "exception", (
            "commons-configuration2 is transitive (Hadoop/platform), not a Knox "
            "managed property. Exception Request (Deferred)."
        )
    if "commons-io" in pkg and "velocity" in path:
        return "exception", (
            "commons-io is reported inside velocity-engine-core (bundled), not "
            "Knox's managed commons-io pin. Exception Request (Deferred)."
        )
    if "shiro" in pkg:
        return "exception", (
            "Shiro fix requires 2.0.x (major API break from 1.13). "
            "Exception Request (Deferred)."
        )
    if "pac4j" in pkg:
        return "exception", (
            "pac4j fix requires 5.7+/6.x (major from 4.5.x). "
            "Exception Request (Deferred)."
        )
    if pkg.startswith("spring-") or pkg in (
        "spring-web", "spring-core", "spring-context", "spring-expression"
    ):
        # Maven Central Spring 5.3 line ends at 5.3.39 (5.3.41 was never published).
        covered = any(v in (fix or "") for v in ("5.3.35", "5.3.36", "5.3.37", "5.3.38", "5.3.39"))
        if covered:
            return "fix_spring", {
                "target": SPRING53, "lib": "spring", "name": "Spring Framework",
            }
        return "exception", (
            f"Spring Framework CVE fix requires 6.x/7.x or unpublished 5.3.41 "
            f"({fix}); Knox max published 5.3.x is 5.3.39. "
            "Exception Request (Deferred)."
        )
    if "nimbus" in pkg:
        return "fix_nimbus", {"target": NIMBUS_9, "lib": "nimbus", "name": "nimbus-jose-jwt"}
    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {"target": LANG3, "lib": "lang3", "name": "commons-lang3"}
    if "postgresql" in pkg:
        return "fix_postgresql", {"target": PG, "lib": "postgresql", "name": "postgresql"}
    if "mina" in pkg:
        return "fix_mina", {"target": MINA, "lib": "mina", "name": "mina-core"}
    if "jakarta.mail" in pkg or "javax.mail" in pkg or pkg.endswith("_jakarta.mail"):
        return "fix_mail", {"target": MAIL, "lib": "mail", "name": "jakarta.mail"}
    return "unknown", f"No rule for {pkg} path={path}"


def classify_kafka3(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()

    if "jetty" in pkg:
        return "exception", (
            "Jetty CVE fix is only on 12.x; Kafka3 stays on Jetty 9.4.x. "
            "Exception Request (Deferred)."
        )
    # connector / uber jars
    if any(
        x in path
        for x in (
            "pubsub-group-kafka-connector",
            "amazon-kinesis-kafka-connecter",
            "camel-aws-sqs",
            "uber",
        )
    ):
        return "exception", (
            f"Flagged inside connector/uber jar ({Path(path).name}), not a "
            "Kafka3-managed standalone dependency pin. Exception Request (Deferred)."
        )
    # Aiven RSM zip contents
    if "/rsm/" in path or path.startswith("rsm/") or "/rsm/" in row["path"]:
        return "exception", (
            "Dependency ships inside Aiven tiered-storage RSM zip "
            "(io.aiven:tiered-storage-for-apache-kafka-*), not a Kafka3 gradle "
            "version pin. Exception Request (Deferred)."
        )
    if "lz4" in pkg:
        return "fix_lz4", {"target": LZ4, "lib": "lz4", "name": "lz4-java"}
    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        # standalone libs/commons-lang3-*.jar
        return "fix_lang3", {"target": LANG3, "lib": "lang3", "name": "commons-lang3"}
    if "plexus-utils" in pkg or "plexus_utils" in pkg:
        return "fix_plexus", {"target": PLEXUS, "lib": "plexus", "name": "plexus-utils"}
    if "nimbus" in pkg or "aircompressor" in pkg or "beanutils" in pkg:
        return "exception", (
            "Bundled via Aiven RSM / non-managed path; not a safe Kafka3 pin. "
            "Exception Request (Deferred)."
        )
    if "jackson" in pkg:
        return "exception", (
            "Jackson finding is on RSM/parquet-jackson shaded content, not the "
            "Kafka3 managed jackson pin. Exception Request (Deferred)."
        )
    return "unknown", f"No rule for {pkg} path={path}"


def classify_registry(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    fix = row["fix"] or ""

    if "jersey-shaded" in path:
        return "exception", (
            "Netty is shaded inside jersey-shaded uber jar; bump belongs to that "
            "module's shading inputs / rebuild, deferred here. "
            "Exception Request (Deferred)."
        )
    if "ranger-plugin" in path or "ranger-plugins" in pkg or "ranger-schema" in path:
        return "exception", (
            "Finding is under registry ranger-plugin packaging (Ranger/Hadoop "
            "transitive). Remediation belongs to Ranger/Hadoop. "
            "Exception Request (Deferred)."
        )
    if "hadoop-common" in pkg:
        return "exception", (
            "hadoop-common is the ODP Hadoop platform artifact. "
            "Exception Request (Deferred)."
        )
    if "logback" in pkg:
        # 1.5-only advisories vs 1.3-line fixes
        if fix_has_line(fix, "1.3.") and not (
            "1.5." in fix and "1.3." not in fix.replace("1.3.", "")
        ):
            # has 1.3.x fix available
            if "1.5.25" in fix and "1.3." not in fix:
                return "exception", (
                    "logback advisory fix is only on 1.5.x; registry stays on "
                    "1.2/1.3 line. Exception Request (Deferred)."
                )
            return "fix_logback", {
                "target": LOGBACK13, "lib": "logback", "name": "logback",
            }
        if "1.5." in fix and "1.3." not in fix:
            return "exception", (
                "logback advisory fix is only on 1.5.x; registry stays on "
                "1.2/1.3 line. Exception Request (Deferred)."
            )
        # mixed: prefer 1.3.16 when listed
        if "1.3." in fix:
            return "fix_logback", {
                "target": LOGBACK13, "lib": "logback", "name": "logback",
            }
        return "exception", (
            "logback advisory fix is only on 1.5.x. Exception Request (Deferred)."
        )
    if "jetty" in pkg:
        # branch already on 9.4.58 (>= 9.4.54)
        return "already_fixed", {
            "target": JETTY94, "lib": "jetty", "name": "jetty",
            "note": f"Already on jetty {JETTY94} (>= 9.4.54) on {COMPONENTS['registry']['base']}.",
        }
    if "nimbus" in pkg:
        return "fix_nimbus", {"target": NIMBUS_10, "lib": "nimbus", "name": "nimbus-jose-jwt"}
    if "postgresql" in pkg:
        return "fix_postgresql", {"target": PG, "lib": "postgresql", "name": "postgresql"}
    if "plexus-utils" in pkg or "plexus_utils" in pkg:
        return "fix_plexus", {"target": PLEXUS, "lib": "plexus", "name": "plexus-utils"}
    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {"target": LANG3, "lib": "lang3", "name": "commons-lang3"}
    return "unknown", f"No rule for {pkg} path={path}"


def classify_nifi2(row):
    pkg = (row["pkg"] or "").lower()
    fix = row["fix"] or ""

    if "undertow" in pkg:
        if "2.3.21" in fix or "2.3.21.Final" in fix or "2.2.39" in fix:
            return "fix_undertow", {
                "target": UNDERTOW, "lib": "undertow", "name": "undertow-core",
            }
        return "exception", (
            f"Undertow advisory fix requires 2.4.x ({fix}); nifi-registry stays "
            "on Undertow 2.3.x via Spring Boot. Exception Request (Deferred)."
        )
    if "jetty" in pkg:
        return "fix_jetty", {"target": JETTY121, "lib": "jetty", "name": "Jetty"}
    if "spring-boot" in pkg:
        return "fix_springboot", {
            "target": SPRING_BOOT, "lib": "springboot", "name": "Spring Boot",
        }
    if "spring-security" in pkg:
        return "fix_springsec", {
            "target": SPRING_SEC, "lib": "springsec", "name": "Spring Security",
        }
    if pkg.startswith("spring-") or pkg in (
        "spring-web", "spring-core", "spring-webmvc", "spring-context"
    ):
        return "fix_spring", {
            "target": SPRING62, "lib": "spring", "name": "Spring Framework",
        }
    if "logback" in pkg:
        return "fix_logback", {
            "target": LOGBACK15, "lib": "logback", "name": "logback",
        }
    if "jackson" in pkg:
        return "fix_jackson", {
            "target": JACKSON_NIFI, "lib": "jackson", "name": "Jackson",
        }
    return "unknown", f"No rule for {pkg}"


CLASSIFY = {
    "knox": classify_knox,
    "kafka3": classify_kafka3,
    "registry": classify_registry,
    "nifi2": classify_nifi2,
}


# ---------- appliers ----------

def _sub_prop(pom: Path, prop: str, ver: str) -> list:
    text = pom.read_text(encoding="utf-8")
    pat = rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)"
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n != 1:
        raise RuntimeError(f"{prop} not found in {pom}")
    pom.write_text(text2, encoding="utf-8")
    return [str(pom.relative_to(pom.parent.parent) if False else pom.name)]


def apply_knox_prop(work: Path, prop: str, ver: str):
    pom = work / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    pat = rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)"
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n != 1:
        raise RuntimeError(f"knox {prop} not found")
    pom.write_text(text2, encoding="utf-8")
    return ["pom.xml"]


def apply_knox_mail(work: Path):
    """Add/override jakarta.mail in dependencyManagement."""
    pom = work / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    changed = []
    if "<jakarta.mail.version>" not in text:
        text = text.replace(
            f"<nimbus-jose-jwt.version>",
            f"<jakarta.mail.version>{MAIL}</jakarta.mail.version>\n        <nimbus-jose-jwt.version>",
            1,
        )
    else:
        text, n = re.subn(
            r"(<jakarta\.mail\.version>)([^<]+)(</jakarta\.mail\.version>)",
            rf"\g<1>{MAIL}\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("jakarta.mail.version replace failed")
    dep = (
        "\n                <dependency>\n"
        "                    <groupId>com.sun.mail</groupId>\n"
        "                    <artifactId>jakarta.mail</artifactId>\n"
        "                    <version>${jakarta.mail.version}</version>\n"
        "                </dependency>"
    )
    if "artifactId>jakarta.mail</artifactId>" not in text:
        # insert before closing of dependencyManagement's dependencies
        # find first </dependencies> inside dependencyManagement
        idx = text.find("<dependencyManagement>")
        if idx < 0:
            raise RuntimeError("no dependencyManagement")
        close = text.find("</dependencies>", idx)
        text = text[:close] + dep + "\n" + text[close:]
    else:
        text, n = re.subn(
            r"(<artifactId>jakarta\.mail</artifactId>\s*<version>)([^<]+)(</version>)",
            rf"\g<1>${{jakarta.mail.version}}\g<3>",
            text,
            count=1,
        )
    pom.write_text(text, encoding="utf-8")
    return ["pom.xml"]


def apply_kafka3_lz4(work: Path):
    """lz4-java 1.8.1 relocated org.lz4 -> at.yawk.lz4; switch coordinate."""
    g = work / "gradle" / "dependencies.gradle"
    text = g.read_text(encoding="utf-8")
    text2, n = re.subn(r'(lz4:\s*")([^"]+)(")', rf"\g<1>{LZ4}\g<3>", text, count=1)
    if n != 1:
        raise RuntimeError("lz4 version not found")
    text3, n2 = re.subn(
        r'lz4:\s*"org\.lz4:lz4-java:\$versions\.lz4"',
        'lz4: "at.yawk.lz4:lz4-java:$versions.lz4"',
        text2,
        count=1,
    )
    if n2 != 1 and "at.yawk.lz4:lz4-java" not in text3:
        raise RuntimeError("lz4 library coordinate not updated")
    g.write_text(text3, encoding="utf-8")
    return ["gradle/dependencies.gradle"]


def apply_kafka3_force(work: Path, coord: str):
    bg = work / "build.gradle"
    text = bg.read_text(encoding="utf-8")
    if coord in text:
        return []
    # libs.log4j is the last force() entry (no trailing comma, tab-indented)
    old = "\t  libs.log4j\n        )"
    new = f'\t  libs.log4j,\n          "{coord}"\n        )'
    if old not in text:
        # fallback: any libs.log4j before closing force paren
        text2, n = re.subn(
            r"(libs\.log4j)\s*\n(\s*\))",
            rf'\1,\n          "{coord}"\n\2',
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("could not insert force coordinate after libs.log4j")
    else:
        text2 = text.replace(old, new, 1)
    bg.write_text(text2, encoding="utf-8")
    return ["build.gradle"]


def apply_registry_prop(work: Path, key: str, ver: str):
    gp = work / "gradle.properties"
    text = gp.read_text(encoding="utf-8")
    text2, n = re.subn(
        rf"({re.escape(key)}\s*=\s*)([^\n]+)", rf"\g<1>{ver}", text, count=1
    )
    if n != 1:
        raise RuntimeError(f"{key} not found in gradle.properties")
    gp.write_text(text2, encoding="utf-8")
    return ["gradle.properties"]


def apply_registry_lang3(work: Path):
    """Pin commons-lang3 via versions + constraint in root build.gradle."""
    gp = work / "gradle.properties"
    text = gp.read_text(encoding="utf-8")
    if "versions_commons_lang3=" not in text:
        text = text.replace(
            "versions_commons_io=",
            f"versions_commons_lang3={LANG3}\nversions_commons_io=",
            1,
        )
        gp.write_text(text, encoding="utf-8")
    else:
        text2, n = re.subn(
            r"(versions_commons_lang3=)([^\n]+)", rf"\g<1>{LANG3}", text, count=1
        )
        if n != 1:
            raise RuntimeError("versions_commons_lang3 replace failed")
        gp.write_text(text2, encoding="utf-8")

    bg = work / "build.gradle"
    b = bg.read_text(encoding="utf-8")
    marker = "compile(libraries.commons.lang3)"
    block = (
        "            compile(libraries.commons.lang3) {\n"
        "                version {\n"
        f"                    strictly project.versions_commons_lang3\n"
        "                }\n"
        "            }"
    )
    if "versions_commons_lang3" in b and "libraries.commons.lang3" in b and "strictly project.versions_commons_lang3" in b:
        return ["gradle.properties", "build.gradle"]
    # insert near other constraints (after logback constraint block if present)
    if "compile(libraries.logging.logback)" in b and "strictly project.versions_commons_lang3" not in b:
        # add new constraints block after guava constraints
        insert = (
            "\n        constraints {\n"
            "            compile(\"org.apache.commons:commons-lang3\") {\n"
            "                version {\n"
            f"                    strictly project.versions_commons_lang3\n"
            "                }\n"
            "            }\n"
            "        }\n"
        )
        # after first constraints { ... } closing - append after guava block
        m = re.search(
            r"constraints \{\s*compile\(\"com\.google\.guava:guava\"\) \{[^}]+\}\s*\}",
            b,
            re.S,
        )
        if not m:
            raise RuntimeError("guava constraints block not found for lang3 insert")
        b = b[: m.end()] + insert + b[m.end() :]
        bg.write_text(b, encoding="utf-8")
        return ["gradle.properties", "build.gradle"]
    raise RuntimeError("could not add lang3 constraint")


def apply_nifi2_root_prop(work: Path, prop: str, ver: str):
    pom = work / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)",
        rf"\g<1>{ver}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError(f"nifi2 root {prop} not found")
    pom.write_text(text2, encoding="utf-8")
    return ["pom.xml"]


def apply_nifi2_springboot(work: Path):
    pom = work / "nifi-registry" / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<spring\.boot\.version>)([^<]+)(</spring\.boot\.version>)",
        rf"\g<1>{SPRING_BOOT}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("spring.boot.version not found")
    pom.write_text(text2, encoding="utf-8")
    return ["nifi-registry/pom.xml"]


def apply_nifi2_undertow(work: Path):
    """Force undertow via dependencyManagement in nifi-registry pom."""
    pom = work / "nifi-registry" / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    if "<undertow.version>" not in text:
        text = text.replace(
            "<spring.boot.version>",
            f"<undertow.version>{UNDERTOW}</undertow.version>\n        <spring.boot.version>",
            1,
        )
    else:
        text, n = re.subn(
            r"(<undertow\.version>)([^<]+)(</undertow\.version>)",
            rf"\g<1>{UNDERTOW}\g<3>",
            text,
            count=1,
        )
        if n != 1:
            raise RuntimeError("undertow.version replace failed")
    dep = (
        "\n            <dependency>\n"
        "                <groupId>io.undertow</groupId>\n"
        "                <artifactId>undertow-core</artifactId>\n"
        "                <version>${undertow.version}</version>\n"
        "            </dependency>\n"
        "            <dependency>\n"
        "                <groupId>io.undertow</groupId>\n"
        "                <artifactId>undertow-servlet</artifactId>\n"
        "                <version>${undertow.version}</version>\n"
        "            </dependency>\n"
        "            <dependency>\n"
        "                <groupId>io.undertow</groupId>\n"
        "                <artifactId>undertow-websockets-jsr</artifactId>\n"
        "                <version>${undertow.version}</version>\n"
        "            </dependency>"
    )
    if "artifactId>undertow-core</artifactId>" not in text:
        idx = text.find("<dependencyManagement>")
        close = text.find("</dependencies>", idx)
        text = text[:close] + dep + "\n" + text[close:]
    pom.write_text(text, encoding="utf-8")
    return ["nifi-registry/pom.xml"]


APPLY = {
    ("knox", "spring"): lambda w: apply_knox_prop(w, "spring.version", SPRING53),
    ("knox", "nimbus"): lambda w: apply_knox_prop(w, "nimbus-jose-jwt.version", NIMBUS_9),
    ("knox", "lang3"): lambda w: apply_knox_prop(w, "commons-lang3.version", LANG3),
    ("knox", "postgresql"): lambda w: apply_knox_prop(w, "postgresql.version", PG),
    ("knox", "mina"): lambda w: apply_knox_prop(w, "mina.version", MINA),
    ("knox", "mail"): apply_knox_mail,
    ("kafka3", "lz4"): apply_kafka3_lz4,
    ("kafka3", "lang3"): lambda w: apply_kafka3_force(
        w, f"org.apache.commons:commons-lang3:{LANG3}"
    ),
    ("kafka3", "plexus"): lambda w: apply_kafka3_force(
        w, f"org.codehaus.plexus:plexus-utils:{PLEXUS}"
    ),
    ("registry", "nimbus"): lambda w: apply_registry_prop(w, "versions_nimbus", NIMBUS_10),
    ("registry", "postgresql"): lambda w: apply_registry_prop(
        w, "versions_postgresql", PG
    ),
    ("registry", "plexus"): lambda w: apply_registry_prop(
        w, "versions_plexus_utils", PLEXUS
    ),
    ("registry", "logback"): lambda w: apply_registry_prop(
        w, "versions_logback", LOGBACK13
    ),
    ("registry", "lang3"): apply_registry_lang3,
    ("nifi2", "jetty"): lambda w: apply_nifi2_root_prop(w, "jetty.version", JETTY121),
    ("nifi2", "spring"): lambda w: apply_nifi2_root_prop(w, "spring.version", SPRING62),
    ("nifi2", "springsec"): lambda w: apply_nifi2_root_prop(
        w, "spring.security.version", SPRING_SEC
    ),
    ("nifi2", "logback"): lambda w: apply_nifi2_root_prop(
        w, "logback.version", LOGBACK15
    ),
    ("nifi2", "jackson"): lambda w: apply_nifi2_root_prop(
        w, "jackson.bom.version", JACKSON_NIFI
    ),
    ("nifi2", "springboot"): apply_nifi2_springboot,
    ("nifi2", "undertow"): apply_nifi2_undertow,
}


def ensure_repo(work: Path, gh: str, base: str, jdk: int):
    env = git_env(jdk)
    run(f"git remote set-url origin https://github.com/{gh}.git", work, env=env, timeout=60)
    run(f"git fetch origin {base} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {base} origin/{base}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", work, env=env, timeout=600)


def compile_gate(comp: str, work: Path, lib: str, jdk: int) -> bool:
    log = f"/tmp/batch5_{comp}_{lib}_build.log"
    env = git_env(jdk)
    if comp == "knox":
        cmd = (
            "mvn -q -DskipTests -Drat.skip=true -Dcheckstyle.skip=true "
            "-Denforcer.skip=true -Dmaven.javadoc.skip=true "
            "-pl gateway-server,gateway-util-common -am package"
        )
        code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    elif comp == "kafka3":
        cmd = "./gradlew :clients:jar -x test --no-daemon"
        code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
        if code == 0 and lib == "lang3":
            _, o2, _ = run(
                "./gradlew -q :tools:dependencies --configuration runtimeClasspath",
                work, env=env, timeout=900,
            )
            if not re.search(rf"commons-lang3.*{re.escape(LANG3)}", o2 or ""):
                # also accept force arrow
                if LANG3 not in (o2 or ""):
                    print("  WARN: lang3 not visible on :tools; checking :clients", flush=True)
        if code == 0 and lib == "plexus":
            _, o2, _ = run(
                "./gradlew -q :tools:dependencies --configuration runtimeClasspath",
                work, env=env, timeout=900,
            )
            print("  plexus:\n  " + "\n  ".join(
                ln for ln in (o2 or "").splitlines() if "plexus-utils" in ln
            )[:600], flush=True)
    elif comp == "registry":
        cmd = (
            "./gradlew :registry-common:jar :storage:storage-tool:jar "
            "-x test --no-daemon"
        )
        code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    elif comp == "nifi2":
        # light gate: validate + compile registry web-api module tree
        cmd = (
            "mvn -q -DskipTests -Drat.skip=true -Dcheckstyle.skip=true "
            "-Dpmd.skip=true -Dspotbugs.skip=true -Denforcer.skip=true "
            "-Dmaven.javadoc.skip=true "
            "-pl nifi-registry/nifi-registry-core/nifi-registry-framework -am package"
        )
        code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    else:
        raise RuntimeError(comp)
    if code != 0:
        for ln in (out + err).splitlines()[-50:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed", "exception")):
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

    # map changed paths relative to work
    rels = []
    for c in changed:
        p = Path(c)
        rels.append(c if not p.is_absolute() else str(p.relative_to(work)))
    run(f"git add {' '.join(rels)}", work, env=git_env(jdk), timeout=60)
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
        f"- Files: {', '.join(rels)}",
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
    "knox": ["spring", "nimbus", "lang3", "postgresql", "mina", "mail"],
    "kafka3": ["lz4", "lang3", "plexus"],
    "registry": ["nimbus", "logback", "lang3", "postgresql", "plexus"],
    "nifi2": [
        "jetty", "spring", "springsec", "springboot", "undertow", "logback", "jackson",
    ],
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
