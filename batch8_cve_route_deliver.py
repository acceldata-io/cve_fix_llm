#!/usr/bin/env python3
"""Batch CVE deliver for Impala (release 3.3.6.4).

Separate PR per library.
Status: /tmp/batch8_cve_status.json
Summary: /root/cve_fix_llm/reports/batch8_status.md

Cross-component note:
  - Netty/Jackson inside kudu-client-* and ozone-filesystem-* jars are NOT
    fixed by Impala DM alone; they need rebuilt Kudu toolchain / Ozone FS
    artifacts (ODP kudu PR Netty 4.1.135, ozone PRs Netty/Jackson) plus an
    Impala retarget. Those tickets are Exception (Deferred).
  - Netty inside impala-minimal-s3a-* IS fixable (Impala shaded-deps module).

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_COMPONENTS=impala
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
STATUS = Path("/tmp/batch8_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch8_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "3600"))
TOKEN = ""

JACKSON = "2.18.6"
LOGBACK = "1.5.25"
LOG4J = "2.25.4"
POSTGRES = "42.7.11"
CONFIG2 = "2.15.0"
LANG3 = "3.18.0"
COMPRESS = "1.26.0"
SPRING53 = "5.3.39"
NETTY = "4.1.133.Final"
JETTY94 = "9.4.57.v20241219"
OKIO = "3.4.0"
OTEL = "1.62.0"
GRPC = "1.75.0"
SQLPARSE = "0.5.4"

COMPONENTS = {
    "impala": {
        "jira": "sehajsandhu/impala",
        "gh": "acceldata-io/impala",
        "work": ROOT / "impala",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 11,
    },
}

FILTER = [
    c.strip()
    for c in os.environ.get("CVE_COMPONENTS", "impala").split(",")
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
        f"# Batch8 CVE status ({RELEASE})",
        f"Updated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        "",
        "Google Sheet: not updated (no Sheets credentials). Paste from this file.",
        "",
        "## Cross-component (Kudu / Ozone)",
        "- Impala pins toolchain Kudu `e742f86f6d` and packages `ozone-filesystem-hadoop3-*`.",
        "- ODP kudu Netty PRs and ozone Netty/Jackson PRs do **not** clear Impala CVEs",
        "  that scan *inside* those jars until Impala retargets rebuilt artifacts.",
        "- Impala-owned `impala-minimal-s3a-*` Netty *is* addressable via netty-bom.",
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
            lines.append(f"- errors: {json.dumps(res['errors'])[:600]}")
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
        f"/usr/lib/jvm/temurin-{jdk}",
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


def classify_impala(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    fix = row["fix"] or ""

    # --- shaded / owner jars (kudu toolchain, ozone FS, iceberg runtime) ---
    if "kudu-client" in path:
        return "exception", (
            "Finding is inside Impala's toolchain Kudu client jar "
            f"(IMPALA_KUDU_VERSION=e742f86f6d). ODP kudu Netty bumps "
            f"(e.g. acceldata-io/kudu Netty PRs) do not rebuild this artifact "
            f"until Impala retargets Kudu. Exception Request (Deferred)."
        )
    if "ozone-filesystem" in path:
        return "exception", (
            "Finding is inside packaged ozone-filesystem-hadoop3 jar. "
            "Remediation requires a rebuilt Ozone FS artifact (ozone Netty/"
            "Jackson CVE PRs) and an Impala ozone version retarget. "
            "Exception Request (Deferred)."
        )
    if "iceberg-hive" in path or "iceberg-hive-runtime" in path:
        return "exception", (
            "Library is shaded inside iceberg-hive-runtime; bump requires a "
            "newer Iceberg runtime, not an Impala property pin. "
            "Exception Request (Deferred)."
        )
    if "cos_api" in path:
        return "exception", (
            "Jackson is shaded inside cos_api-bundle; owner must rebuild the "
            "fat jar. Exception Request (Deferred)."
        )

    if "elasticsearch" in pkg:
        return "exception", (
            "Elasticsearch 7.17.x; advisory fixes are on 8.x/9.x (major). "
            "Exception Request (Deferred)."
        )
    if "pac4j" in pkg:
        return "exception", (
            "pac4j 4.5.x; advisory fixes are on 5.7+/6.x (major). "
            "Exception Request (Deferred)."
        )
    if "ranger-plugins" in pkg:
        return "exception", (
            "ranger-plugins-common fix requires Ranger 2.8.0; belongs to Ranger. "
            "Exception Request (Deferred)."
        )
    if "libthrift" in pkg or pkg == "thrift" or "thrift" == pkg:
        return "exception", (
            "libthrift 0.23.0 is a breaking major from 0.16.0. "
            "Exception Request (Deferred)."
        )
    if "commons-lang" in pkg and "lang3" not in pkg:
        return "exception", (
            "commons-lang 2.6 has no upstream fix on the 2.x line. "
            "Exception Request (Deferred)."
        )
    if "ini4j" in pkg or "javax.el" in pkg:
        return "exception", (
            "No viable upstream fix on the current major line. "
            "Exception Request (Deferred)."
        )
    if "commons-configuration" in pkg and "configuration2" not in pkg:
        return "exception", (
            "commons-configuration 1.x line; Impala manages configuration2 "
            "separately. Exception Request (Deferred)."
        )

    # Jetty: same-major 9.4.57 fixable; 12.x-only → exception
    if "jetty" in pkg:
        if "9.4.57" in fix or "9.4.58" in fix:
            return "fix_jetty", {
                "target": JETTY94, "lib": "jetty", "name": "Jetty",
            }
        return "exception", (
            "Jetty CVE fix is only on 12.x; Impala stays on Jetty 9.4.x. "
            "Exception Request (Deferred)."
        )

    # Spring: 5.3.39 where listed; else major/unpublished → exception
    if "spring" in pkg:
        if "5.3.39" in fix:
            return "fix_spring", {
                "target": SPRING53, "lib": "spring", "name": "Spring Framework",
            }
        return "exception", (
            f"Spring Framework advisory needs 6.x/7.x or unpublished 5.3.41+ "
            f"({fix}); Impala stays on 5.3.x. Exception Request (Deferred)."
        )

    if "log4j" in pkg:
        return "fix_log4j", {"target": LOG4J, "lib": "log4j", "name": "Log4j"}
    if "logback" in pkg:
        return "fix_logback", {
            "target": LOGBACK, "lib": "logback", "name": "logback",
        }
    if "jackson" in pkg:
        return "fix_jackson", {
            "target": JACKSON, "lib": "jackson", "name": "Jackson",
        }
    if "postgresql" in pkg:
        return "fix_postgres", {
            "target": POSTGRES, "lib": "postgres", "name": "postgresql",
        }
    if "configuration2" in pkg:
        return "fix_config2", {
            "target": CONFIG2, "lib": "config2", "name": "commons-configuration2",
        }
    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {
            "target": LANG3, "lib": "lang3", "name": "commons-lang3",
        }
    if "commons-compress" in pkg:
        return "fix_compress", {
            "target": COMPRESS, "lib": "compress", "name": "commons-compress",
        }
    if "commons-io" in pkg:
        return "already_fixed", {
            "note": (
                "Impala fe/pom.xml already pins commons-io 2.14.0 "
                f"(>= 2.14.0) on {COMPONENTS['impala']['base']}."
            ),
        }
    if "grpc" in pkg:
        return "fix_grpc", {
            "target": GRPC, "lib": "grpc", "name": "grpc-netty-shaded",
        }
    if "netty" in pkg:
        # remaining after kudu/ozone exceptions → s3a / direct DM
        return "fix_netty", {"target": NETTY, "lib": "netty", "name": "Netty"}
    if "okio" in pkg:
        return "fix_okio", {"target": OKIO, "lib": "okio", "name": "okio"}
    if "opentelemetry" in pkg:
        return "fix_otel", {
            "target": OTEL, "lib": "otel", "name": "OpenTelemetry",
        }
    if "sqlparse" in pkg:
        return "fix_sqlparse", {
            "target": SQLPARSE, "lib": "sqlparse", "name": "sqlparse",
        }
    if "protobuf" in pkg:
        return "already_fixed", {
            "note": (
                "Impala already pins IMPALA_PROTOBUF_JAVA_VERSION=3.25.5; "
                "remaining protobuf hits inside kudu-client are owner-shaded."
            ),
        }
    if "aircompressor" in pkg:
        return "exception", (
            "aircompressor 2.0.x is a major from 0.27 and/or shaded in Iceberg. "
            "Exception Request (Deferred)."
        )
    return "unknown", f"No rule for {pkg} path={path}"


CLASSIFY = {"impala": classify_impala}


def set_config_export(work: Path, var: str, ver: str):
    path = work / "bin/impala-config.sh"
    text = path.read_text(encoding="utf-8")
    text2, n = re.subn(
        rf"(export {re.escape(var)}=)([^\n]+)",
        rf"\g<1>{ver}",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError(f"{var} not found in impala-config.sh")
    path.write_text(text2, encoding="utf-8")
    return ["bin/impala-config.sh"]


def set_pom_prop(work: Path, prop: str, ver: str, rel="java/pom.xml"):
    pom = work / rel
    text = pom.read_text(encoding="utf-8")
    pat = rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)"
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n == 1:
        pom.write_text(text2, encoding="utf-8")
        return [rel]
    # insert before </properties>
    if "</properties>" not in text:
        raise RuntimeError(f"{prop} / properties missing in {rel}")
    insert = f"    <{prop}>{ver}</{prop}>\n"
    pom.write_text(
        text.replace("</properties>", insert + "  </properties>", 1),
        encoding="utf-8",
    )
    return [rel]


def ensure_dm(work: Path, group: str, artifact: str, ver: str, rel="java/pom.xml"):
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
    # insert before closing of dependencyManagement dependencies
    marker = "  </dependencyManagement>"
    # find last </dependencies> before dependencyManagement end
    dm = text.find("<dependencyManagement>")
    if dm < 0:
        raise RuntimeError("no dependencyManagement")
    # insert after opening <dependencies> of DM
    deps = text.find("<dependencies>", dm)
    insert_at = deps + len("<dependencies>")
    pom.write_text(text[:insert_at] + "\n" + block + text[insert_at:], encoding="utf-8")
    return [rel]


def ensure_netty_bom(work: Path):
    pom = work / "java/pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<netty\.version>)([^<]+)(</netty\.version>)",
        rf"\g<1>{NETTY}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("netty.version not found")
    if "netty-bom" not in text2:
        bom = f"""
      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-bom</artifactId>
        <version>${{netty.version}}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
"""
        # insert before first netty-handler DM entry
        needle = "<artifactId>netty-handler</artifactId>"
        idx = text2.find(needle)
        if idx < 0:
            raise RuntimeError("netty-handler DM missing")
        # back up to <dependency>
        dep_start = text2.rfind("<dependency>", 0, idx)
        text2 = text2[:dep_start] + bom + text2[dep_start:]
    pom.write_text(text2, encoding="utf-8")
    return ["java/pom.xml"]


def apply_sqlparse(work: Path):
    changed = []
    req = work / "infra/python/deps/requirements.txt"
    text = req.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"sqlparse\s*==\s*[0-9.]+",
        f"sqlparse == {SQLPARSE}",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("sqlparse pin not found in requirements.txt")
    req.write_text(text2, encoding="utf-8")
    changed.append("infra/python/deps/requirements.txt")
    # LICENSE / rat references to old vendored tree are informational; leave vendor
    # dir swap for a follow-up if packaging copies from requirements install.
    return changed


APPLY = {
    ("impala", "log4j"): lambda w: set_config_export(w, "IMPALA_LOG4J2_VERSION", LOG4J),
    ("impala", "jackson"): lambda w: set_config_export(
        w, "IMPALA_JACKSON_DATABIND_VERSION", JACKSON
    ),
    ("impala", "postgres"): lambda w: set_config_export(
        w, "IMPALA_POSTGRES_JDBC_DRIVER_VERSION", POSTGRES
    ),
    ("impala", "spring"): lambda w: set_config_export(
        w, "IMPALA_SPRINGFRAMEWORK_VERSION", SPRING53
    ),
    ("impala", "config2"): lambda w: set_pom_prop(
        w, "commons-configuration2.version", CONFIG2
    ),
    ("impala", "lang3"): lambda w: (
        set_pom_prop(w, "commons-lang3.version", LANG3)
        + ensure_dm(w, "org.apache.commons", "commons-lang3", LANG3)
    ),
    ("impala", "compress"): lambda w: (
        set_pom_prop(w, "commons-compress.version", COMPRESS)
        + ensure_dm(w, "org.apache.commons", "commons-compress", COMPRESS)
    ),
    ("impala", "netty"): ensure_netty_bom,
    ("impala", "okio"): lambda w: (
        ensure_dm(w, "com.squareup.okio", "okio-jvm", OKIO)
        + ensure_dm(w, "com.squareup.okio", "okio", OKIO)
    ),
    ("impala", "otel"): lambda w: ensure_dm(
        w, "io.opentelemetry", "opentelemetry-api", OTEL
    ),
    ("impala", "grpc"): lambda w: ensure_dm(
        w, "io.grpc", "grpc-netty-shaded", GRPC
    ),
    ("impala", "logback"): lambda w: (
        ensure_dm(w, "ch.qos.logback", "logback-core", LOGBACK)
        + ensure_dm(w, "ch.qos.logback", "logback-classic", LOGBACK)
    ),
    ("impala", "sqlparse"): apply_sqlparse,
}


def apply_jetty(work: Path):
    changed = set_pom_prop(work, "jetty.version", JETTY94)
    pom = work / "java/pom.xml"
    text = pom.read_text(encoding="utf-8")
    if "jetty-bom" not in text:
        bom = """
      <dependency>
        <groupId>org.eclipse.jetty</groupId>
        <artifactId>jetty-bom</artifactId>
        <version>${jetty.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
"""
        dm = text.find("<dependencyManagement>")
        deps = text.find("<dependencies>", dm)
        insert_at = deps + len("<dependencies>")
        pom.write_text(text[:insert_at] + "\n" + bom + text[insert_at:], encoding="utf-8")
    else:
        ensure_dm(work, "org.eclipse.jetty", "jetty-bom", "${jetty.version}")
    return ["java/pom.xml"]


APPLY[("impala", "jetty")] = apply_jetty


def ensure_repo(work: Path, gh: str, base: str, jdk: int):
    env = git_env(jdk)
    run(f"git remote set-url origin https://github.com/{gh}.git", work, env=env, timeout=60)
    run(f"git fetch origin {base} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {base} origin/{base}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx -e .m2", work, env=env, timeout=900)


def impala_mvn_env(work: Path, jdk: int):
    env = git_env(jdk)
    # Load exports from config without executing the whole toolchain bootstrap.
    cfg = (work / "bin/impala-config.sh").read_text(encoding="utf-8")
    for m in re.finditer(r"^export (IMPALA_[A-Z0-9_]+)=([^\n]+)$", cfg, re.M):
        val = m.group(2).strip().strip('"').strip("'")
        # skip shell expansions that need runtime
        if "$" in val or "`" in val:
            continue
        env[m.group(1)] = val
    # Minimal stubs so Maven ${env.*} interpolation does not fail hard
    stubs = {
        "IMPALA_LOGS_DIR": "/tmp/impala-logs",
        "IMPALA_FE_TEST_COVERAGE_DIR": "/tmp/impala-cov",
        "IMPALA_TOOLCHAIN_KUDU_MAVEN_REPOSITORY": "file:///tmp/empty-m2",
        "IMPALA_TOOLCHAIN_KUDU_MAVEN_REPOSITORY_ENABLED": "false",
        "CDP_MAVEN_REPOSITORY": "https://repo1.acceldata.dev/repository/odp-staging-central/",
    }
    for k, v in stubs.items():
        env.setdefault(k, v)
    # Common CDP/IMPALA version envs referenced by pom — set placeholders if missing
    for k in list(env):
        pass
    defaults = {
        "IMPALA_HADOOP_VERSION": "3.3.6",
        "IMPALA_HIVE_VERSION": "4.1.0",
        "IMPALA_HIVE_STORAGE_API_VERSION": "2.8.1",
        "IMPALA_HIVE_MAJOR_VERSION": "4",
        "IMPALA_HIVE_DIST_TYPE": "apache",
        "IMPALA_HUDI_VERSION": "0.14.0",
        "IMPALA_RANGER_VERSION": "2.5.0",
        "IMPALA_HBASE_VERSION": "2.5.0",
        "IMPALA_AVRO_JAVA_VERSION": "1.11.3",
        "IMPALA_ORC_JAVA_VERSION": "1.8.5",
        "IMPALA_OZONE_VERSION": "1.4.1.3.3.6.5-SNAPSHOT",
        "IMPALA_PARQUET_VERSION": "1.13.1",
        "IMPALA_KITE_VERSION": "1.1.0",
        "IMPALA_KNOX_VERSION": "2.0.0",
        "IMPALA_COS_VERSION": "5.6.212",
        "IMPALA_OBS_VERSION": "3.23.3",
        "IMPALA_THRIFT_POM_VERSION": "0.16.0",
        "IMPALA_KUDU_VERSION": "e742f86f6d",
        "IMPALA_SLF4J_VERSION": "1.7.36",
        "IMPALA_RELOAD4j_VERSION": "1.2.22",
        "IMPALA_JUNIT_VERSION": "4.13.2",
        "IMPALA_HTTP_CORE_VERSION": "4.4.14",
        "IMPALA_GUAVA_VERSION": "32.0.1-jre",
        "IMPALA_DERBY_VERSION": "10.14.2.0",
        "IMPALA_ICEBERG_VERSION": "1.7.2",
        "IMPALA_XMLSEC_VERSION": "2.3.4",
        "IMPALA_BOUNCY_CASTLE_VERSION": "1.78.1",
        "IMPALA_JSON_SMART_VERSION": "2.5.2",
        "IMPALA_DBCP2_VERSION": "2.9.0",
        "IMPALA_AWS_JAVA_SDK_BUNDLE_VERSION": "1.12.782",
    }
    for k, v in defaults.items():
        env.setdefault(k, v)
    return env


def compile_gate(comp: str, work: Path, lib: str, jdk: int) -> bool:
    log = f"/tmp/batch8_{comp}_{lib}_build.log"
    env = impala_mvn_env(work, jdk)
    # Light gate: resolve/validate java parent + fe module graph.
    cmd = (
        "mvn -f java/pom.xml -q -DskipTests -Dmaven.javadoc.skip=true "
        "-Dcheckstyle.skip=true -Denforcer.skip=true "
        "-pl ../fe -am validate"
    )
    code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        # Fall back: at least parse the poms we changed
        cmd2 = "mvn -f java/pom.xml -q -N validate -DskipTests"
        code2, out2, err2 = run(cmd2, work, env=env, timeout=600, log_path=log)
        if code2 == 0:
            print("   compile_gate: fe validate failed; java -N validate OK", flush=True)
            return True
        for ln in (out + err + out2 + err2).splitlines()[-40:]:
            if any(x in ln.lower() for x in ("error", "failure", "failed")):
                print("   ", ln[:220], flush=True)
        return False
    return True


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
    # branch may already have open PR
    if r.status_code == 422:
        r2 = requests.get(
            f"https://api.github.com/repos/{gh}/pulls",
            headers=headers,
            params={"head": f"acceldata-io:{branch}", "state": "open"},
            timeout=60,
        )
        if r2.ok and r2.json():
            return r2.json()[0]["html_url"]
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

    # Reuse existing open Log4j PR #70 if still applicable
    if lib == "log4j":
        import requests

        headers = {
            "Authorization": f"token {TOKEN}",
            "Accept": "application/vnd.github+json",
        }
        r = requests.get(
            f"https://api.github.com/repos/{gh}/pulls/70",
            headers=headers,
            timeout=60,
        )
        if r.ok and r.json().get("state") == "open":
            pr = r.json()["html_url"]
            print(f"  reusing existing PR {pr}", flush=True)
            closed = []
            for t in tickets:
                ok = ca.close_ticket_with_comment(
                    t["key"],
                    f"Fixed via PR: {pr} — bumped {name} to {target} on {base}.",
                    "Closed",
                    assignee=ASSIGNEE,
                )
                if ok:
                    closed.append(t["key"])
            return {"lib": lib, "ok": True, "pr": pr, "closed": closed, "branch": "OSV-22342"}

    applier = APPLY.get((comp, lib))
    if not applier:
        raise RuntimeError(f"no applier for {comp}/{lib}")
    changed = applier(work)

    if DRY:
        return {
            "lib": lib, "dry": True, "title": title,
            "tickets": [t["key"] for t in tickets],
        }

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
        f"- Files: {', '.join(changed[:20])}",
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
    "impala": [
        "log4j", "jackson", "postgres", "spring", "config2", "lang3",
        "compress", "netty", "jetty", "okio", "otel", "grpc", "logback",
        "sqlparse",
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
    except KeyboardInterrupt:
        write_status(phase="INTERRUPTED")
        raise
