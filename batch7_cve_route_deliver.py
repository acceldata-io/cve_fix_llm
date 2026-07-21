#!/usr/bin/env python3
"""Batch CVE deliver for trino, trino-gateway (release 3.3.6.4).

Separate PR per library.
Status: /tmp/batch7_cve_status.json
Summary: /root/cve_fix_llm/reports/batch7_status.md

  CVE_DRY_RUN=1 / CVE_ROUTE_ONLY=1 / CVE_COMPONENTS=trino,trino-gateway
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
STATUS = Path("/tmp/batch7_cve_status.json")
SUMMARY = Path("/root/cve_fix_llm/reports/batch7_status.md")
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "7200"))
TOKEN = ""

JETTY = "12.0.34"
JACKSON = "2.21.1"
JACKSON_GW = "2.18.6"
LOGBACK = "1.5.25"
OTEL = "1.62.0"
CONFIG2 = "2.15.0"
LZ4 = "1.10.1"
GRPC = "1.75.0"
BCPROV = "1.84"
REACTOR_NETTY = "1.2.8"
SNOWFLAKE = "3.23.1"
LANG3 = "3.18.0"
NIMBUS = "10.0.2"
MAIL20 = "2.0.2"
AIRCOMPRESSOR_V3 = "3.4"
JSON_SMART = "2.5.2"
MINA = "2.2.7"

COMPONENTS = {
    "trino": {
        "jira": "sehajsandhu/trino",
        "gh": "acceldata-io/trino",
        "work": ROOT / "trino",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 23,
        "exclude_jira_substr": "trino-gateway",
    },
    "trino-gateway": {
        "jira": "sehajsandhu/trino-gateway",
        "gh": "acceldata-io/trino-gateway",
        "work": ROOT / "trino-gateway",
        "base": "nightly/ODP-3.3.6.5",
        "jdk": 23,
    },
}

FILTER = [
    c.strip()
    for c in os.environ.get("CVE_COMPONENTS", "trino,trino-gateway").split(",")
    if c.strip()
]

GO_LIBS = {
    "crypto/tls", "crypto/x509", "net", "net/http", "net/url", "os/exec",
    "crypto/tls_crypto/tls", "crypto/x509_crypto/x509",
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


def write_summary(results: dict):
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Batch7 CVE status ({RELEASE})",
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
        f"/usr/lib/jvm/temurin-{jdk}",
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


def git_env(jdk: int = 23):
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


def classify_trino(row):
    pkg = (row["pkg"] or "").lower()
    path = (row["path"] or "").lower()
    art = pkg.split("_")[-1] if "_" in pkg else pkg

    go_markers = (
        "crypto/tls", "crypto/x509", "net/http", "net/url", "os/exec",
    )
    if (
        pkg in ("net", "os")
        or art in ("net", "os")
        or any(m in pkg or m in art for m in go_markers)
    ):
        return "exception", (
            "Go stdlib advisory (crypto/tls, crypto/x509, net, os, …); remediation "
            "is Go toolchain/image rebuild, not a Maven pin. "
            "Exception Request (Deferred)."
        )
    if "kafka-clients" in pkg:
        return "exception", (
            "kafka-clients is the ODP platform artifact "
            f"({row.get('ver')}); bump belongs to Kafka/ODP, not Trino alone. "
            "Exception Request (Deferred)."
        )
    if "ranger-plugins" in pkg:
        return "exception", (
            "ranger-plugins-common fix requires Ranger 2.8.0; belongs to Ranger. "
            "Exception Request (Deferred)."
        )
    if "trino-iceberg" in pkg or (art == "trino-iceberg"):
        return "exception", (
            "Advisory requires a newer Trino release line (480+); this branch is "
            "472.x. Exception Request (Deferred)."
        )
    if "libthrift" in pkg or "thrift" in pkg and "libthrift" in path:
        return "exception", (
            "libthrift 0.23.0 is a breaking major from 0.21.0 for Pinot. "
            "Exception Request (Deferred)."
        )
    if "commons-lang" in pkg and "lang3" not in pkg:
        return "exception", (
            "commons-lang 2.6 has no upstream fix on the 2.x line. "
            "Exception Request (Deferred)."
        )
    if "guava" in pkg and "clickhouse" in path:
        return "exception", (
            "Guava is shaded inside clickhouse-jdbc-*-all.jar; owner must rebuild "
            "the fat jar. Exception Request (Deferred)."
        )
    if "wire-runtime" in pkg:
        return "exception", (
            "wire-runtime-jvm has no published fixed version for this advisory. "
            "Exception Request (Deferred)."
        )
    if "jetty" in pkg:
        return "fix_jetty", {"target": JETTY, "lib": "jetty", "name": "Jetty"}
    if "jackson" in pkg:
        return "fix_jackson", {
            "target": JACKSON, "lib": "jackson", "name": "Jackson",
        }
    if "logback" in pkg:
        return "fix_logback", {
            "target": LOGBACK, "lib": "logback", "name": "logback",
        }
    if "opentelemetry" in pkg:
        return "fix_otel", {
            "target": OTEL, "lib": "otel", "name": "OpenTelemetry",
        }
    if "configuration2" in pkg:
        return "fix_config2", {
            "target": CONFIG2, "lib": "config2", "name": "commons-configuration2",
        }
    if "lz4" in pkg:
        return "fix_lz4", {"target": LZ4, "lib": "lz4", "name": "lz4-java"}
    if "grpc-netty-shaded" in pkg or "grpc-netty" in pkg:
        return "fix_grpc", {
            "target": GRPC, "lib": "grpc", "name": "grpc-netty-shaded",
        }
    if "bcprov" in pkg or "bouncycastle" in pkg:
        return "fix_bcprov", {
            "target": BCPROV, "lib": "bcprov", "name": "bcprov-jdk18on",
        }
    if "reactor-netty" in pkg:
        return "fix_reactor", {
            "target": REACTOR_NETTY, "lib": "reactor", "name": "reactor-netty",
        }
    if "snowflake" in pkg:
        return "fix_snowflake", {
            "target": SNOWFLAKE, "lib": "snowflake", "name": "snowflake-jdbc",
        }
    return "unknown", f"No rule for {pkg} path={path}"


def classify_gateway(row):
    pkg = (row["pkg"] or "").lower()

    if "aircompressor" in pkg:
        return "fix_aircompressor", {
            "target": AIRCOMPRESSOR_V3, "lib": "aircompressor",
            "name": "aircompressor-v3",
        }
    if "commons-lang3" in pkg or "commons_lang3" in pkg:
        return "fix_lang3", {
            "target": LANG3, "lib": "lang3", "name": "commons-lang3",
        }
    if "jackson" in pkg:
        return "fix_jackson", {
            "target": JACKSON_GW, "lib": "jackson", "name": "Jackson",
        }
    if "jakarta.mail" in pkg or pkg.endswith("_jakarta.mail"):
        return "fix_mail", {
            "target": MAIL20, "lib": "mail", "name": "jakarta.mail",
        }
    if "jetty" in pkg:
        return "fix_jetty", {"target": JETTY, "lib": "jetty", "name": "Jetty"}
    if "json-smart" in pkg:
        return "fix_jsonsmart", {
            "target": JSON_SMART, "lib": "jsonsmart", "name": "json-smart",
        }
    if "logback" in pkg:
        return "fix_logback", {
            "target": LOGBACK, "lib": "logback", "name": "logback",
        }
    if "mina" in pkg:
        return "fix_mina", {"target": MINA, "lib": "mina", "name": "mina-core"}
    if "nimbus" in pkg:
        return "fix_nimbus", {
            "target": NIMBUS, "lib": "nimbus", "name": "nimbus-jose-jwt",
        }
    return "unknown", f"No rule for {pkg}"


CLASSIFY = {
    "trino": classify_trino,
    "trino-gateway": classify_gateway,
}


def set_or_insert_prop(pom: Path, prop: str, ver: str):
    text = pom.read_text(encoding="utf-8")
    pat = rf"(<{re.escape(prop)}>)([^<]+)(</{re.escape(prop)}>)"
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n == 1:
        pom.write_text(text2, encoding="utf-8")
        return
    # insert before </properties>
    if "</properties>" not in text:
        raise RuntimeError(f"no properties / {prop} in {pom}")
    insert = f"        <{prop}>{ver}</{prop}>\n"
    text2 = text.replace("</properties>", insert + "    </properties>", 1)
    pom.write_text(text2, encoding="utf-8")


def replace_bom_version(pom: Path, artifact: str, ver: str):
    text = pom.read_text(encoding="utf-8")
    pat = (
        rf"(<artifactId>{re.escape(artifact)}</artifactId>\s*"
        rf"<version>)([^<]+)(</version>)"
    )
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n != 1:
        raise RuntimeError(f"{artifact} version not found in {pom}")
    pom.write_text(text2, encoding="utf-8")


def ensure_dm_artifact(pom: Path, group: str, artifact: str, ver: str):
    """Ensure a dependencyManagement entry exists (insert or replace version)."""
    text = pom.read_text(encoding="utf-8")
    pat = (
        rf"(<groupId>{re.escape(group)}</groupId>\s*"
        rf"<artifactId>{re.escape(artifact)}</artifactId>\s*"
        rf"<version>)([^<]+)(</version>)"
    )
    text2, n = re.subn(pat, rf"\g<1>{ver}\g<3>", text, count=1)
    if n >= 1:
        pom.write_text(text2, encoding="utf-8")
        return
    block = f"""
            <dependency>
                <groupId>{group}</groupId>
                <artifactId>{artifact}</artifactId>
                <version>{ver}</version>
            </dependency>
"""
    # insert after <dependencyManagement>\n        <dependencies>
    marker = "<dependencyManagement>"
    if marker not in text:
        raise RuntimeError(f"no dependencyManagement in {pom}")
    # find first <dependencies> after dependencyManagement
    dm = text.find(marker)
    deps = text.find("<dependencies>", dm)
    if deps < 0:
        raise RuntimeError(f"no dependencies under dependencyManagement in {pom}")
    insert_at = deps + len("<dependencies>")
    text2 = text[:insert_at] + "\n" + block + text[insert_at:]
    pom.write_text(text2, encoding="utf-8")


def apply_trino_jetty(work: Path):
    pom = work / "pom.xml"
    replace_bom_version(pom, "jetty-bom", JETTY)
    replace_bom_version(pom, "jetty-ee10-bom", JETTY)
    return ["pom.xml"]


def apply_trino_jackson(work: Path):
    pom = work / "pom.xml"
    set_or_insert_prop(pom, "dep.jackson.version", JACKSON)
    pinot = work / "plugin/trino-pinot/pom.xml"
    text = pinot.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<artifactId>jackson-(?:annotations|core|databind)</artifactId>\s*"
        r"<version>)2\.19\.[0-9]+(</version>)",
        rf"\g<1>{JACKSON}\g<2>",
        text,
    )
    if n:
        pinot.write_text(text2, encoding="utf-8")
        return ["pom.xml", "plugin/trino-pinot/pom.xml"]
    return ["pom.xml"]


def apply_trino_logback(work: Path):
    set_or_insert_prop(work / "pom.xml", "dep.logback.version", LOGBACK)
    return ["pom.xml"]


def apply_trino_otel(work: Path):
    pom = work / "pom.xml"
    set_or_insert_prop(pom, "dep.opentelemetry.version", OTEL)
    set_or_insert_prop(pom, "dep.opentelemetry-alpha.version", f"{OTEL}-alpha")
    # Keep instrumentation BOM aligned enough to avoid SPI/runtime scope drift.
    # 2.17.0 tracks OpenTelemetry SDK 1.52+; use a recent stable if present.
    set_or_insert_prop(pom, "dep.opentelemetry-instrumentation.version", "2.17.1")
    set_or_insert_prop(
        pom, "dep.opentelemetry-instrumentation-alpha.version", "2.17.1-alpha"
    )
    return ["pom.xml"]


def apply_trino_config2(work: Path):
    ensure_dm_artifact(
        work / "pom.xml",
        "org.apache.commons", "commons-configuration2", CONFIG2,
    )
    return ["pom.xml"]


def apply_trino_lz4(work: Path):
    changed = []
    # org.lz4 relocated to at.yawk.lz4; 1.10.1 only published under at.yawk.lz4
    for rel in (
        "pom.xml",
        "plugin/trino-clickhouse/pom.xml",
        "testing/trino-product-tests/pom.xml",
    ):
        pom = work / rel
        if not pom.is_file():
            continue
        text = pom.read_text(encoding="utf-8")
        text2 = text.replace(
            "<groupId>org.lz4</groupId>",
            "<groupId>at.yawk.lz4</groupId>",
        )
        if rel == "pom.xml":
            text2, n = re.subn(
                r"(<artifactId>lz4-java</artifactId>\s*<version>)([^<]+)(</version>)",
                rf"\g<1>{LZ4}\g<3>",
                text2,
                count=1,
            )
            if n != 1:
                raise RuntimeError("lz4-java version not found in root pom")
        if text2 != text:
            pom.write_text(text2, encoding="utf-8")
            changed.append(rel)
    if not changed:
        raise RuntimeError("lz4-java not updated")
    return changed


def apply_trino_grpc(work: Path):
    changed = []
    ensure_dm_artifact(
        work / "pom.xml", "io.grpc", "grpc-netty-shaded", GRPC,
    )
    changed.append("pom.xml")
    pinot = work / "plugin/trino-pinot/pom.xml"
    text = pinot.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<groupId>io\.grpc</groupId>\s*<artifactId>grpc-[a-z0-9-]+"
        r"</artifactId>\s*<version>)1\.(70|73)\.0(</version>)",
        rf"\g<1>{GRPC}\g<3>",
        text,
    )
    if n:
        pinot.write_text(text2, encoding="utf-8")
        changed.append("plugin/trino-pinot/pom.xml")
    return changed


def apply_trino_bcprov(work: Path):
    ensure_dm_artifact(
        work / "pom.xml",
        "org.bouncycastle", "bcprov-jdk18on", BCPROV,
    )
    return ["pom.xml"]


def apply_trino_reactor(work: Path):
    pom = work / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        r"(<artifactId>reactor-netty-core</artifactId>\s*<version>)([^<]+)"
        r"(</version>)",
        rf"\g<1>{REACTOR_NETTY}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("reactor-netty-core not found")
    pom.write_text(text2, encoding="utf-8")
    ensure_dm_artifact(
        pom, "io.projectreactor.netty", "reactor-netty-http", REACTOR_NETTY,
    )
    return ["pom.xml"]


def apply_trino_snowflake(work: Path):
    set_or_insert_prop(work / "pom.xml", "dep.snowflake.version", SNOWFLAKE)
    return ["pom.xml"]


def apply_gw_prop(work: Path, prop: str, ver: str):
    set_or_insert_prop(work / "pom.xml", prop, ver)
    return ["pom.xml"]


def apply_gw_jetty(work: Path):
    return apply_gw_prop(work, "dep.jetty.version", JETTY)


def apply_gw_jackson(work: Path):
    return apply_gw_prop(work, "dep.jackson.version", JACKSON_GW)


def apply_gw_logback(work: Path):
    return apply_gw_prop(work, "dep.logback.version", LOGBACK)


def apply_gw_explicit(work: Path, artifact: str, ver: str, rel="gateway-ha/pom.xml"):
    pom = work / rel
    text = pom.read_text(encoding="utf-8")
    text2, n = re.subn(
        rf"(<artifactId>{re.escape(artifact)}</artifactId>\s*<version>)([^<]+)"
        rf"(</version>)",
        rf"\g<1>{ver}\g<3>",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError(f"{artifact} version not found in {rel}")
    pom.write_text(text2, encoding="utf-8")
    return [rel]


def apply_gw_force_dm(work: Path, group: str, artifact: str, ver: str):
    ensure_dm_artifact(work / "pom.xml", group, artifact, ver)
    return ["pom.xml"]


APPLY = {
    ("trino", "jetty"): apply_trino_jetty,
    ("trino", "jackson"): apply_trino_jackson,
    ("trino", "logback"): apply_trino_logback,
    ("trino", "otel"): apply_trino_otel,
    ("trino", "config2"): apply_trino_config2,
    ("trino", "lz4"): apply_trino_lz4,
    ("trino", "grpc"): apply_trino_grpc,
    ("trino", "bcprov"): apply_trino_bcprov,
    ("trino", "reactor"): apply_trino_reactor,
    ("trino", "snowflake"): apply_trino_snowflake,
    ("trino-gateway", "jetty"): apply_gw_jetty,
    ("trino-gateway", "jackson"): apply_gw_jackson,
    ("trino-gateway", "logback"): apply_gw_logback,
    ("trino-gateway", "nimbus"): lambda w: apply_gw_explicit(
        w, "nimbus-jose-jwt", NIMBUS
    ),
    ("trino-gateway", "mail"): lambda w: apply_gw_explicit(w, "jakarta.mail", MAIL20),
    ("trino-gateway", "aircompressor"): lambda w: apply_gw_explicit(
        w, "aircompressor-v3", AIRCOMPRESSOR_V3
    ),
    ("trino-gateway", "lang3"): lambda w: apply_gw_force_dm(
        w, "org.apache.commons", "commons-lang3", LANG3
    ),
    ("trino-gateway", "jsonsmart"): lambda w: apply_gw_force_dm(
        w, "net.minidev", "json-smart", JSON_SMART
    ),
    ("trino-gateway", "mina"): lambda w: apply_gw_force_dm(
        w, "org.apache.mina", "mina-core", MINA
    ),
}


def ensure_repo(work: Path, gh: str, base: str, jdk: int):
    env = git_env(jdk)
    run(f"git remote set-url origin https://github.com/{gh}.git", work, env=env, timeout=60)
    run(f"git fetch origin {base} --prune", work, env=env, timeout=600)
    run(f"git checkout -B {base} origin/{base}", work, env=env, timeout=120)
    run("git reset --hard HEAD && git clean -fdx", work, env=env, timeout=900)


def compile_gate(comp: str, work: Path, lib: str, jdk: int) -> bool:
    log = f"/tmp/batch7_{comp}_{lib}_build.log"
    env = git_env(jdk)
    skip = (
        "-DskipTests -Dair.check.skip-all=true -Dair.check.skip-spotbugs=true "
        "-Dair.check.skip-pmd=true -Dair.check.skip-checkstyle=true "
        "-Dair.check.skip-enforcer=true -Dmaven.javadoc.skip=true"
    )
    if comp == "trino":
        cmd = (
            f"mvn -q {skip} -Pdisable-check-spi-dependencies "
            f"-pl core/trino-spi,core/trino-main -am package"
        )
    elif comp == "trino-gateway":
        cmd = f"mvn -q {skip} -pl gateway-ha -am package"
    else:
        raise RuntimeError(comp)
    code, out, err = run(cmd, work, env=env, timeout=TIMEOUT, log_path=log)
    if code != 0:
        for ln in (out + err).splitlines()[-60:]:
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
    "trino": [
        "jetty", "jackson", "logback", "otel", "config2",
        "lz4", "grpc", "bcprov", "reactor", "snowflake",
    ],
    "trino-gateway": [
        "jetty", "jackson", "logback", "nimbus", "mail",
        "aircompressor", "lang3", "jsonsmart", "mina",
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
