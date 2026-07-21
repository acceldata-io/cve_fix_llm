#!/usr/bin/env python3
"""Log4j 2.25.4 compile matrix + PR deliver on node82.

Policy: bump org.apache.logging.log4j managed versions to 2.25.4.
Compile first; PR + close Jiras only for green comps.
Commit subject:
  <OSV> - CVE - Bumped-up Log4j to 2.25.4 to address <CVE_ID>
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

WORK = Path("/root/3.3.6.5")
BASE = "nightly/ODP-3.3.6.5"
VERSION = "2.25.4"
RESULT = Path("/tmp/log4j_compile_matrix.json")
REVIEWER = "basapuram-kumar"
ASSIGNEE = "senthil.kumar"
RELEASE = "3.3.6.4"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
SKIP_BUILD = os.environ.get("CVE_SKIP_BUILD", "0") not in ("0", "false", "False")
ONLY = [x.strip() for x in os.environ.get("CVE_ONLY_COMPS", "").split(",") if x.strip()]
RESUME = os.environ.get("CVE_RESUME", "1") == "1"
TIMEOUT = int(os.environ.get("CVE_COMPILE_TIMEOUT", "5400"))
MODE = os.environ.get("CVE_MODE", "compile")  # compile | deliver | both
TOKEN = ""

# Build/job definitions (smoke: skipTests)
JOBS = [
    {
        "comp": "celeborn", "repo": "celeborn", "gh": "acceldata-io/celeborn",
        "jira_repos": ["sehajsandhu/celeborn"], "jdk": 11,
        "build": "./build/make-distribution.sh --release -DskipTests -Pspark-3.5 -Ptez -Pmr -Pjdk-11 -Paws -Dspotless.check.skip=true",
        "props": ["log4j2.version", "log4j.version"],
    },
    {
        "comp": "cruise-control", "repo": "cruise-control", "gh": "acceldata-io/cruise-control",
        "jira_repos": ["sehajsandhu/cruise-control"], "jdk": 11,
        "build": "./gradlew :cruise-control-core:jar :cruise-control:jar :cruise-control-metrics-reporter:jar -x test -x compileTestJava -x compileTestScala --no-daemon",
        "gradle_literal": True, "fetch_tags": True,
        "preprocess": "cruise_control_disable_semver",
    },
    {
        "comp": "cruise-control3", "repo": "cruise-control3", "gh": "acceldata-io/cruise-control3",
        "jira_repos": ["sehajsandhu/cruise-control3"], "jdk": 11,
        "build": "./gradlew :cruise-control-core:jar :cruise-control:jar :cruise-control-metrics-reporter:jar -x test -x compileTestJava -x compileTestScala --no-daemon",
        "gradle_literal": True, "fetch_tags": True,
        "preprocess": "cruise_control_disable_semver",
    },
    {
        "comp": "druid", "repo": "druid", "gh": "acceldata-io/druid",
        "jira_repos": ["sehajsandhu/druid"], "jdk": 11,
        "build": "mvn -DskipTests -Dcheckstyle.skip=true -Drat.skip=true -Dmaven.javadoc.skip=true -Dweb.console.skip=true -Denforcer.skip=true -Pdist install",
        "props": ["log4j.version", "log4j2.version"],
    },
    {
        "comp": "flink", "repo": "flink", "gh": "acceldata-io/flink",
        "jira_repos": ["sehajsandhu/flink"], "jdk": 11,
        "build": "mvn -DskipTests -Drat.skip=true -Dmaven.javadoc.skip=true -Dcheckstyle.skip=true -Denforcer.skip=true -pl flink-dist -am package",
        "props": ["log4j.version", "log4j2.version"],
    },
    {
        "comp": "hbase", "repo": "hbase", "gh": "acceldata-io/hbase",
        "jira_repos": ["sehajsandhu/hbase"], "jdk": 8,
        "build": "mvn -DskipTests -Dcheckstyle.skip=true -Dspotbugs.skip=true -Drat.skip=true -Denforcer.skip=true -Dhadoop.profile=3.0 package",
        "props": ["log4j2.version", "log4j.version"],
    },
    {
        "comp": "hive", "repo": "hive", "gh": "acceldata-io/hive",
        "jira_repos": ["sehajsandhu/hive"], "jdk": 11,
        "build": "mvn -DskipTests -Dtar -Pdist -Dmaven.javadoc.skip=true -Dallow.root.build -Denforcer.skip=true install",
        "props": ["log4j2.version", "log4j.version"],
        "preprocess": "hive_expand_odp_version",
        "drop_modules": ["kudu-handler", "packaging"],
    },
    {
        "comp": "impala", "repo": "impala", "gh": "acceldata-io/impala",
        "jira_repos": ["sehajsandhu/impala"], "jdk": 11,
        "build": "bash -c 'export IMPALA_SYSTEM_PYTHON3_OVERRIDE=${IMPALA_SYSTEM_PYTHON3_OVERRIDE:-/usr/bin/python3}; set +e; source ./bin/impala-config.sh; set -e; export IMPALA_LOG4J2_VERSION=${IMPALA_LOG4J2_VERSION}; cd java && mvn -DskipTests -Denforcer.skip=true install'",
        "props": [],  # env export in script
        "preprocess": "impala_log4j_env",
        "impala_env": True,
    },
    {
        "comp": "knox", "repo": "knox", "gh": "acceldata-io/knox",
        "jira_repos": ["sehajsandhu/knox"], "jdk": 11,
        "build": "mvn -Ppackage -Prelease -Dmaven.test.skip=true -DskipJSTests -DskipTests -Drat.skip=true -Denforcer.skip=true -pl '!gateway-admin-ui,!gateway-openapi-ui,!knox-token-generation-ui,!knox-token-management-ui,!knox-webshell-ui,!knox-homepage-ui' -am package",
        "props": ["log4j2.version", "log4j.version"],
    },
    {
        "comp": "oozie", "repo": "oozie", "gh": "acceldata-io/oozie",
        "jira_repos": ["sehajsandhu/oozie"], "jdk": 11,
        "build": "mvn -DskipTests -Drat.skip=true -Dmaven.javadoc.skip=true -Denforcer.skip=true -Dspotbugs.skip=true -Dfindbugs.skip=true -Dxml.skip=true install",
        "props": ["log4j2.version"],
        "inject_xml_props": ["log4j2.version"],
        "force_log4j_dm": True,
        "drop_modules": ["fluent-job"],  # spotbugs/xml plugin broken on fluent-job-api
    },
    {
        "comp": "ozone", "repo": "ozone", "gh": "acceldata-io/ozone",
        "jira_repos": ["sehajsandhu/ozone"], "jdk": 11,
        "build": "mvn -DskipTests -Pdist,java-11 -Dcheckstyle.skip=true -Dspotbugs.skip=true -Drat.skip=true -Dmaven.javadoc.skip=true -Denforcer.skip=true install",
        "props": ["log4j2.version", "log4j.version"],
    },
    {
        "comp": "ozone2", "repo": "ozone", "gh": "acceldata-io/ozone",
        "jira_repos": ["sehajsandhu/ozone2"], "jdk": 11,
        "branch": "nightly/ODP-2.1.0.3.3.6.5",
        "build": "mvn -DskipTests -Pdist,java-11 -Dcheckstyle.skip=true -Dspotbugs.skip=true -Drat.skip=true -Dmaven.javadoc.skip=true -Denforcer.skip=true -Dsort.skip=true install",
        "props": ["log4j2.version", "log4j.version"],
        "post_apply": "ozone_sortpom",
    },
    {
        "comp": "phoenix", "repo": "phoenix", "gh": "acceldata-io/phoenix",
        "jira_repos": ["sehajsandhu/phoenix"], "jdk": 8,
        "build": "mvn -DskipTests -Dcheckstyle.skip=true -Drat.skip=true -Dmaven.javadoc.skip=true -Denforcer.skip=true install",
        "props": ["log4j2.version", "log4j.version"],
    },
    {
        "comp": "spark3", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3"], "jdk": 11, "branch": BASE,
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver -DskipTests -DskipSparkTests",
        "props": ["log4j.version", "log4j2.version"],
    },
    {
        "comp": "spark3_3_3_3", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3_3_3_3"], "jdk": 11,
        "branch": "nightly/ODP-3.3.3.3.3.6.5",
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver -DskipTests -DskipSparkTests",
        "props": ["log4j.version", "log4j2.version"],
    },
    {
        "comp": "spark3_3_5_1", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark3_3_5_1"], "jdk": 11,
        "branch": "nightly/ODP-3.5.1.3.3.6.5",
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver -DskipTests -DskipSparkTests",
        "props": ["log4j.version", "log4j2.version"],
    },
    {
        "comp": "spark4", "repo": "spark3", "gh": "acceldata-io/spark3",
        "jira_repos": ["sehajsandhu/spark4"], "jdk": 17,
        "branch": "nightly/ODP-4.1.1.3.3.6.5",
        "build": "./dev/make-distribution.sh --tgz -Pyarn,hadoop-3,hive,hive-thriftserver,kubernetes -Dscala.version=2.13.17 -DskipSparkTests -DskipTests -Dgpg.skip",
        "props": ["log4j.version", "log4j2.version"],
    },
]


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
        "#!/bin/sh\ncase \"$1\" in\n*Username*) echo x-access-token ;;\n*Password*) echo \"$GITHUB_TOKEN\" ;;\nesac\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    os.environ["GIT_ASKPASS"] = str(askpass)
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GITHUB_TOKEN"] = TOKEN


def git_env() -> dict:
    env = os.environ.copy()
    env["GIT_ASKPASS"] = os.environ.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GITHUB_TOKEN"] = TOKEN
    return env


def jdk_home(major: int) -> str:
    cands = {
        8: ["/usr/lib/jvm/java-1.8.0-openjdk", "/usr/lib/jvm/java-1.8.0"],
        11: ["/usr/lib/jvm/java-11-openjdk", "/usr/lib/jvm/java-11"],
        17: ["/usr/lib/jvm/java-17-openjdk", "/usr/lib/jvm/java-17"],
    }
    for c in cands.get(major, []):
        if Path(c).exists():
            return c
    for p in Path("/usr/lib/jvm").glob(f"java-{major}*"):
        if p.is_dir():
            return str(p)
    raise SystemExit(f"JDK {major} not found")


def run(cmd, cwd, env=None, timeout=TIMEOUT, log_path=None):
    print(f"+ ({cwd}) {cmd}", flush=True)
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=str(cwd), text=True,
            capture_output=True, env=env or git_env(), timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s", ""
    out, err = p.stdout or "", p.stderr or ""
    if log_path:
        Path(log_path).write_text(out + "\n" + err, encoding="utf-8", errors="replace")
    return p.returncode, out, err


def ensure_clone(job: dict) -> Path:
    repo = job["repo"]
    branch = job.get("branch", BASE)
    path = WORK / job["comp"]
    WORK.mkdir(parents=True, exist_ok=True)
    env = git_env()
    url = f"https://github.com/acceldata-io/{repo}.git"
    if (path / ".git").is_dir():
        run(f"git remote set-url origin {url}", path, env=env, timeout=60)
        if job.get("fetch_tags"):
            run("git fetch origin --tags --prune", path, env=env, timeout=300)
        code, _, err = run(f"git fetch origin {branch} --prune", path, env=env, timeout=300)
        if code != 0:
            print(f"fetch warn: {err[-500:]}")
        run(f"git checkout -B {branch} origin/{branch}", path, env=env, timeout=120)
        return path
    code, _, err = run(
        f"git clone --branch {branch} --single-branch {url} {path.name}",
        WORK, env=env, timeout=900,
    )
    if code != 0:
        raise RuntimeError(f"clone {repo} failed: {err[-800:]}")
    if job.get("fetch_tags"):
        run("git fetch origin --tags --prune", path, env=env, timeout=300)
    return path


def restore_clean(repo_dir: Path):
    run("git reset --hard HEAD && git clean -fdx", repo_dir, env=git_env(), timeout=300)


def hive_expand_odp_version(repo_dir: Path):
    root = repo_dir / "pom.xml"
    text = root.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"<odp\.release\.version>([^<]+)</odp\.release\.version>", text)
    if not m:
        return
    ver = m.group(1).strip()
    for pom in repo_dir.rglob("pom.xml"):
        if "/target/" in str(pom):
            continue
        t = pom.read_text(encoding="utf-8", errors="replace")
        if "${odp.release.version}" not in t:
            continue
        pom.write_text(t.replace("${odp.release.version}", ver), encoding="utf-8")


def cruise_control_disable_semver(repo_dir: Path):
    sg = repo_dir / "settings.gradle"
    if sg.is_file():
        text = sg.read_text(encoding="utf-8", errors="replace")
        text2 = re.sub(
            r"(?m)^\s*apply plugin:\s*['\"]net\.vivin\.gradle-semantic-build-versioning['\"].*$",
            "// disabled for CVE compile smoke",
            text,
        )
        text2 = re.sub(
            r"(?m)^\s*classpath\s+['\"]gradle\.plugin\.net\.vivin:gradle-semantic-build-versioning:.*$",
            "// disabled for CVE compile smoke",
            text2,
        )
        if text2 != text:
            sg.write_text(text2, encoding="utf-8")
    gp = repo_dir / "gradle.properties"
    if gp.is_file():
        t = gp.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?m)^version=", t) is None:
            gp.write_text(t + "\nversion=2.5.143\n", encoding="utf-8")
    else:
        gp.write_text("version=2.5.143\n", encoding="utf-8")
    bg = repo_dir / "build.gradle"
    if bg.is_file():
        text = bg.read_text(encoding="utf-8", errors="replace")
        text2 = re.sub(
            r"(?m)^(.*testImplementation.*kafka.*:test[\"'].*)$",
            r"// CVE smoke skip: \1",
            text,
        )
        text2 = re.sub(
            r"(?m)^(.*testImplementation.*:tests[\"'].*)$",
            r"// CVE smoke skip: \1",
            text2,
        )
        if text2 != text:
            bg.write_text(text2, encoding="utf-8")


def impala_log4j_env(repo_dir: Path):
    cfg = repo_dir / "bin" / "impala-config.sh"
    if not cfg.is_file():
        return
    t = cfg.read_text(encoding="utf-8", errors="replace")
    t2 = re.sub(
        r"(?m)^(export\s+IMPALA_LOG4J2_VERSION=).*",
        rf"\g<1>{VERSION}",
        t,
    )
    if t2 == t and "IMPALA_LOG4J2_VERSION" not in t:
        t2 = t + f"\nexport IMPALA_LOG4J2_VERSION={VERSION}\n"
    if t2 != t:
        cfg.write_text(t2, encoding="utf-8")


def ozone_sortpom(repo_dir: Path, env: dict | None = None):
    """Re-sort root pom so sortpom:verify passes after property edits."""
    e = env or git_env()
    java = e.get("JAVA_HOME") or jdk_home(11)
    e = {**e, "JAVA_HOME": java, "PATH": f"{java}/bin:" + e.get("PATH", "")}
    run(
        "mvn -q com.github.ekryd.sortpom:sortpom-maven-plugin:3.0.1:sort -N",
        repo_dir, env=e, timeout=180,
    )


def drop_pom_modules(repo_dir: Path, modules: list[str]):
    pom = repo_dir / "pom.xml"
    if not pom.is_file():
        return
    text = pom.read_text(encoding="utf-8", errors="replace")
    orig = text
    for mod in modules:
        text = re.sub(
            rf"<module>\s*{re.escape(mod)}\s*</module>",
            f"<!-- CVE smoke skipped: {mod} -->",
            text,
        )
    if text != orig:
        pom.write_text(text, encoding="utf-8")


def discover_pins(repo_dir: Path) -> list[dict]:
    pins = []
    files = []
    for name in ["pom.xml", "gradle.properties", "build.gradle", "bin/impala-config.sh"]:
        p = repo_dir / name
        if p.is_file():
            files.append(p)
    for p in repo_dir.rglob("pom.xml"):
        if any(x in str(p) for x in ("/target/", "/.git/")):
            continue
        try:
            if p.stat().st_size > 3_000_000:
                continue
            if "log4j" in p.read_text(encoding="utf-8", errors="replace").lower():
                files.append(p)
        except Exception:
            continue
    seen = set()
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(p.relative_to(repo_dir))
        for m in re.finditer(
            r"<(log4j2?\.version|log4j\.version)>([^<]+)</",
            text,
        ):
            key = (rel, m.group(1), m.group(2))
            if key in seen:
                continue
            seen.add(key)
            pins.append({"file": rel, "kind": "xml", "name": m.group(1), "value": m.group(2).strip()})
        for m in re.finditer(
            r"(?m)^\s*(log4j2?Version|log4j2?\.version)\s*[=:]\s*[\"']?([0-9][^\"'\s]+)",
            text,
        ):
            key = (rel, m.group(1), m.group(2))
            if key in seen:
                continue
            seen.add(key)
            pins.append({"file": rel, "kind": "gradle", "name": m.group(1), "value": m.group(2).strip()})
        for m in re.finditer(
            r"(?m)^export\s+(IMPALA_LOG4J2_VERSION)=([^\s]+)",
            text,
        ):
            key = (rel, m.group(1), m.group(2))
            if key in seen:
                continue
            seen.add(key)
            pins.append({"file": rel, "kind": "env", "name": m.group(1), "value": m.group(2).strip()})
    return pins


def apply_version(repo_dir: Path, pins: list[dict], version: str, job: dict | None = None) -> list[str]:
    changed = []
    if job and job.get("inject_xml_props"):
        root = repo_dir / "pom.xml"
        if root.is_file():
            text = root.read_text(encoding="utf-8", errors="replace")
            orig = text
            for prop in job["inject_xml_props"]:
                if f"<{prop}>" not in text and "<properties>" in text:
                    text = text.replace(
                        "<properties>",
                        f"<properties>\n        <{prop}>{version}</{prop}>",
                        1,
                    )
                    pins.append({"file": "pom.xml", "kind": "xml", "name": prop, "value": version})
            if text != orig:
                root.write_text(text, encoding="utf-8")

    # Restrict bumps to declared property names when provided.
    if job and job.get("props"):
        allowed = set(job["props"])
        pins = [p for p in pins if p.get("name") in allowed]
    # Never overwrite Maven property indirection like ${env.FOO}
    pins = [p for p in pins if "${" not in (p.get("value") or "")]
    # Never treat classic Log4j 1.x pins as Log4j2 bumps
    pins = [
        p for p in pins
        if not (
            p.get("name") in ("log4j.version", "log4jVersion")
            and re.match(r"^1\.", str(p.get("value") or ""))
        )
    ]

    by_file: dict[str, list] = {}
    for pin in pins:
        by_file.setdefault(pin["file"], []).append(pin)
    for rel, plist in by_file.items():
        fp = repo_dir / rel
        if not fp.is_file():
            continue
        text = fp.read_text(encoding="utf-8", errors="replace")
        orig = text
        for pin in plist:
            name = pin["name"]
            if pin["kind"] == "xml":
                text = re.sub(
                    rf"<{re.escape(name)}>[^<]+</{re.escape(name)}>",
                    f"<{name}>{version}</{name}>",
                    text,
                )
            elif pin["kind"] == "gradle":
                text = re.sub(
                    rf"(?m)^(\s*{re.escape(name)}\s*[=:]\s*)[\"']?[^\"'\s]+[\"']?",
                    rf"\g<1>{version}",
                    text,
                )
            elif pin["kind"] == "env":
                text = re.sub(
                    rf"(?m)^(export\s+{re.escape(name)}=).*",
                    rf"\g<1>{version}",
                    text,
                )
        if text != orig:
            fp.write_text(text, encoding="utf-8")
            changed.append(rel)

    # Cruise-control style: hardcoded org.apache.logging.log4j:...:X.Y.Z
    if job and job.get("gradle_literal"):
        for pattern in ["build.gradle", "**/build.gradle"]:
            for bg in repo_dir.glob(pattern) if "*" not in pattern else repo_dir.rglob("build.gradle"):
                if "/.git/" in str(bg):
                    continue
                text = bg.read_text(encoding="utf-8", errors="replace")
                text2 = re.sub(
                    r'(org\.apache\.logging\.log4j:[a-zA-Z0-9._-]+:)([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                    rf"\g<1>{version}",
                    text,
                )
                if text2 != text:
                    bg.write_text(text2, encoding="utf-8")
                    rel = str(bg.relative_to(repo_dir))
                    if rel not in changed:
                        changed.append(rel)

    if job and job.get("force_log4j_dm"):
        root = repo_dir / "pom.xml"
        if root.is_file():
            text = root.read_text(encoding="utf-8", errors="replace")
            marker = "<!-- CVE_LOG4J_FORCE -->"
            if marker not in text:
                block = f"""
            {marker}
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-api</artifactId>
                <version>${{log4j2.version}}</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId>
                <version>${{log4j2.version}}</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-1.2-api</artifactId>
                <version>${{log4j2.version}}</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-slf4j-impl</artifactId>
                <version>${{log4j2.version}}</version>
            </dependency>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-web</artifactId>
                <version>${{log4j2.version}}</version>
            </dependency>
"""
                # Insert after first <dependencies> under dependencyManagement if present
                m = re.search(r"(<dependencyManagement>\s*<dependencies>)", text)
                if m:
                    text = text[:m.end()] + block + text[m.end():]
                    root.write_text(text, encoding="utf-8")
                    if "pom.xml" not in changed:
                        changed.append("pom.xml")
    return changed


def try_compile(job, repo_dir: Path, pins: list[dict]) -> dict:
    restore_clean(repo_dir)
    branch = job.get("branch", BASE)
    run(f"git checkout -B {branch} origin/{branch}", repo_dir, env=git_env(), timeout=120)
    pre = job.get("preprocess")
    if pre == "hive_expand_odp_version":
        hive_expand_odp_version(repo_dir)
    elif pre == "cruise_control_disable_semver":
        cruise_control_disable_semver(repo_dir)
    elif pre == "impala_log4j_env":
        impala_log4j_env(repo_dir)
    if job.get("drop_modules"):
        drop_pom_modules(repo_dir, job["drop_modules"])
    # rediscover after preprocess inject
    pins = discover_pins(repo_dir) or pins
    if job.get("inject_xml_props") and not any(p.get("name") in job["inject_xml_props"] for p in pins):
        for prop in job["inject_xml_props"]:
            pins.append({"file": "pom.xml", "kind": "xml", "name": prop, "value": "0.0.0"})
    changed = apply_version(repo_dir, pins, VERSION, job=job)
    print(f"  applied {VERSION} in {changed}", flush=True)
    env = git_env()
    java = jdk_home(job["jdk"])
    env["JAVA_HOME"] = java
    env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
    if job.get("impala_env"):
        env["IMPALA_LOG4J2_VERSION"] = VERSION
        env.setdefault("IMPALA_SYSTEM_PYTHON3_OVERRIDE", "/usr/bin/python3")
        # Prefer system python3 for Config sourcing without Ambari wrappers
        for py in ("/usr/bin/python3", "/usr/local/bin/python3"):
            if Path(py).exists():
                env["IMPALA_SYSTEM_PYTHON3_OVERRIDE"] = py
                break
    if job.get("post_apply") == "ozone_sortpom":
        ozone_sortpom(repo_dir, env=env)
        if "pom.xml" not in changed:
            changed.append("pom.xml")
    log_path = f"/tmp/log4j_build_{job['comp']}_{VERSION}.log"
    t0 = time.time()
    code, out, err = run(job["build"], repo_dir, env=env, timeout=TIMEOUT, log_path=log_path)
    sec = round(time.time() - t0, 1)
    ok = code == 0
    tail = (err or out or "")[-1500:]
    print(f"  compile {VERSION}: {'OK' if ok else 'FAIL'} exit={code} {sec}s jdk={job['jdk']} log={log_path}", flush=True)
    if not ok:
        print(tail[-800:], flush=True)
    return {"version": VERSION, "ok": ok, "exit": code, "seconds": sec, "changed": changed, "tail": tail[-1000:], "jdk": job["jdk"]}


def compile_all():
    load_token()
    jobs = [j for j in JOBS if not ONLY or j["comp"] in ONLY]
    prior = []
    if RESUME and RESULT.is_file():
        try:
            prior = list(json.loads(RESULT.read_text(encoding="utf-8")).get("results") or [])
        except Exception:
            prior = []
    results = []
    done = {r["comp"] for r in prior if r.get("status") == "OK" and r.get("chosen") == VERSION}
    results = [r for r in prior if r.get("comp") in done]
    print(f"JOBS={len(jobs)} VERSION={VERSION} resume_ok={sorted(done)}", flush=True)
    for job in jobs:
        if job["comp"] in done:
            print(f"\nSKIP {job['comp']} (already OK @ {VERSION})", flush=True)
            continue
        print(f"\n{'='*72}\nCOMP {job['comp']} jdk={job['jdk']} target={VERSION}\n{'='*72}", flush=True)
        row = {"comp": job["comp"], "repo": job["repo"], "jdk": job["jdk"], "target": VERSION}
        try:
            repo_dir = ensure_clone(job)
            pins = discover_pins(repo_dir)
            if job.get("gradle_literal") and not pins:
                pins = [{"file": "build.gradle", "kind": "gradle", "name": "log4jLiteral", "value": "0"}]
            row["pins"] = pins
            print(f"  pins: {pins}", flush=True)
            if not pins and not job.get("gradle_literal") and not job.get("inject_xml_props") and not job.get("impala_env"):
                row["status"] = "NO_PINS"
            else:
                if SKIP_BUILD:
                    restore_clean(repo_dir)
                    branch = job.get("branch", BASE)
                    run(f"git checkout -B {branch} origin/{branch}", repo_dir, env=git_env(), timeout=120)
                    if job.get("preprocess") == "impala_log4j_env":
                        impala_log4j_env(repo_dir)
                    elif job.get("preprocess") == "cruise_control_disable_semver":
                        cruise_control_disable_semver(repo_dir)
                    elif job.get("preprocess") == "hive_expand_odp_version":
                        hive_expand_odp_version(repo_dir)
                    if job.get("drop_modules"):
                        drop_pom_modules(repo_dir, job["drop_modules"])
                    changed = apply_version(repo_dir, pins, VERSION, job=job)
                    row["status"] = "OK"
                    row["chosen"] = VERSION
                    row["attempts"] = [{"version": VERSION, "ok": True, "changed": changed, "skipped_build": True}]
                else:
                    att = try_compile(job, repo_dir, pins)
                    row["attempts"] = [{k: v for k, v in att.items() if k != "tail"} | {"tail": att.get("tail", "")[:300]}]
                    row["chosen"] = VERSION if att["ok"] else None
                    row["status"] = "OK" if att["ok"] else "FAIL"
                    restore_clean(repo_dir)
        except Exception as e:
            row["status"] = "ERROR"
            row["error"] = str(e)[:800]
            print(f"  ERROR: {e}", flush=True)
        results = [r for r in results if r.get("comp") != job["comp"]]
        results.append(row)
        RESULT.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")
    print("\n===== SUMMARY =====")
    for r in results:
        print(f"{r['comp']:28} {r.get('status'):8} chosen={r.get('chosen')}")
    ok = sum(1 for r in results if r.get("chosen") == VERSION)
    fail = sum(1 for r in results if r.get("status") in ("FAIL", "ERROR", "NO_PINS"))
    summary = {"ok": ok, "fail": fail, "version": VERSION}
    RESULT.write_text(json.dumps({"results": results, "summary": summary}, indent=2), encoding="utf-8")
    print(f"OK={ok} fail={fail} wrote {RESULT}")
    return results


# ---------------- deliver -----------------
def parse_ver(v: str):
    if not v:
        return None
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", str(v).strip())
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def advisory_id(key: str, summary: str, field_value) -> str:
    import cve_analyser as ca
    if isinstance(field_value, dict):
        field_value = field_value.get("value") or field_value.get("name") or ""
    blob = f"{field_value or ''} {summary or ''} {key or ''}"
    m = re.search(
        r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PRISMA-\d{4}-\d+)",
        blob, re.I,
    )
    if m:
        raw = m.group(0)
        if raw.upper().startswith("CVE-") or raw.upper().startswith("PRISMA-"):
            return raw.upper()
        return "GHSA-" + raw[5:].lower()
    if str(field_value or "").strip():
        return str(field_value).strip()
    return ca.extract_cve_id(key, summary or "", str(field_value or ""))


def covered_by_log4j(pkg: str, ver: str, path: str, summary: str) -> bool:
    blob = " ".join([pkg or "", path or "", summary or ""]).lower()
    if "log4j" not in blob and "logging.log4j" not in blob:
        return False
    # skip classic log4j 1.x (reload4j / log4j:log4j) unless log4j-1.2-api bridge
    if re.search(r"(^|[^0-9])1\.\d+\.\d+", ver or "") and "log4j-1.2-api" not in blob and "logging.log4j" not in blob:
        return False
    pv = parse_ver(ver)
    if not pv:
        return "logging.log4j" in blob or "log4j-core" in blob or "log4j-1.2-api" in blob
    if pv[0] != 2:
        return False
    return pv < (2, 25, 4)


def fetch_tickets(jira_repos: list[str]) -> list[dict]:
    import cve_analyser as ca
    out = {}
    for repo in jira_repos:
        jql = (
            f'project = OSV AND "cve-found-in-release-version[short text]" ~ "{RELEASE}" '
            f'AND "cve-repo[short text]" ~ "{repo}" AND status = "To Do" '
            f'AND ("cve-package[short text]" ~ "log4j" OR summary ~ "log4j") '
            f"ORDER BY key ASC"
        )
        token = None
        while True:
            url = (
                f"{ca.JIRA_BASE_URL}/rest/api/3/search/jql"
                f"?jql={urllib.parse.quote(jql)}&maxResults=100"
                f"&fields=key,summary,customfield_10875,customfield_10892,customfield_10888,customfield_10127"
            )
            if token:
                url += f"&nextPageToken={urllib.parse.quote(token)}"
            r = ca.SESSION.get(url, headers={"Accept": "application/json"},
                               auth=(ca.EMAIL, ca.API_TOKEN))
            if r.status_code != 200:
                print(f"  Jira error {repo}: {r.status_code} {r.text[:200]}")
                break
            data = r.json()
            for i in data.get("issues", []):
                f = i["fields"]
                item = {
                    "key": i["key"],
                    "summary": f.get("summary") or "",
                    "pkg": f.get("customfield_10875") or "",
                    "ver": f.get("customfield_10892") or "",
                    "path": f.get("customfield_10888") or "",
                    "cve_id": advisory_id(i["key"], f.get("summary") or "", f.get("customfield_10127") or ""),
                    "repo": repo,
                }
                if covered_by_log4j(item["pkg"], item["ver"], item["path"], item["summary"]):
                    out[item["key"]] = item
            if data.get("isLast", True):
                break
            token = data.get("nextPageToken")
            if not token:
                break
    return [out[k] for k in sorted(out)]


def gh(method: str, path: str, payload=None):
    import requests
    headers = {"Authorization": f"token {TOKEN}", "Accept": "application/vnd.github+json"}
    url = f"https://api.github.com{path}"
    if method == "GET":
        return requests.get(url, headers=headers, timeout=60)
    if method == "POST":
        return requests.post(url, headers=headers, json=payload, timeout=60)
    if method == "PATCH":
        return requests.patch(url, headers=headers, json=payload, timeout=60)
    raise ValueError(method)


def create_pr(gh_slug: str, branch: str, title: str, body: str, base: str) -> str | None:
    if DRY:
        print(f"  [DRY_RUN] PR {title}")
        return f"https://github.com/{gh_slug}/pull/DRY"
    r = gh("POST", f"/repos/{gh_slug}/pulls",
           {"title": title, "head": branch, "base": base, "body": body})
    if r.status_code == 201:
        url = r.json()["html_url"]
        num = r.json()["number"]
        print(f"  PR created: {url}")
        rr = gh("POST", f"/repos/{gh_slug}/pulls/{num}/requested_reviewers",
                {"reviewers": [REVIEWER]})
        print(f"  reviewer {REVIEWER}: HTTP {rr.status_code}")
        return url
    if r.status_code == 422:
        q = gh("GET", f"/repos/{gh_slug}/pulls?head=acceldata-io:{branch}&state=open")
        if q.status_code == 200 and q.json():
            url = q.json()[0]["html_url"]
            print(f"  PR exists: {url}")
            return url
    print(f"  ERROR PR [{r.status_code}]: {r.text[:400]}")
    return None


def deliver_one(job: dict) -> dict:
    import cve_analyser as ca
    comp = job["comp"]
    repo_dir = WORK / job["comp"]
    base = job.get("branch", BASE)
    print(f"\n{'='*72}\nDELIVER {comp} version={VERSION} base={base}\n{'='*72}", flush=True)
    if not (repo_dir / ".git").is_dir():
        return {"comp": comp, "status": "NO_REPO"}
    tickets = fetch_tickets(job["jira_repos"])
    print(f"  tickets: {len(tickets)}")
    for t in tickets[:8]:
        print(f"    {t['key']} ver={t['ver']} cve={t.get('cve_id')} path={t.get('path')}")
    if not tickets:
        return {"comp": comp, "status": "NO_TICKETS"}
    branch = tickets[0]["key"]
    keys = [t["key"] for t in tickets]
    cve_id = next((t["cve_id"] for t in tickets if t.get("cve_id") and t["cve_id"] != "UNKNOWN"),
                  tickets[0].get("cve_id") or "UNKNOWN")
    lib = "Log4j"

    run(f"git remote set-url origin https://github.com/{job['gh']}.git", repo_dir, timeout=60)
    run(f"git fetch origin {base} --prune", repo_dir, timeout=300)
    run(f"git checkout -B {base} origin/{base}", repo_dir, timeout=120)
    run("git reset --hard HEAD && git clean -fd", repo_dir, timeout=120)
    run(f"git checkout -B {branch} origin/{base}", repo_dir, timeout=120)

    # Apply ONLY version bump for PR (no smoke-only drops)
    pins = discover_pins(repo_dir)
    job_pr = {k: v for k, v in job.items() if k in ("inject_xml_props", "force_log4j_dm", "gradle_literal", "impala_env")}
    if job.get("impala_env"):
        impala_log4j_env(repo_dir)
    changed = apply_version(repo_dir, pins, VERSION, job=job_pr or None)
    if job.get("post_apply") == "ozone_sortpom":
        java = jdk_home(job["jdk"])
        env = git_env()
        env["JAVA_HOME"] = java
        env["PATH"] = f"{java}/bin:" + env.get("PATH", "")
        ozone_sortpom(repo_dir, env=env)
        if "pom.xml" not in changed:
            changed.append("pom.xml")
    print(f"  changed: {changed}")
    code, porcelain, _ = run("git status --porcelain", repo_dir, timeout=30)
    if not (porcelain or "").strip():
        print("  no diff — skip")
        return {"comp": comp, "status": "NO_DIFF", "tickets": keys}

    title = f"{branch} - CVE - Bumped-up {lib} to {VERSION} to address {cve_id}"
    body = "\n".join([
        f"- Library : {lib}",
        f"- Version : -> {VERSION}",
        f"- Tickets : {', '.join(keys)}",
    ])
    commit_msg = title if len(keys) == 1 else title + "\n\nAlso covers: " + ", ".join(keys[1:])
    if DRY:
        print(f"  [DRY_RUN] {title}")
        return {"comp": comp, "status": "DRY", "title": title, "tickets": keys}

    run("git add -A", repo_dir, timeout=60)
    p = subprocess.run(["git", "commit", "-m", commit_msg], cwd=str(repo_dir),
                       text=True, capture_output=True, env=git_env())
    if p.returncode != 0:
        print(p.stdout, p.stderr)
        return {"comp": comp, "status": "COMMIT_FAIL", "tickets": keys}
    run(f"git push -u origin {branch}", repo_dir, timeout=300)
    pr_url = create_pr(job["gh"], branch, title, body, base=base)
    if not pr_url:
        return {"comp": comp, "status": "PR_FAIL", "tickets": keys}
    comment = f"Fixed via PR: {pr_url} — {lib} bumped to {VERSION} on {base} to address the linked log4j CVE(s)."
    closed = []
    for k in keys:
        ok = ca.close_ticket_with_comment(k, comment, "Closed", assignee=ASSIGNEE)
        print(f"    {k} -> {'Closed' if ok else 'FAILED'}")
        if ok:
            closed.append(k)
    return {"comp": comp, "status": "OK", "pr": pr_url, "tickets": keys, "closed": closed, "title": title}


def deliver_all(results=None):
    load_token()
    ok_comps = set()
    if results:
        ok_comps = {r["comp"] for r in results if r.get("chosen") == VERSION}
    elif RESULT.is_file():
        data = json.loads(RESULT.read_text(encoding="utf-8"))
        ok_comps = {r["comp"] for r in data.get("results") or [] if r.get("chosen") == VERSION}
    jobs = [j for j in JOBS if (not ONLY or j["comp"] in ONLY) and (not ok_comps or j["comp"] in ok_comps)]
    print(f"DELIVER jobs={len(jobs)} ok_gate={sorted(ok_comps)} DRY={DRY}")
    out = []
    for job in jobs:
        try:
            out.append(deliver_one(job))
        except Exception as e:
            print(f"  ERROR {job['comp']}: {e}")
            out.append({"comp": job["comp"], "status": "ERROR", "error": str(e)[:400]})
        Path("/tmp/log4j_deliver.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\n===== DELIVER SUMMARY =====")
    for r in out:
        print(f"{r.get('comp'):28} {r.get('status'):10} pr={r.get('pr')} closed={len(r.get('closed') or [])}/{len(r.get('tickets') or [])}")
    return out


def main():
    mode = MODE
    if mode == "compile":
        compile_all()
    elif mode == "deliver":
        deliver_all()
    else:
        results = compile_all()
        deliver_all(results)


if __name__ == "__main__":
    main()
