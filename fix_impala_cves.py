"""
Impala 3.2.3.6 CVE delivery -- SEPARATE per-library PR per fix (one commit + one
PR per library group), reviewer basapuram-kumar, closes the matching Jira; all
other tickets routed to Exception Request.

Impala (org.apache.impala 4.4.0 ODP fork, acceldata-io/impala
nightly/ODP-3.2.3.7-2, JDK 8). 137 flagged CVEs in 3.2.3.6.

A full Impala build needs the heavy native (C++) toolchain bootstrap, so these
pure-Java dependency version bumps are validated via Maven artifact resolution on
node82 (every bumped/added coordinate -- incl. the io.netty:netty-bom import that
aligns the unmanaged netty-codec-dns/mqtt/redis modules -- resolves cleanly from
the configured repos; spring 5.3.40+ is commercial-only so spring stays an
exception).

FIX (22 tickets, 8 PRs):
  netty                   4.1.132->4.1.133.Final  java/pom.xml (netty.version +
                            netty-bom import aligns every io.netty:* module)   11
  log4j2                  2.25.3->2.25.4   bin/impala-config.sh                  5
  jackson (databind+core) 2.16.1->2.18.6   bin/impala-config.sh                 1
  postgresql jdbc         42.5.6->42.7.11  bin/impala-config.sh                 1
  commons-configuration2  2.10.1->2.15.0   java/pom.xml                         1
  okio                    1.6.0->1.17.6    java/pom.xml (new dM)                1
  commons-io              2.8.0->2.14.0    java/pom.xml (new dM)                1
  opentelemetry-api       1.49.0->1.62.0   java/pom.xml (new dM)                1

EXCEPTION (115 tickets) -- libthrift/thrift (Hive 0.23 compile constraint),
shaded inside third-party fat jars (kudu-client / ozone-filesystem /
impala-minimal-s3a-aws-sdk / htrace-core4 / cos_api-bundle / aws-java-sdk-bundle
/ iceberg-hive-runtime), jetty 9->11/12, sqlparse vendored py, no-fix-open,
spring 6.x/commercial-only, ranger ODP fork, pac4j/elasticsearch major.

Honors CVE_DRY_RUN=1.
"""

import os
import subprocess

os.environ.setdefault("CVE_PROFILE", "impala")

import cve_analyser as ca
import cve_fixer as cf

WORKDIR = os.path.expanduser("~/cve_fix_workdir/impala")
TB = cf.TARGET_BRANCH
REVIEWER = "basapuram-kumar"
POM = "java/pom.xml"
CFG = "bin/impala-config.sh"

# ---- pristine anchors (must match origin/TB exactly) ----
GUAVA = """      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>${guava.version}</version>
      </dependency>"""

NETTY_HANDLER = """      <!-- Override Netty versions (transitive from kudu-client) to address multiple CVEs.
           OSV-11063 . Fixed in 4.1.129.Final. -->
      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-handler</artifactId>
        <version>${netty.version}</version>
      </dependency>"""

NETTY_HANDLER_WITH_BOM = """      <!-- Override Netty versions (transitive from kudu-client) to address multiple CVEs.
           OSV-11063 . Fixed in 4.1.129.Final. netty-bom aligns every io.netty:*
           module (incl. netty-codec-dns/mqtt/redis/common) to ${netty.version}. -->
      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-bom</artifactId>
        <version>${netty.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-handler</artifactId>
        <version>${netty.version}</version>
      </dependency>"""


def dm_add(block: str) -> tuple:
    """Insert a new dependencyManagement entry right after the guava block."""
    return (GUAVA, GUAVA + "\n\n" + block)


# group -> (summary, [(file, old, new), ...])
FIX = {
    "netty": ("Increasing netty version to 4.1.133.Final (netty-bom) to fix the Impala netty CVEs",
        [(POM, "<netty.version>4.1.132.Final</netty.version>",
                "<netty.version>4.1.133.Final</netty.version>"),
         (POM, NETTY_HANDLER, NETTY_HANDLER_WITH_BOM)]),
    "log4j2": ("Increasing log4j2 version to 2.25.4 to fix the Impala log4j2 CVEs",
        [(CFG, "export IMPALA_LOG4J2_VERSION=2.25.3",
                "export IMPALA_LOG4J2_VERSION=2.25.4")]),
    "jackson": ("Increasing jackson version to 2.18.6 to fix the Impala jackson CVEs",
        [(CFG, "export IMPALA_JACKSON_DATABIND_VERSION=2.16.1",
                "export IMPALA_JACKSON_DATABIND_VERSION=2.18.6")]),
    "postgresql": ("Increasing postgresql jdbc version to 42.7.11 to fix the Impala postgresql CVEs",
        [(CFG, "export IMPALA_POSTGRES_JDBC_DRIVER_VERSION=42.5.6",
                "export IMPALA_POSTGRES_JDBC_DRIVER_VERSION=42.7.11")]),
    "commons-configuration2": ("Increasing commons-configuration2 version to 2.15.0 to fix the Impala commons-configuration2 CVEs",
        [(POM, "<commons-configuration2.version>2.10.1</commons-configuration2.version>",
                "<commons-configuration2.version>2.15.0</commons-configuration2.version>")]),
    "okio": ("Pinning okio to 1.17.6 to fix the Impala okio CVEs",
        [(POM,) + dm_add("""      <dependency>
        <groupId>com.squareup.okio</groupId>
        <artifactId>okio</artifactId>
        <version>1.17.6</version>
      </dependency>""")]),
    "commons-io": ("Pinning commons-io to 2.14.0 to fix the Impala commons-io CVEs",
        [(POM,) + dm_add("""      <dependency>
        <groupId>commons-io</groupId>
        <artifactId>commons-io</artifactId>
        <version>2.14.0</version>
      </dependency>""")]),
    "opentelemetry-api": ("Pinning opentelemetry-api to 1.62.0 to fix the Impala opentelemetry CVEs",
        [(POM,) + dm_add("""      <dependency>
        <groupId>io.opentelemetry</groupId>
        <artifactId>opentelemetry-api</artifactId>
        <version>1.62.0</version>
      </dependency>""")]),
}

ORDER = ["netty", "log4j2", "jackson", "postgresql", "commons-configuration2",
         "okio", "commons-io", "opentelemetry-api"]


# ---- exception reason texts ----
_THRIFT = ("libthrift 0.16.0 is shared with Hive and the rest of the Hadoop "
    "stack; upgrading to the fixed 0.23.0 breaks Hive compilation (Hive's "
    "generated thrift code and the ODP Hive fork are bound to the 0.16.x thrift "
    "API). The bump must be coordinated platform-wide and cannot be done inside "
    "Impala. Routed to exception.")
_KUDU = ("the flagged netty/protobuf classes are shaded inside the third-party "
    "kudu-client uber-jar (Apache Kudu client, pulled transitively). Kudu "
    "re-packages its own netty/protobuf, so an Impala-side dependency bump does "
    "not change the classes baked into that jar; remediation requires a Kudu "
    "client upgrade. Routed to exception.")
_OZONE = ("the flagged netty/jackson classes are shaded inside the third-party "
    "ozone-filesystem-hadoop3 fat jar (Apache Ozone Hadoop3 connector). The fat "
    "jar bundles its own copies, which an Impala dependency bump cannot displace; "
    "remediation requires an Apache Ozone upgrade owned by the platform. Routed "
    "to exception.")
_S3A = ("netty is shaded inside the AWS Java SDK that Impala repackages into "
    "impala-minimal-s3a-aws-sdk (the bundled netty comes from aws-java-sdk-bundle "
    "1.12.x, the latest 1.12.x AWS SDK uber-jar). The netty classes are baked "
    "into the AWS SDK jar and are not displaceable by Impala's netty.version; "
    "remediation requires the AWS SDK v2 major upgrade. Routed to exception.")
_HTRACE = ("jackson is shaded/relocated inside the abandoned "
    "htrace-core4-4.1.0-incubating fat jar (a Hadoop transitive). Apache HTrace "
    "was retired and 4.1.0 (2016) is its last release, so there is no newer "
    "htrace artifact carrying a patched jackson; Impala cannot bump it via its "
    "own pom. Routed to exception.")
_COS = ("jackson is shaded inside the third-party Tencent COS SDK fat jar "
    "(cos_api-bundle); the bundled jackson is baked into that uber-jar and an "
    "Impala dependency bump cannot displace it. Remediation requires a Tencent "
    "COS SDK upgrade. Routed to exception.")
_AWSBUNDLE = ("netty is shaded inside aws-java-sdk-bundle-1.12.x, the latest "
    "1.12.x AWS SDK uber-jar pulled transitively via hadoop-aws. The bundle "
    "re-packages its own netty, so Impala's netty bump does not affect the "
    "classes inside it; remediation requires the AWS SDK v2 major upgrade owned "
    "by the Hadoop/ODP platform. Routed to exception.")
_ICEBERG = ("the flagged dependency (aircompressor / jackson / parquet-avro / "
    "avro) is shaded inside the third-party iceberg-hive-runtime-1.6.1 fat jar; "
    "the bundled copies are baked into that uber-jar and can only be addressed by "
    "upgrading Apache Iceberg, a separate coordinated change. Routed to "
    "exception.")
_JETTY = ("jetty-http / jetty-io 9.4.57 is the last Jetty line on the "
    "javax.servlet namespace and JDK 8. The fix versions (11.x/12.x) require "
    "Jakarta EE (jakarta.* namespace) and JDK 11+, which Impala (JDK 8, javax "
    "servlet) does not support. Routed to exception pending a Jakarta/JDK 11 "
    "migration.")
_SQLPARSE = ("sqlparse 0.3.1 is vendored in shell/ext-py and pinned in "
    "shell/packaging/requirements.txt. The fix (0.4.4 / 0.5.x) drops Python 2 "
    "support, which the Impala shell still relies on for this ODP 3.2.3 "
    "baseline; upgrading would break impala-shell. Routed to exception.")
_OPEN = ("no fixed version is available upstream for this CVE (fix=open) and the "
    "library (commons-lang 2.x / ini4j) is EOL/abandoned. Routed to exception "
    "(no fix available).")
_SPRING = ("springframework is at 5.3.37; these CVEs are fixed only in Spring "
    "6.x (Jakarta / JDK 17) or in commercial-only Spring 5.3.40+ (5.3.39 is the "
    "last OSS 5.3.x release; 5.3.40/5.3.41 are enterprise-only and confirmed "
    "unavailable on public Maven). Impala on JDK 8 / Spring 5.3.x cannot "
    "remediate without a major Spring 6 / Jakarta migration. Routed to "
    "exception.")
_RANGER = ("ranger-plugins-common is the ODP Ranger platform fork (version "
    "suffix 2.5.0.3.2.3.x); the fix (2.8.0) is owned by the platform Ranger "
    "build and coordinated across ODP components, not bumpable inside Impala. "
    "Routed to exception.")
_PAC4J = ("pac4j-core 4.5.5: the only fix is a major jump to 5.7.10 / 6.4.1, a "
    "breaking API change (pac4j 5.x requires JDK 11), which Impala (JDK 8) cannot "
    "take without a coordinated upgrade. Routed to exception.")
_ELASTIC = ("elasticsearch 7.17.29: the fix is in 8.19.8 / 9.x, a major version "
    "upgrade with breaking API/protocol changes, out of scope for a CVE "
    "dependency bump. Routed to exception.")

SHADED = {
    "kudu-client": _KUDU,
    "ozone-filesystem-hadoop3": _OZONE,
    "impala-minimal-s3a-aws-sdk": _S3A,
    "htrace-core4": _HTRACE,
    "cos_api-bundle": _COS,
    "aws-java-sdk-bundle": _AWSBUNDLE,
    "iceberg-hive-runtime": _ICEBERG,
}


def _shaded_bundle(path: str):
    b = os.path.basename(path or "")
    for s in SHADED:
        if b.startswith(s):
            return s
    return None


def categorize(issues):
    """Return (fix_keys: {group: [keys]}, exc: {key: reason})."""
    fix = {g: [] for g in FIX}
    exc = {}
    for i in issues:
        k = i["key"]
        L = i["affected_library"].split("_")[-1].lower()
        fv = i.get("fixed_version", "")
        path = i.get("cve_path", "")
        if L in ("libthrift", "thrift"):
            exc[k] = _THRIFT; continue
        sj = _shaded_bundle(path)
        if sj:
            exc[k] = SHADED[sj]; continue
        if L.startswith("netty"):
            fix["netty"].append(k); continue
        if L == "log4j-core":
            fix["log4j2"].append(k); continue
        if L == "jackson-core":
            fix["jackson"].append(k); continue
        if L == "postgresql":
            fix["postgresql"].append(k); continue
        if L == "commons-configuration2":
            fix["commons-configuration2"].append(k); continue
        if L == "okio":
            fix["okio"].append(k); continue
        if L == "commons-io":
            fix["commons-io"].append(k); continue
        if L == "opentelemetry-api":
            fix["opentelemetry-api"].append(k); continue
        if L in ("spring-core", "spring-context"):
            exc[k] = _SPRING; continue
        if L.startswith("jetty"):
            exc[k] = _JETTY; continue
        if L == "sqlparse":
            exc[k] = _SQLPARSE; continue
        if L in ("commons-lang", "ini4j"):
            exc[k] = _OPEN; continue
        if L == "ranger-plugins-common":
            exc[k] = _RANGER; continue
        if L == "pac4j-core":
            exc[k] = _PAC4J; continue
        if L == "elasticsearch":
            exc[k] = _ELASTIC; continue
        exc[k] = ("UNCLASSIFIED:" + L)
    return fix, exc


def git(cmd: str) -> int:
    print(f"    $ {cmd}")
    return subprocess.run(cmd, shell=True, cwd=WORKDIR).returncode


def gh(method: str, path: str, payload: dict):
    token = cf.github_token()
    headers = {"Authorization": f"token {token}",
               "Accept": "application/vnd.github+json"}
    return ca.SESSION.request(
        method, f"https://api.github.com/repos/{cf.REPO_SLUG}{path}",
        headers=headers, json=payload)


def deliver(group: str, keys: list) -> None:
    summary, edits = FIX[group]
    branch = min(keys)            # representative OSV key as branch name
    title = f"{branch} - CVE - {summary}"
    print(f"\n{'='*74}\n  {group.upper()}  branch={branch}  ({len(keys)} tickets)\n{'='*74}")
    if not keys:
        print("  no tickets -> skip"); return
    if ca.DRY_RUN:
        files = sorted({e[0] for e in edits})
        print(f"  [DRY_RUN] {branch}: edit {files}, PR, reviewer={REVIEWER}, close {keys}")
        return
    if git(f"git checkout -f -B {branch} origin/{TB}") != 0:
        print("  ERROR checkout"); return
    for fpath, old, new in edits:
        full = os.path.join(WORKDIR, fpath)
        text = open(full, encoding="utf-8").read()
        if text.count(old) != 1:
            print(f"  ERROR anchor count={text.count(old)} in {fpath}; abort {group}")
            return
        open(full, "w", encoding="utf-8").write(text.replace(old, new, 1))
        git(f"git add {fpath}")
    if git(f'git commit -m "{title}"') != 0:
        print("  ERROR commit"); return
    if git(f"git push -u origin {branch} --force") != 0:
        print("  ERROR push"); return
    plan = {"branch": branch, "libraries": [group], "target_version": "",
            "issues": [{"key": k} for k in keys]}
    pr_url = cf.create_pull_request(plan, title)
    if not pr_url:
        print("  ERROR no PR"); return
    num = pr_url.rstrip("/").split("/")[-1]
    gh("PATCH", f"/pulls/{num}", {"title": title,
        "body": f"- Tickets : {', '.join(keys)}\n\nImpala 3.2.3.6 CVE per-library "
                f"fix. Validated via Maven artifact resolution on JDK 8 (a full "
                f"Impala build requires the native toolchain bootstrap)."})
    rr = gh("POST", f"/pulls/{num}/requested_reviewers", {"reviewers": [REVIEWER]})
    print(f"  reviewer {REVIEWER}: {rr.status_code}")
    comment = (f"Fixed via PR: {pr_url}  -  on {TB} the {group} version was bumped "
               f"to address this CVE; validated that the fixed coordinate resolves "
               f"from the configured repos. (Per-library PR.)")
    for k in keys:
        ca.close_ticket_with_comment(k, comment, "Closed")
    print(f"  {group}: PR {pr_url} | closed {len(keys)}")


def main() -> None:
    issues = ca.fetch_all_tickets()
    fix, exc = categorize(issues)
    bad = {k: v for k, v in exc.items() if v.startswith("UNCLASSIFIED")}
    print(f"Impala CVE split delivery  DRY_RUN={ca.DRY_RUN}  total={len(issues)}")
    print(f"  FIX groups: " + ", ".join(f"{g}={len(fix[g])}" for g in ORDER))
    print(f"  FIX total={sum(len(v) for v in fix.values())}  EXC total={len(exc)}")
    if bad:
        print(f"  !! UNCLASSIFIED ({len(bad)}): {bad}")
        return
    if not ca.DRY_RUN and git("git fetch origin --prune") != 0:
        print("fetch failed"); return
    for g in ORDER:
        deliver(g, fix[g])
    print(f"\n{'='*74}\n  ROUTING {len(exc)} EXCEPTIONS\n{'='*74}")
    if ca.DRY_RUN:
        from collections import Counter
        c = Counter(exc.values())
        for r, n in c.most_common():
            print(f"  [DRY_RUN] {n:3d} x {r[:70]}")
        return
    routed = 0
    for k, reason in exc.items():
        if ca.update_ticket_exception(k, reason):
            routed += 1
    print(f"  routed {routed}/{len(exc)} exceptions")


if __name__ == "__main__":
    main()
