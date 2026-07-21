"""
Build-target profiles for the CVE analyser / fixer.

A single profile bundles everything that differs between the components we patch
(spark2, spark3 lines, livy, pinot, ambari, python apps, …):

  Jira side   : repo (cve-repo filter), release (cve-found-in-release-version).
  Git/build   : git_url, target_branch, pom_path, java_home, build_cmd.
  Fix logic   : aligned_versions, fix_targets.
  Routing     : exception_rules, close_rules, shaded_bundle_rules.

**Unified remediation catalog** (`cve_remediation_catalog.py`) holds the
per-component fix_targets + exception_rules learned from prior release runs
(batch9–14, Ambari, Pinot, …). Empty profile rule lists are filled from that
catalog at import time; hand-tuned spark2/spark3/livy/pinot lists are kept.

Select the active profile with the CVE_PROFILE environment variable, e.g.:

    CVE_PROFILE=spark3-3.5.5 python3 cve_fixer.py
    CVE_PROFILE=odp-ambari python3 cve_fixer.py

Defaults to "spark2" so existing spark2 runs are unchanged.

Inspect the catalog:

    python3 cve_remediation_catalog.py              # all components
    python3 cve_remediation_catalog.py odp-ambari    # one component
    python3 cve_remediation_catalog.py table         # markdown fix_targets table
"""

import os
import re
import shutil
from pathlib import Path
from typing import Optional

# Account that exception/closed tickets are assigned to (same across components).
ASSIGNEE_ACCOUNT_ID = "712020:53c91b99-c1e1-4c8e-80b8-84f656392ae4"

DEFAULT_PROFILE = "spark2"

# ---------------------------------------------------------------------------
# Portable paths (macOS laptop OR any Linux remote, e.g. 10.101.11.82)
# ---------------------------------------------------------------------------
# Prefer env vars so the same repo works everywhere without editing profiles:
#   CVE_JAVA_HOME_8 / CVE_JAVA_HOME_11  — absolute JDK homes
#   CVE_WORKDIR                         — base dir for component checkouts
#                                         (default: ~/cve_fix_workdir)
# Falls back to common Linux/macOS install locations, then `java` on PATH.


def _first_existing(*candidates) -> str:
    for c in candidates:
        if not c:
            continue
        p = os.path.expanduser(str(c))
        if os.path.isdir(p):
            return p
    return ""


def resolve_java_home(major: int = 8) -> str:
    """Resolve a JDK home for the given major version (8 or 11, …).

    Explicit ``CVE_JAVA_HOME_<N>`` / ``JAVA_HOME_<N>`` always win (even if the
    directory is not created yet — so a remote ``.env`` is deterministic).
    Otherwise probe common Linux/macOS install layouts, then ``java`` on PATH.
    """
    major = int(major)
    for k in (f"CVE_JAVA_HOME_{major}", f"JAVA_HOME_{major}"):
        v = (os.environ.get(k) or "").strip()
        if v:
            return os.path.expanduser(v)
    # JAVA_HOME only as a last-env fallback for the requested major when set.
    if major == 8:
        v = (os.environ.get("JAVA_HOME") or "").strip()
        if v:
            return os.path.expanduser(v)

    # Common Linux (yum/apt/temurin/corretto) + macOS Corretto layouts.
    linux = [
        f"/usr/lib/jvm/java-{major}-openjdk",
        f"/usr/lib/jvm/java-{major}-openjdk-amd64",
        f"/usr/lib/jvm/temurin-{major}-jdk",
        f"/usr/lib/jvm/java-{major}-amazon-corretto",
        f"/usr/lib/jvm/corretto-{major}",
        f"/opt/java/jdk-{major}",
        f"/opt/jdk-{major}",
        f"/usr/lib/jvm/jdk-{major}",
    ]
    # Also accept "java-1.8.0-openjdk" style dirs
    if major == 8:
        linux = [
            "/usr/lib/jvm/java-1.8.0-openjdk",
            "/usr/lib/jvm/java-1.8.0-openjdk-amd64",
            "/usr/lib/jvm/jre-1.8.0-openjdk",
        ] + linux
    mac_home = os.path.expanduser("~/Library/Java/JavaVirtualMachines")
    mac = []
    if os.path.isdir(mac_home):
        for d in sorted(os.listdir(mac_home), reverse=True):
            # corretto-1.8.0_412 / corretto-11.0.23 / temurin-8.jdk …
            if re.search(rf"(?:^|[-_])(?:1\.)?{major}(?:\D|$)", d):
                mac.append(os.path.join(mac_home, d, "Contents", "Home"))

    found = _first_existing(*linux, *mac)
    if found:
        return found

    # Last resort: derive from `java` on PATH (may not match requested major).
    java_bin = shutil.which("java")
    if java_bin:
        real = Path(java_bin).resolve()
        # .../bin/java -> home is parent of bin
        if real.parent.name == "bin":
            return str(real.parent.parent)
    return ""


def resolve_workdir(component: str, explicit: str = "") -> str:
    """Component checkout path under CVE_WORKDIR (portable across machines)."""
    if explicit and not explicit.startswith("/Users/"):
        # Keep relative / ~/ paths; drop machine-specific absolute Mac paths.
        return os.path.expanduser(explicit)
    base = os.environ.get("CVE_WORKDIR", "~/cve_fix_workdir")
    return os.path.expanduser(os.path.join(base, component))


def jdk_major_for_release(release: str) -> Optional[int]:
    """ODP baseline JDK policy: 3.3.6.* releases use JDK 11, 3.2.3.* use JDK 8.

    Returns None when the release string does not match either baseline (caller
    falls back to the profile default).
    """
    r = (release or "").strip()
    if not r:
        return None
    if re.search(r"3\.3\.6", r):
        return 11
    if re.search(r"3\.2\.3", r):
        return 8
    return None


def effective_release(profile: dict, release: Optional[str] = None) -> str:
    """Resolve the release string for JDK / scoping decisions."""
    return (release or os.environ.get("CVE_RELEASE")
            or os.environ.get("CVE_ADDRESS_RELEASE")
            or profile.get("release") or "")


# Resolved once at import (after env is loaded). Override per-run via env vars.
_JDK8 = resolve_java_home(8)
_JDK11 = resolve_java_home(11)
_SPARK3_JAVA_HOME = _JDK8  # spark3 builds on JDK 8 for ODP 3.2.3.7 baseline


# ===================================================================
# ODP platform-aligned versions (kept in sync across Hadoop/Hive/Spark)
# ===================================================================
# Spark3 inherits the same platform alignment; per-profile overrides can be
# layered on top via _merge() when a spark line needs a different value.
_ODP_ALIGNED_BASE = {
    "jackson2": "2.18.6",
    "guava": "32.0.1-jre",
    "commons-lang3": "3.18.0",
    "commons-text": "1.10.0",
    "commons-configuration2": "2.15.0",
    "netty4": "4.1.135.Final",
    "commons-io": "2.16.1",
    "commons-compress": "1.26.1",
    "avro": "1.11.5",
    "jetty": "9.4.57.v20241219",
    "nimbus-jose": "9.37.4",
    "log4j2": "2.25.4",
    "xmlsec": "2.3.4",
    "bouncycastle": "1.84",
    "dnsjava": "3.6.0",
    "libthrift": "0.16.0",
    "hadoop-thirdparty": "1.4.0",
}

# Extra alignment values used by the spark3 fix targets.
_ODP_ALIGNED_SPARK3 = {
    "lz4-java": "1.8.1",
    "jdom2": "2.0.6.1",
    "aircompressor": "2.0.3",
    "okio": "1.17.6",
}


def _merge(base: dict, *overrides: dict) -> dict:
    out = dict(base)
    for o in overrides:
        out.update(o)
    return out


# ===================================================================
# Exception rules
# ===================================================================
# Matching semantics (see cve_fixer.match_rule):
#   match            : case-insensitive substring of the affected library name
#   affected_prefix  : (opt) ticket affected version must start with this
#   path_contains    : (opt) regex searched (case-insensitive) against CVE-Path
#   cve              : (opt) exact CVE-ID match (e.g. "CVE-2025-66566")
# First rule whose match + all filters pass wins.

_SPARK2_EXCEPTION_RULES = [
    {
        "match": "com.google.protobuf",
        "description": "This fix requires more changes on both hive and spark2 sides",
    },
    {
        "match": "jackson-mapper-asl",
        "description": "1.9.13 is the latest version in 1.x of jackson-mapper-asl",
    },
    {
        "match": "libthrift",
        "description": ("Hive and other Hadoop components does not have fix for "
                        "this CVE and increase libthrift to 0.23.0 requires more "
                        "changes across all the ODP components"),
    },
    {
        # netty 3.10.x (io.netty_netty); the 4.x codec libs are bumped instead.
        "match": "io.netty_netty",
        "affected_prefix": "3.10",
        "description": ("Netty 3.10.* version does not have fix for this CVE and "
                        "hence we require Exception"),
    },
    {
        # netty 4.1.130 shaded inside aws-java-sdk-bundle-1.12.79x.jar.
        "match": "io.netty_netty",
        "affected_prefix": "4.1.130",
        "path_contains": r"aws-java-sdk-bundle-1\.12\.79\d*\.jar",
        "description": ("netty 4.1.130.Final is pulled by thirdparty library "
                        "aws-java-sdk-bundle-1.12.797.jar; and since 1.12.797 is "
                        "latest version for aws-java-sdk-bundle we require "
                        "exception for this CVE"),
    },
    {
        "match": "org.eclipse.jetty",
        "affected_prefix": "9.4",
        "description": ("jetty 9.4.* version does not have fix for this CVE; And "
                        "we increasing to 12* version require major changes across "
                        "ODP components"),
    },
    {
        "match": "com.squareup.okhttp3",
        "description": ("okhttp 3.12.0 is pulled transitively by "
                        "io.fabric8:kubernetes-client; the fix is only in okhttp "
                        "4.9.2 (Kotlin-based, requires okio 2.x and kotlin-stdlib) "
                        "and needs a major Kubernetes-client upgrade across ODP "
                        "components"),
    },
    {
        "match": "org.apache.calcite",
        "description": ("calcite-core 1.2.0-incubating is bound to spark2's "
                        "bundled Hive 1.2.1 fork; the fix requires calcite 1.26.0+ "
                        "/ 1.32.0 which is a major API break (org.eigenbase -> "
                        "org.apache.calcite) incompatible with Hive 1.2.1 and "
                        "needs the entire Hive integration to be upgraded"),
    },
    {
        "match": "commons-lang_commons-lang",
        "description": ("commons-lang 2.6 is the last release of the EOL "
                        "commons-lang 2.x line; CVE-2025-48924 has no fixed "
                        "version available for it"),
    },
    {
        "match": "org.apache.spark_spark-core",
        "description": ("CVE-2022-31777 (Spark UI XSS) is fixed only in Spark "
                        "3.2.2 / 3.3.0; Spark 2.4 is end-of-life with no backport "
                        "release available"),
    },
    {
        "match": "org.yaml_snakeyaml",
        "description": ("snakeyaml 1.33 is pulled only by the fabric8 "
                        "kubernetes-client (spark-kubernetes) to parse trusted "
                        "kube-config; the fix (snakeyaml 2.0) is incompatible with "
                        "fabric8 4.x and would break Kubernetes YAML parsing at "
                        "runtime, so it cannot be upgraded without a major "
                        "kubernetes-client (fabric8 5.12+) overhaul"),
    },
]

# Spark3 exceptions: libraries that cannot be bumped inside the spark3 build.
_SPARK3_EXCEPTION_RULES = [
    {
        "match": "libthrift",
        "description": ("libthrift 0.16.0 is shared with Hive and other Hadoop "
                        "components; upgrading to 0.23.0 requires coordinated "
                        "changes across all ODP components"),
    },
    {
        "match": "com.squareup.okhttp3",
        "description": ("okhttp 3.12.x is pulled transitively by "
                        "io.fabric8:kubernetes-client; the fix is only in okhttp "
                        "4.9.2 (Kotlin/okio 2.x) and needs a major "
                        "kubernetes-client upgrade across ODP components"),
    },
    {
        # jetty 9.4.x bundled in Spark; moving to 11/12.x is too invasive.
        "match": "org.eclipse.jetty",
        "affected_prefix": "9.4",
        "description": ("jetty 9.4.* does not have a fix for this CVE; moving to "
                        "11.x/12.x is a major change across ODP components"),
    },
    {
        "match": "commons-lang_commons-lang",
        "description": ("commons-lang 2.6 is the last release of the EOL "
                        "commons-lang 2.x line; CVE-2025-48924 has no fixed "
                        "release for it"),
    },
    {
        # Hive 2.3.x fork bundled in spark3; fixes land only in Hive 4.0.x.
        "match": "org.apache.hive",
        "description": ("the fix is only available in Hive 4.0.x; spark3 bundles "
                        "the Hive 2.3.x fork and upgrading it is a major, "
                        "cross-component change"),
    },
    {
        # lz4-java CVE-2025-66566 has no fixed release (fix=open).
        "match": "org.lz4_lz4-java",
        "cve": "CVE-2025-66566",
        "description": ("lz4-java has no fixed release for this CVE (fix=open); "
                        "deferring until upstream publishes a patched version"),
    },
    {
        # zookeeper is a platform-built component (ODP version suffix); the fix
        # (3.8.3 / 3.9.x) is owned by the platform ZooKeeper build, not spark3.
        # Convert this to a close rule with the commit link once ODP ships the fix.
        "match": "org.apache.zookeeper_zookeeper",
        "description": ("ZooKeeper is a platform-built component (ODP fork "
                        "3.5.10.x); upgrading to the fixed 3.8.3 / 3.9.x line is "
                        "owned by the platform ZooKeeper build and applied across "
                        "ODP components, not inside spark3"),
    },
    {
        # protobuf-java 2.5.0 is pinned for Hadoop/Hive wire-format compatibility;
        # the fix (3.16.1+ / 3.25.5) is a major break across ODP components.
        "match": "com.google.protobuf",
        "description": ("protobuf-java 2.5.0 is pinned for Hadoop/Hive wire-format "
                        "compatibility; upgrading to 3.16.1+/3.25.5 is a major "
                        "change required across all ODP components"),
    },
    {
        # guava is pinned to 14.0.1 to stay compatible with the bundled Hive 2.3
        # fork; jumping to 24.1.1 / 32.0.0 is a large, Hive-breaking API change.
        "match": "com.google.guava",
        "description": ("guava is pinned to 14.0.1 for compatibility with the "
                        "bundled Hive 2.3 fork; upgrading to 24.1.1 / 32.x is a "
                        "major API change that breaks the Hive integration and "
                        "must be coordinated across ODP components"),
    },
    {
        # kotlin-stdlib comes transitively from the kubernetes-client / okhttp
        # toolchain; deferred rather than force-overridden under fabric8 4.x.
        "match": "kotlin-stdlib",
        "description": ("kotlin-stdlib is pulled transitively by the "
                        "kubernetes-client / okhttp toolchain; it is deferred "
                        "rather than overridden to avoid breaking the bundled "
                        "fabric8 kubernetes-client"),
    },
    {
        # ini4j is abandoned; CVE-2022-41404 has no fixed release (fix=open).
        "match": "org.ini4j_ini4j",
        "description": ("ini4j 0.5.4 is the last release of an abandoned project; "
                        "CVE-2022-41404 has no fixed version available"),
    },
    {
        # jdom2 is a compile dependency of the Aliyun OSS Java SDK, pulled in by
        # Hadoop's Aliyun connector (matches the 3.2.3.5 manual handling).
        "match": "org.jdom_jdom2",
        "description": ("jdom2 is a compile dependency of the Aliyun OSS Java SDK, "
                        "which is pulled in by Hadoop's Aliyun connector; it is a "
                        "third-party transitive dependency and deferred"),
    },
]

# ===================================================================
# Close rules (fixed outside the component -> comment + close)
# ===================================================================
_SPARK2_CLOSE_RULES = [
    {
        "match": "org.bouncycastle",
        "comment": ("BouncyCastle has been upgraded in the platform Hadoop build "
                    "(spark2 bundles bcprov-jdk15on / bcpkix-jdk15on from Hadoop). "
                    "Fix: https://github.com/acceldata-io/hadoop/commit/"
                    "dd65aa74d25b15f331bcf702d8c9454a775f61c4"),
    },
]

_SPARK3_CLOSE_RULES = [
    {
        "match": "org.bouncycastle",
        "comment": ("BouncyCastle is bundled from the platform Hadoop build, where "
                    "it has been upgraded. Fix: "
                    "https://github.com/acceldata-io/hadoop/commit/"
                    "dd65aa74d25b15f331bcf702d8c9454a775f61c4"),
    },
]

# ===================================================================
# Shaded-bundle rules
# ===================================================================
# Applied to CVEs whose vulnerable class lives inside a third-party FAT/shaded
# jar (not a standalone library jar and not a Spark-built assembly). A Spark-side
# version bump can't change these, so route them to "exception" or "close".
#   bundle  : case-insensitive substring of the jar filename in CVE-Path
#   action  : "exception" or "close"
#   description / comment : text used for the Jira update
_SPARK3_SHADED_BUNDLE_RULES = [
    {
        "bundle": "hadoop-client-runtime",
        "action": "exception",
        "description": ("the vulnerable class is shaded/relocated inside Hadoop's "
                        "shaded client (hadoop-client-runtime); it must be fixed "
                        "in the platform Hadoop build, not in Spark"),
    },
    {
        "bundle": "hadoop-client-api",
        "action": "exception",
        "description": ("the vulnerable class is shaded/relocated inside Hadoop's "
                        "shaded client (hadoop-client-api); it must be fixed in "
                        "the platform Hadoop build, not in Spark"),
    },
    {
        "bundle": "aws-java-sdk-bundle",
        "action": "exception",
        "description": ("the vulnerable dependency is shaded inside "
                        "aws-java-sdk-bundle-1.12.797.jar, which is the latest "
                        "aws-java-sdk-bundle; no separate fix is possible in Spark"),
    },
    {
        "bundle": "iceberg-spark-runtime",
        "action": "exception",
        "description": ("the vulnerable dependency is shaded inside the "
                        "iceberg-spark-runtime fat jar; it can only be addressed "
                        "by upgrading Apache Iceberg, which is a separate effort"),
    },
    {
        "bundle": "gcs-connector",
        "action": "exception",
        "description": ("the vulnerable dependency is shaded inside the GCS "
                        "connector fat jar (gcs-connector-hadoop3-shaded); it can "
                        "only be addressed by upgrading the GCS connector"),
    },
    {
        "bundle": "parquet-jackson",
        "action": "exception",
        "description": ("Jackson is shaded/relocated inside parquet-jackson; it is "
                        "addressed by upgrading Apache Parquet, which is a "
                        "separate, coordinated change"),
    },
    {
        "bundle": "htrace-core",
        "action": "exception",
        "description": ("This CVE is pulled from Hadoop which in-turn from "
                        "htrace-core*. And htrace-core* is a non-active third "
                        "party library; And hence we require exception"),
    },
    {
        "bundle": "hudi-spark",
        "action": "exception",
        "description": ("the vulnerable dependency is shaded inside the Hudi spark "
                        "bundle (hudi-spark3.x-bundle); it can only be addressed by "
                        "upgrading Apache Hudi, which is a separate effort"),
    },
]


# ===================================================================
# Fix targets
# ===================================================================
# patch.type:
#   "property"   -> set <name>VERSION</name> for each name in names
#   "dependency" -> set <version> inside the <dependency> for group:artifact
_SPARK2_FIX_TARGETS = [
    {
        "name": "jackson",
        "lib_regex": r"^com\.fasterxml\.jackson",
        "aligned_key": "jackson2",
        "patch": {
            "type": "property",
            "names": [
                "fasterxml.jackson.version",
                "fasterxml.jackson-module-scala.version",
                "fasterxml.jackson.databind.version",
            ],
        },
        "commit_subject": "{branch} - CVE - Increasing jackson version to fix {cve}",
    },
    {
        "name": "netty",
        "lib_regex": r"^io\.netty_netty-",
        "affected_prefix": "4.1",
        "aligned_key": "netty4",
        "patch": {"type": "dependency", "group": "io.netty", "artifact": "netty-all"},
        "commit_subject": "{branch} - CVE - Increasing netty version to fix {cve}",
    },
]

# Spark3 fix targets. Property names are best-effort for the Spark 3.5 pom and
# are marked VERIFY; if a name is wrong the patch is a safe no-op (logged as
# "no pom changes") rather than a bad edit.
_SPARK3_FIX_TARGETS = [
    {
        "name": "jackson",
        "lib_regex": r"^com\.fasterxml\.jackson",
        "aligned_key": "jackson2",
        "patch": {
            "type": "property",
            "names": [  # confirmed in spark3 pom (both at 2.17.2)
                "fasterxml.jackson.version",
                "fasterxml.jackson.databind.version",
            ],
        },
        "commit_subject": "{branch} - CVE - Increasing jackson version to fix {cve}",
    },
    {
        "name": "netty",
        "lib_regex": r"^io\.netty_netty-",
        "affected_prefix": "4.1",
        "aligned_key": "netty4",
        "patch": {"type": "property", "names": ["netty.version"]},  # confirmed (4.1.132.Final)
        "commit_subject": "{branch} - CVE - Increasing netty version to fix {cve}",
    },
    {
        "name": "log4j2",
        "lib_regex": r"^org\.apache\.logging\.log4j",
        "aligned_key": "log4j2",
        "patch": {"type": "property", "names": ["log4j.version"]},  # confirmed (2.25.3)
        "commit_subject": "{branch} - CVE - Increasing log4j2 version to fix {cve}",
    },
    {
        "name": "commons-lang3",
        "lib_regex": r"^org\.apache\.commons_commons-lang3",
        "aligned_key": "commons-lang3",
        "patch": {"type": "property", "names": ["commons-lang3.version"]},  # confirmed (3.13.0)
        "commit_subject": "{branch} - CVE - Increasing commons-lang3 version to fix {cve}",
    },
    {
        "name": "lz4-java",
        "lib_regex": r"^org\.lz4_lz4-java",
        "affected_prefix": "1.8",
        "aligned_key": "lz4-java",
        "patch": {"type": "dependency", "group": "org.lz4", "artifact": "lz4-java"},
        "commit_subject": "{branch} - CVE - Increasing lz4-java version to fix {cve}",
    },
    {
        "name": "aircompressor",
        "lib_regex": r"^io\.airlift_aircompressor",
        "affected_prefix": "2.",
        "aligned_key": "aircompressor",
        "patch": {"type": "dependency", "group": "io.airlift", "artifact": "aircompressor"},
        "commit_subject": "{branch} - CVE - Increasing aircompressor version to fix {cve}",
    },
    {
        "name": "commons-compress",
        "lib_regex": r"^org\.apache\.commons_commons-compress",
        "aligned_key": "commons-compress",
        "patch": {"type": "property", "names": ["commons-compress.version"]},
        "commit_subject": "{branch} - CVE - Increasing commons-compress version to fix {cve}",
    },
    {
        "name": "commons-io",
        "lib_regex": r"^commons-io_commons-io",
        "aligned_key": "commons-io",
        "patch": {"type": "property", "names": ["commons-io.version"]},
        "commit_subject": "{branch} - CVE - Increasing commons-io version to fix {cve}",
    },
    {
        # okio standalone jar (okio-1.x.jar); 1.6/1.14 -> 1.17.6. The copy shaded
        # inside hadoop-client-runtime is handled by the shaded-bundle rules.
        "name": "okio",
        "lib_regex": r"^com\.squareup\.okio_okio",
        "affected_prefix": "1.",
        "aligned_key": "okio",
        "patch": {"type": "managed", "group": "com.squareup.okio", "artifact": "okio"},
        "commit_subject": "{branch} - CVE - Increasing okio version to fix {cve}",
    },
]


# ===================================================================
# Livy2 (org.apache.livy livy-main) — single Maven project, scala 2.12 / spark3
# ===================================================================
# Versions Livy can bump directly in its own poms to clear the fixable CVEs.
_LIVY2_ALIGNED = {
    # netty.version property -> netty-all; the individual netty-codec-* modules
    # come transitively from netty-all, so this bump reaches them too. Stay on
    # the 4.1.x line (4.1.133 covers every flagged codec CVE; 4.2.x is a major
    # line jump we deliberately avoid).
    "netty4": "4.1.133.Final",
    # jackson.version property (also drives jackson-databind/module-scala).
    "jackson2": "2.18.6",
    # direct <dependency> in the root pom (hard-coded version, not a property).
    "commons-configuration2": "2.15.0",
}

# Fix targets — directly fixable in livy2's own poms.
_LIVY2_FIX_TARGETS = [
    {
        # netty.version is declared twice (top-level properties AND inside the
        # spark3 build profile, which overrides it); patch.all bumps both so the
        # change takes effect under -Pspark3.
        "name": "netty",
        "lib_regex": r"^io\.netty_netty-",
        "affected_prefix": "4.1",
        "aligned_key": "netty4",
        "patch": {"type": "property", "names": ["netty.version"], "all": True},
        "commit_subject": "{branch} - CVE - Increasing netty version to fix {cve}",
    },
    {
        "name": "jackson",
        "lib_regex": r"^com\.fasterxml\.jackson",
        "aligned_key": "jackson2",
        "patch": {"type": "property", "names": ["jackson.version"]},
        "commit_subject": "{branch} - CVE - Increasing jackson version to fix {cve}",
    },
    {
        "name": "commons-configuration2",
        "lib_regex": r"^org\.apache\.commons_commons-configuration2",
        "aligned_key": "commons-configuration2",
        "patch": {"type": "dependency",
                  "group": "org.apache.commons", "artifact": "commons-configuration2"},
        "commit_subject": ("{branch} - CVE - Increasing commons-configuration2 "
                           "version to fix {cve}"),
    },
]

# Exception rules — routed to "Exception Request" (Deferred). Matched per-ticket
# by case-insensitive substring of the affected library name (+ optional
# affected_prefix / path_contains). Order matters: first match wins.
_LIVY2_EXCEPTION_RULES = [
    {
        # Already routed (10 tickets done); kept for idempotency. Already-handled
        # tickets are assigned + Exception Request, so the analyser's
        # assignee=empty / status="To Do" JQL no longer returns them and this
        # rule simply does not fire on re-runs.
        "match": "libthrift",
        "description": ("Hive and other Hadoop components does not have fix for "
                        "this CVE and increase libthrift to 0.23.0 requires more "
                        "changes across all the ODP components"),
    },
    {
        "match": "org.eclipse.jetty",
        "affected_prefix": "9.4",
        "description": ("jetty 9.4.57 (bundled in the jetty-runner fat jar) has no "
                        "fix on the 9.4.x line for this CVE; the fix is only in "
                        "jetty 11.x/12.x, a major upgrade requiring coordinated "
                        "changes across ODP components"),
    },
    {
        "match": "org.apache.mina",
        "description": ("mina-core 2.2.3 is bundled inside the third-party "
                        "jetty-runner fat jar (org.eclipse.jetty:jetty-runner) and "
                        "is not a separately-managed Livy dependency, so it cannot "
                        "be bumped independently; Livy already excludes mina-core "
                        "from its declared (test) dependencies"),
    },
    {
        "match": "org.apache.commons_commons-lang3",
        "path_contains": r"jetty-runner",
        "description": ("Livy's own commons-lang3 is already managed at 3.18.0 "
                        "(the fixed version); the flagged 3.17.0 copy is bundled "
                        "inside the third-party jetty-runner fat jar and cannot be "
                        "bumped via the version property"),
    },
    {
        "match": "commons-lang_commons-lang",
        "description": ("commons-lang 2.6 is the last release of the EOL "
                        "commons-lang 2.x line; this CVE has no fixed version "
                        "available"),
    },
    {
        "match": "org.apache.zookeeper",
        "description": ("ZooKeeper is a platform-built component (ODP fork "
                        "3.5.10.x); upgrading to the fixed 3.8.3 / 3.9.x line is "
                        "owned by the platform ZooKeeper build and applied across "
                        "ODP components, not inside Livy"),
    },
    {
        "match": "org.apache.hadoop_hadoop-common",
        "description": ("hadoop-common is a platform-built ODP Hadoop fork; the "
                        "fix (3.2.4 / 3.3.3) is owned by the platform Hadoop build "
                        "and coordinated across ODP components, not bumpable "
                        "inside Livy"),
    },
    {
        "match": "org.apache.hive",
        "description": ("the fix is only available in Hive 4.0.0; Livy depends on "
                        "the ODP Hive 3.1.4 fork and upgrading it is a major, "
                        "cross-component change"),
    },
    {
        "match": "org.apache.livy_livy-server",
        "description": ("these are vulnerabilities in Livy's own server code; the "
                        "only published fix is the 0.9.0-incubating release, so "
                        "addressing them requires backporting the upstream "
                        "security fixes into this 0.8.0 fork (a code change, not a "
                        "dependency bump)"),
    },
    {
        "match": "org.pac4j",
        "description": ("pac4j-core 4.5.5 is an undeclared transitive dependency; "
                        "the only fix is a major version jump to 5.7.10 / 6.4.1, a "
                        "breaking API change that must be coordinated across "
                        "components"),
    },
]

# Shaded-bundle rules — CVEs whose vulnerable class lives inside a third-party
# fat jar. Only htrace-core4 here (jackson 2.4.0 shaded inside it). The
# jetty-runner-bundled CVEs (mina / jetty-http / jetty-io / commons-lang3) are
# intentionally NOT given a shaded rule so they fall through to the per-library
# exception rules above, which carry their distinct rationale; the
# velocity-engine-core commons-io copy is left untouched (transitive; Livy's own
# commons-io is already 2.16.1 >= the 2.14.0 fix) and surfaces in the
# "unmatched shaded" report for manual review.
_LIVY2_SHADED_BUNDLE_RULES = [
    {
        "bundle": "htrace-core",
        "action": "exception",
        "description": ("This CVE is pulled from Hadoop which in-turn from "
                        "htrace-core*. And htrace-core* is a non-active third "
                        "party library; And hence we require exception"),
    },
]

# Verified build: full Java/Scala reactor, tests skipped. Excludes the
# spark-binary-download integration tests, the Python packaging module, the
# coverage aggregator (needs the integration-test jar) and the assembly (bundles
# the excluded modules). remoteresources.skip works around an unresolvable ASF
# incubator-disclaimer SNAPSHOT bundle in the configured repos.
_LIVY2_BUILD_CMD = (
    "mvn clean package -DskipTests -Pspark3 -Dremoteresources.skip=true "
    "-pl '!integration-test,!thriftserver/server,!coverage,!python-api,!assembly'"
)


# Shared spark3 build settings (confirmed: all spark3 lines build on the
# 3.2.3.7 baseline with JDK 8 and the same make-distribution invocation).
# JDK home comes from resolve_java_home(8) / CVE_JAVA_HOME_8 (see top of file).
_SPARK3_BUILD_CMD = (
    "sh -x dev/make-distribution.sh --tgz "
    "-Phadoop-3.2,hive,hive-thriftserver,yarn,sparkr,kubernetes,"
    "hadoop-cloud,iceberg,hudi,delta,gluten "
    "-DskipSparkTests -DskipTests -Dgpg.skip -Dskip=true "
    "-Dyarn.version=3.2.3.3.2.3.7-2 -Dhadoop.version=3.2.3.3.2.3.7-2"
)


# ===================================================================
# hbase-connectors (org.apache.hbase.connectors) — Maven, JDK 8,
# ci-friendly revision 1.1.0.3.2.3.7-2 on nightly/ODP-3.2.3.7-2.
# ===================================================================
# A thin connector project (kafka-proxy + spark connectors + assembly) built on
# top of the ODP HBase 2.5 / Hadoop 2.10/3.2 forks. Almost every flagged jar in
# the assembled lib/ is either (a) pulled transitively from the HBase/Hadoop
# platform forks, or (b) relocated inside a third-party shaded fat jar
# (hbase-shaded-netty, htrace-core4). The ONLY library hbase-connectors declares
# and manages itself is commons-lang3, so that is the single in-pom fix target.
#
# netty: all flagged netty CVEs live inside the HBase third-party shaded artifact
# org.apache.hbase.thirdparty:hbase-shaded-netty (the deployed lib was
# hbase-shaded-netty-4.1.10.jar = netty 4.1.116.Final). That artifact is pulled
# transitively from the HBase 2.5 fork, so it is pinned via a dependencyManagement
# override to the latest available 4.1.13 (= netty 4.1.131.Final) by the dedicated
# fix_hbase_netty.py driver. 4.1.13 clears the 6 older (2025) netty CVEs; the 13
# newer (2026) CVEs need netty 4.1.132/4.1.133 which no hbase-thirdparty shaded
# release ships yet, so they fall through to the hbase-shaded-netty shaded rule
# below (Exception) once the covered 6 are closed.
_HBASE_CONNECTORS_ALIGNED = {
    "commons-lang3": "3.18.0",
}

_HBASE_CONNECTORS_FIX_TARGETS = [
    {
        # commons-lang3 is declared + managed in the root pom (3.17.0) and lands
        # in the assembled lib as commons-lang3-3.17.0.jar -> 3.18.0.
        "name": "commons-lang3",
        "lib_regex": r"^org\.apache\.commons_commons-lang3",
        "aligned_key": "commons-lang3",
        "patch": {"type": "property", "names": ["commons-lang3.version"]},
        "commit_subject": "{branch} - CVE - Increasing commons-lang3 version to fix {cve}",
    },
]

_HBASE_CONNECTORS_EXCEPTION_RULES = [
    {
        # protobuf-java 2.5.0 from the Hadoop 2.x stack; wire-format pinned.
        "match": "com.google.protobuf",
        "description": ("protobuf-java 2.5.0 is pulled transitively from the Hadoop "
                        "2.x stack and is pinned for Hadoop/HBase wire-format "
                        "compatibility; upgrading to 3.16.1+/3.25.5 is a major "
                        "change owned by the platform Hadoop/HBase build and "
                        "coordinated across ODP components"),
    },
    {
        # zookeeper 3.4.9 pulled transitively by the HBase 2.5 fork.
        "match": "org.apache.zookeeper",
        "description": ("ZooKeeper 3.4.9 is pulled transitively by the HBase 2.5 "
                        "fork; the fix requires a major upgrade to the 3.8.x/3.9.x "
                        "line which is owned by the platform ZooKeeper/HBase build "
                        "and coordinated across ODP components, not bumpable inside "
                        "hbase-connectors"),
    },
    {
        # hadoop-common 2.10.0 (hadoop-two) bundled by the HBase 2.5 stack.
        "match": "org.apache.hadoop",
        "description": ("hadoop-common 2.10.0 is the Hadoop 2.x artifact pulled "
                        "transitively by the HBase 2.5 stack; the fix is owned by "
                        "the platform Hadoop build and coordinated across ODP "
                        "components, not bumpable inside hbase-connectors"),
    },
    {
        "match": "commons-lang_commons-lang",
        "description": ("commons-lang 2.6 is the last release of the EOL "
                        "commons-lang 2.x line; CVE-2025-48924 has no fixed version "
                        "available for it"),
    },
    {
        "match": "com.fasterxml.woodstox",
        "description": ("woodstox-core 5.0.3 is pulled transitively from the Hadoop "
                        "stack; upgrading it is owned by the platform Hadoop build "
                        "and coordinated across ODP components"),
    },
    {
        "match": "commons-net_commons-net",
        "description": ("commons-net 3.1 is pulled transitively from the Hadoop "
                        "stack; upgrading it is owned by the platform Hadoop build "
                        "and coordinated across ODP components"),
    },
    {
        "match": "org.apache.httpcomponents",
        "description": ("httpclient 4.5.2 is pulled transitively from the "
                        "Hadoop/HBase stack; upgrading it is owned by the platform "
                        "Hadoop/HBase build and coordinated across ODP components"),
    },
    {
        "match": "io.opentelemetry",
        "description": ("opentelemetry-api 1.49.0 is pulled transitively by the "
                        "HBase 2.5 fork; upgrading to 1.62.0 is owned by the "
                        "platform HBase build and coordinated across ODP "
                        "components"),
    },
]

_HBASE_CONNECTORS_SHADED_BUNDLE_RULES = [
    {
        # netty relocated inside HBase's third-party shaded artifact. After the
        # dedicated driver bumps it to 4.1.13 (netty 4.1.131) and closes the 6
        # covered (2025) CVEs, the remaining 13 (2026) CVEs land here.
        "bundle": "hbase-shaded-netty",
        "action": "exception",
        "description": ("the flagged netty classes are bundled inside HBase's "
                        "third-party shaded artifact "
                        "(org.apache.hbase.thirdparty:hbase-shaded-netty), which "
                        "has been upgraded to the latest available 4.1.13 "
                        "(netty 4.1.131.Final). These CVEs are fixed only in netty "
                        "4.1.132.Final / 4.1.133.Final, which is not yet shipped by "
                        "any hbase-thirdparty shaded release, so they are deferred "
                        "until hbase-thirdparty ships the patched netty"),
    },
    {
        # jackson relocated inside the abandoned htrace-core4 fat jar.
        "bundle": "htrace-core",
        "action": "exception",
        "description": ("This CVE is pulled from Hadoop which in-turn from "
                        "htrace-core*. And htrace-core* is a non-active third "
                        "party library; And hence we require exception"),
    },
]


# ===================================================================
# pinot (org.apache.pinot) — large Maven reactor, JDK 11, fork version
# 1.3.0.3.2.3.7-2 on nightly/ODP-3.2.3.7-2.
# ===================================================================
# Every flagged CVE lives inside one of Pinot's OWN build artifacts -- the
# plugin fat jars (pinot-orc / pinot-parquet / pinot-kinesis / pinot-pulsar /
# pinot-kafka / pinot-batch-ingestion-spark-*-shaded.jar) and the
# pinot-all-*-jar-with-dependencies.jar uber jar. Those are rebuilt from source,
# so for every library Pinot CENTRALLY MANAGES at the flagged version (netty,
# log4j, helix, commons-lang3, commons-configuration2, nimbus-jose-jwt,
# aircompressor, async-http-client), bumping the managed property + rebuilding
# flows the fixed version into the shaded jars -> in-pom fix targets.
# `built_jar_prefixes` = ("pinot-",) makes the analyser treat these as
# component-built (not third-party shaded), so the per-library fix/exception
# rules below decide each case (mirrors how spark-*.jar is handled for spark2).
#
# EXCEPTIONS: libraries whose flagged version is a HARD TRANSITIVE that Pinot's
# dependencyManagement does NOT displace into the shaded jar (protobuf-java 2.5.0
# and okio 1.6.0 -- Pinot manages 3.25.5 / 3.10.2, but the old copies come from
# Hadoop/Parquet), platform forks (hadoop-common/hdfs, zookeeper -- ODP
# 3.2.3.x/3.5.10.x suffix), and jetty 9.4.57 (no fix on the 9.4.x line; the fix
# is only in 11.x/12.x, a breaking javax->jakarta upgrade).
#
# DEFERRED (handled last, per request): the jackson 2.4.0 cluster -- 53
# jackson-databind + the 6 jackson-core copies all at 2.4.0, shaded inside
# pinot-orc (transitive from ORC/hive-storage-api, not displaced by Pinot's
# managed 2.18.2). There is intentionally NO jackson fix target and NO jackson
# rule, so these (plus the 2 jackson-core 2.18.x copies that share the same
# jackson.version property and will be cleared together with the cluster) stay
# in "To Do" untouched until the jackson cluster is addressed.
_PINOT_ALIGNED = {
    "netty4": "4.1.135.Final",            # managed netty.version 4.1.132 -> fix >= 4.1.133
    "log4j2": "2.25.4",                    # log4j.version 2.25.3 -> 2.25.4
    "helix": "1.3.0",                      # helix.version 1.2.0 -> 1.3.0
    "commons-lang3": "3.18.0",             # commons-lang3.version 3.17.0 -> 3.18.0
    "commons-configuration2": "2.15.0",    # 2.11.0 -> 2.15.0
    "nimbus-jose": "10.0.2",               # nimbus-jose-jwt.version 10.0.1 -> 10.0.2 (10.x line)
    "aircompressor": "2.0.3",              # 2.0.2 -> 2.0.3
    "async-http-client": "3.0.10",         # 3.0.1 -> 3.0.10 (3.0.x line)
}

_PINOT_FIX_TARGETS = [
    {
        "name": "netty",
        "lib_regex": r"^io\.netty_netty-",
        "affected_prefix": "4.1",
        "aligned_key": "netty4",
        "patch": {"type": "property", "names": ["netty.version"]},
        "commit_subject": "{branch} - CVE - Increasing netty version to fix {cve}",
    },
    {
        "name": "log4j2",
        "lib_regex": r"^org\.apache\.logging\.log4j",
        "aligned_key": "log4j2",
        "patch": {"type": "property", "names": ["log4j.version"]},
        "commit_subject": "{branch} - CVE - Increasing log4j2 version to fix {cve}",
    },
    {
        "name": "helix",
        "lib_regex": r"^org\.apache\.helix",
        "aligned_key": "helix",
        "patch": {"type": "property", "names": ["helix.version"]},
        "commit_subject": "{branch} - CVE - Increasing helix version to fix {cve}",
    },
    {
        "name": "commons-lang3",
        "lib_regex": r"^org\.apache\.commons_commons-lang3",
        "aligned_key": "commons-lang3",
        "patch": {"type": "property", "names": ["commons-lang3.version"]},
        "commit_subject": "{branch} - CVE - Increasing commons-lang3 version to fix {cve}",
    },
    {
        "name": "commons-configuration2",
        "lib_regex": r"^org\.apache\.commons_commons-configuration2",
        "aligned_key": "commons-configuration2",
        "patch": {"type": "property", "names": ["commons-configuration2.version"]},
        "commit_subject": ("{branch} - CVE - Increasing commons-configuration2 "
                           "version to fix {cve}"),
    },
    {
        "name": "nimbus-jose-jwt",
        "lib_regex": r"^com\.nimbusds_nimbus-jose-jwt",
        "aligned_key": "nimbus-jose",
        "patch": {"type": "property", "names": ["nimbus-jose-jwt.version"]},
        "commit_subject": ("{branch} - CVE - Increasing nimbus-jose-jwt version "
                           "to fix {cve}"),
    },
    {
        "name": "aircompressor",
        "lib_regex": r"^io\.airlift_aircompressor",
        "aligned_key": "aircompressor",
        "patch": {"type": "property", "names": ["aircompressor.version"]},
        "commit_subject": "{branch} - CVE - Increasing aircompressor version to fix {cve}",
    },
    {
        "name": "async-http-client",
        "lib_regex": r"^org\.asynchttpclient_async-http-client",
        "aligned_key": "async-http-client",
        "patch": {"type": "property", "names": ["async-http-client.version"]},
        "commit_subject": ("{branch} - CVE - Increasing async-http-client version "
                           "to fix {cve}"),
    },
]

_PINOT_EXCEPTION_RULES = [
    {
        # protobuf-java 2.5.0 shaded inside pinot-parquet; Pinot manages 3.25.5
        # but the 2.5.0 copy is a hard transitive from the Hadoop stack pulled by
        # parquet, pinned for Hadoop wire-format compatibility.
        "match": "com.google.protobuf",
        "description": ("protobuf-java 2.5.0 is a hard transitive pulled by the "
                        "Hadoop stack into the pinot-parquet shaded jar and is "
                        "pinned for Hadoop wire-format compatibility; Pinot's own "
                        "managed protobuf is already 3.25.5, but the bundled 2.5.0 "
                        "copy is not displaced by Pinot's dependencyManagement and "
                        "upgrading it is owned by the platform Hadoop build, "
                        "coordinated across ODP components"),
    },
    {
        # okio 1.6.0 shaded inside pinot-parquet; Pinot manages 3.10.2 but the
        # 1.6.0 copy is a hard transitive from parquet that dM does not displace.
        "match": "com.squareup.okio_okio",
        "affected_prefix": "1.",
        "description": ("okio 1.6.0 is a hard transitive bundled inside the "
                        "pinot-parquet shaded jar; Pinot's own managed okio is "
                        "already 3.10.2, but the 1.6.0 copy pulled by Parquet is "
                        "not displaced by Pinot's dependencyManagement and can "
                        "only be addressed by upgrading Apache Parquet, a "
                        "separate coordinated change"),
    },
    {
        # jetty 9.4.57 inside pinot-parquet; no fix on the 9.4.x line.
        "match": "org.eclipse.jetty",
        "affected_prefix": "9.4",
        "description": ("jetty 9.4.57 (bundled in the pinot-parquet shaded jar via "
                        "the Hadoop stack) has no fix on the 9.4.x line for this "
                        "CVE; the fix is only in jetty 11.x/12.x, a major "
                        "javax->jakarta upgrade requiring coordinated changes "
                        "across ODP components"),
    },
    {
        # hadoop-common / hadoop-hdfs are the ODP platform Hadoop fork.
        "match": "org.apache.hadoop",
        "description": ("hadoop-common / hadoop-hdfs are the ODP platform Hadoop "
                        "fork (version suffix 3.2.3.x); the fix is owned by the "
                        "platform Hadoop build and coordinated across ODP "
                        "components, not bumpable inside Pinot"),
    },
    {
        # zookeeper is the ODP platform ZooKeeper fork (3.5.10.x).
        "match": "org.apache.zookeeper",
        "description": ("ZooKeeper is a platform-built component (ODP fork "
                        "3.5.10.x); upgrading to the fixed 3.8.x/3.9.x line is "
                        "owned by the platform ZooKeeper build and applied across "
                        "ODP components, not inside Pinot"),
    },
]


# ===================================================================
# Profiles
# ===================================================================
PROFILES = {
    # ---- spark2 (proven; unchanged behavior) ----
    "spark2": {
        "repo": "sehajsandhu/spark2",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/spark.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/spark",   # existing spark2 checkout
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        "build_cmd": (
            "sh -x dev/make-distribution.sh --tgz "
            "-Phadoop-3.2,hive,hive-thriftserver,yarn,sparkr,kubernetes,"
            "hadoop-cloud,iceberg,hudi,delta,gluten "
            "-DskipSparkTests -DskipTests -Dmaven.test.skip=true -Dgpg.skip -Dskip=true "
            "-Dyarn.version=3.2.3.3.2.3.7-2 -Dhadoop.version=3.2.3.3.2.3.7-2"
        ),
        "aligned_versions": _ODP_ALIGNED_BASE,
        "fix_targets": _SPARK2_FIX_TARGETS,
        "exception_rules": _SPARK2_EXCEPTION_RULES,
        "close_rules": _SPARK2_CLOSE_RULES,
        "shaded_bundle_rules": [],   # spark2 handles htrace via cve_analyser.CVE_PATH_RULES
    },

    # ---- spark3 3.5.5 (current scan target) ----
    "spark3-3.5.5": {
        "repo": "sehajsandhu/spark3",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/spark3.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "pom_path": "pom.xml",
        "java_home": _SPARK3_JAVA_HOME,
        "build_cmd": _SPARK3_BUILD_CMD,
        "aligned_versions": _merge(_ODP_ALIGNED_BASE, _ODP_ALIGNED_SPARK3),
        "fix_targets": _SPARK3_FIX_TARGETS,
        "exception_rules": _SPARK3_EXCEPTION_RULES,
        "close_rules": _SPARK3_CLOSE_RULES,
        "shaded_bundle_rules": _SPARK3_SHADED_BUNDLE_RULES,
    },

    # ---- spark3 3.5.1 ----
    "spark3-3.5.1": {
        "repo": "sehajsandhu/spark3_3_5_1",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/spark3.git",
        "target_branch": "nightly/ODP-3.5.1.3.2.3.7-2",
        "pom_path": "pom.xml",
        "java_home": _SPARK3_JAVA_HOME,
        "build_cmd": _SPARK3_BUILD_CMD,
        "aligned_versions": _merge(_ODP_ALIGNED_BASE, _ODP_ALIGNED_SPARK3),
        "fix_targets": _SPARK3_FIX_TARGETS,
        "exception_rules": _SPARK3_EXCEPTION_RULES,
        "close_rules": _SPARK3_CLOSE_RULES,
        "shaded_bundle_rules": _SPARK3_SHADED_BUNDLE_RULES,
    },

    # ---- spark3 3.3.3 ----
    "spark3-3.3.3": {
        "repo": "sehajsandhu/spark3_3_3_3",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/spark3.git",
        "target_branch": "nightly/ODP-3.3.3.3.2.3.7-2",
        "pom_path": "pom.xml",
        "java_home": _SPARK3_JAVA_HOME,
        "build_cmd": _SPARK3_BUILD_CMD,
        "aligned_versions": _merge(_ODP_ALIGNED_BASE, _ODP_ALIGNED_SPARK3),
        "fix_targets": _SPARK3_FIX_TARGETS,
        "exception_rules": _SPARK3_EXCEPTION_RULES,
        "close_rules": _SPARK3_CLOSE_RULES,
        "shaded_bundle_rules": _SPARK3_SHADED_BUNDLE_RULES,
    },

    # ---- livy2 (org.apache.livy, single Maven project on the ODP-3.2.3.7-2
    #      baseline; existing local checkout) ----
    "livy2": {
        "repo": "sehajsandhu/livy2",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/livy.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/livy",
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        "build_cmd": _LIVY2_BUILD_CMD,
        "aligned_versions": _LIVY2_ALIGNED,
        "fix_targets": _LIVY2_FIX_TARGETS,
        "exception_rules": _LIVY2_EXCEPTION_RULES,
        "close_rules": [],
        "shaded_bundle_rules": _LIVY2_SHADED_BUNDLE_RULES,
    },

    # ---- livy3_3_5_1: Livy built against Spark 3.5.1 (separate branch
    #      nightly/ODP-3.5.1.3.2.3.7-2). Same affected-lib versions as livy3
    #      (netty 4.1.132, jackson 2.15.4, commons-configuration2 2.11.0, ...),
    #      so it reuses the livy2 fix targets / shaded rules. Extra exception
    #      rule: standalone commons-lang3 jars (3.13.0 / 3.14.0) pulled
    #      transitively from the Spark 3.5.1 distribution (Livy declares no
    #      commons-lang3 on this branch). ----
    "livy3_3_5_1": {
        "repo": "sehajsandhu/livy3_3_5_1",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/livy.git",
        "target_branch": "nightly/ODP-3.5.1.3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/livy3_3_5_1",
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        "build_cmd": _LIVY2_BUILD_CMD,
        "aligned_versions": _LIVY2_ALIGNED,
        "fix_targets": _LIVY2_FIX_TARGETS,
        "exception_rules": _LIVY2_EXCEPTION_RULES + [
            {
                # standalone commons-lang3 (NOT the jetty-runner-bundled copy) —
                # comes from the Spark 3.5.1 distribution; Livy does not manage it.
                "match": "org.apache.commons_commons-lang3",
                "description": ("commons-lang3 is pulled transitively from the "
                                "Spark 3.5.1 baseline (spark.version "
                                "3.5.1.3.2.3.6-2); Livy declares/manages no "
                                "commons-lang3 on this branch and the bundled jars "
                                "come from the Spark distribution, so it cannot be "
                                "displaced independently - fix owned by the Spark "
                                "baseline. Deferred."),
            },
        ],
        "close_rules": [],
        "shaded_bundle_rules": _LIVY2_SHADED_BUNDLE_RULES,
    },

    # ---- livy3_3_3_3: Livy built against Spark 3.3.3 (separate branch
    #      nightly/ODP-3.3.3.3.2.3.7-2). Same affected-lib versions as
    #      livy3 / livy3_3_5_1 (netty 4.1.132, jackson 2.15.4,
    #      commons-configuration2 2.11.0, jetty 9.4.57, libthrift 0.16.0), so it
    #      reuses the livy2 fix targets / shaded rules. Scala 2.12.18,
    #      spark.version 3.3.3.3.2.3.7-2. Extra exception rule: standalone
    #      commons-lang3 jars pulled transitively from the Spark 3.3.3
    #      distribution (Livy declares no commons-lang3 on this branch). ----
    "livy3_3_3_3": {
        "repo": "sehajsandhu/livy3_3_3_3",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/livy.git",
        "target_branch": "nightly/ODP-3.3.3.3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/livy3_3_3_3",
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        "build_cmd": _LIVY2_BUILD_CMD,
        "aligned_versions": _LIVY2_ALIGNED,
        "fix_targets": _LIVY2_FIX_TARGETS,
        "exception_rules": _LIVY2_EXCEPTION_RULES + [
            {
                # standalone commons-lang3 (NOT the jetty-runner-bundled copy) —
                # comes from the Spark 3.3.3 distribution; Livy does not manage it.
                "match": "org.apache.commons_commons-lang3",
                "description": ("commons-lang3 is pulled transitively from the "
                                "Spark 3.3.3 baseline (spark.version "
                                "3.3.3.3.2.3.7-2); Livy declares/manages no "
                                "commons-lang3 on this branch and the bundled jars "
                                "come from the Spark distribution, so it cannot be "
                                "displaced independently - fix owned by the Spark "
                                "baseline. Deferred."),
            },
        ],
        "close_rules": [],
        "shaded_bundle_rules": _LIVY2_SHADED_BUNDLE_RULES,
    },

    # ---- hbase-connectors (org.apache.hbase.connectors; Maven, JDK 8;
    #      nightly/ODP-3.2.3.7-2). Only commons-lang3 is fixed in-pom; netty is
    #      pinned via hbase-shaded-netty by fix_hbase_netty.py; everything else
    #      is transitive (HBase/Hadoop forks) or shaded -> Exception. ----
    "hbase-connectors": {
        "repo": "sehajsandhu/hbase-connectors",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/hbase-connectors.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/hbase-connectors",
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        # The reactor needs hbase-shaded-mapreduce / hbase-shaded-testing-util
        # and the ODP HBase 2.5 / Hadoop forks, which live in the acceldata
        # odp-staging-release repo (not the odp-release repo the global
        # ~/.m2/settings.xml mirrors); hbc-settings.xml mirrors to staging.
        "build_cmd": (
            "mvn -s ~/cve_fix_workdir/hbc-settings.xml clean package "
            "-DskipTests -Dmaven.test.skip=true "
            "-Dcheckstyle.skip=true -Dspotless.check.skip=true "
            "-Dspotless.apply.skip=true -Drat.skip=true -Denforcer.skip=true "
            "-Dmaven.javadoc.skip=true"
        ),
        "aligned_versions": _HBASE_CONNECTORS_ALIGNED,
        "fix_targets": _HBASE_CONNECTORS_FIX_TARGETS,
        "exception_rules": _HBASE_CONNECTORS_EXCEPTION_RULES,
        "close_rules": [],
        "shaded_bundle_rules": _HBASE_CONNECTORS_SHADED_BUNDLE_RULES,
    },

    # ---- pinot (org.apache.pinot; Maven, JDK 11; fork 1.3.0.3.2.3.7-2 on
    #      nightly/ODP-3.2.3.7-2). All CVEs live inside Pinot's own shaded
    #      plugin/uber jars (built_jar_prefixes=("pinot-",) -> treated as
    #      component-built). 8 managed-property fix targets, 5 exception rules
    #      (protobuf 2.5 / okio 1.6 / jetty 9.4 / hadoop / zookeeper). The
    #      jackson 2.4.0 cluster is deferred -> no jackson rule, stays To Do. ----
    "pinot": {
        "repo": "sehajsandhu/pinot",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/pinot.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/pinot",
        "pom_path": "pom.xml",
        # Pinot requires JDK 11 (jdk.version=11), unlike the JDK 8 components.
        "java_home": _JDK11,
        # Reuses hbc-settings.xml (adds the acceldata odp-staging-release repo,
        # which hosts the ODP Hadoop/ZooKeeper forks the reactor needs).
        "build_cmd": (
            "mvn -s ~/cve_fix_workdir/hbc-settings.xml clean package "
            "-DskipTests -Dmaven.test.skip=true "
            "-Dcheckstyle.skip=true -Dspotless.check.skip=true "
            "-Dspotless.apply.skip=true -Drat.skip=true -Denforcer.skip=true "
            "-Dspotbugs.skip=true -Dmaven.javadoc.skip=true"
        ),
        "built_jar_prefixes": ("pinot-",),
        "aligned_versions": _PINOT_ALIGNED,
        "fix_targets": _PINOT_FIX_TARGETS,
        "exception_rules": _PINOT_EXCEPTION_RULES,
        "close_rules": [],
        "shaded_bundle_rules": [],
    },

    # ---- clickhouse (ch-ui-wrapper Spring Boot 2.7.18 web app; Maven, JDK 11;
    #      fork version 1.0.0.3.2.3.7-2 on acceldata-io/ch-ui
    #      nightly/ODP-3.2.3.7-2). ALL 70 flagged CVEs live inside the single
    #      ch-ui-wrapper fat jar (BOOT-INF/lib/*). The wrapper just serves the
    #      CH-UI static bundle, so the deps are plain Spring Boot managed
    #      libraries fixable by overriding the version properties + rebuilding.
    #      Routing is handled by the dedicated fix_clickhouse_cves.py driver
    #      (version-aware: the tomcat / spring families split fix-vs-exception by
    #      the per-ticket FIXED version, which the generic rule system cannot
    #      express), so the fix_targets / rule lists here are intentionally empty.
    #
    #      FIX (52 props bumped, build-verified in BOOT-INF/lib):
    #        tomcat.version            9.0.109 -> 9.0.119  (latest 9.0.x)
    #        jackson-bom.version       2.15.0  -> 2.18.6
    #        logback.version           1.4.12  -> 1.5.37   (+ slf4j 2.0.18 so the
    #                                                       1.5.x binding resolves)
    #        spring-framework.version  5.3.31  -> 5.3.39   (latest OSS 5.3.x)
    #        snakeyaml.version         already 2.0 (covers all 7)
    #      EXCEPTION: spring-boot (needs Boot 3.x/JDK17), spring-framework CVEs
    #        whose only fix is 5.3.40+ (commercial-only) / 6.x / 7.x, and tomcat
    #        CVEs with no 9.0.x fix (only 10.1.x/11.x = jakarta namespace,
    #        incompatible with Spring Boot 2.7). ----
    "clickhouse": {
        "repo": "sehajsandhu/clickhouse",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/ch-ui.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/ch-ui",
        "pom_path": "ch-ui-wrapper/pom.xml",
        # Spring Boot 2.7 + logback 1.5.x / tomcat 9.0.119 build on JDK 11.
        "java_home": _JDK11,
        "build_cmd": ("mvn -q -DskipTests -f ch-ui-wrapper/pom.xml clean package"),
        "aligned_versions": {},
        "fix_targets": [],
        "exception_rules": [],
        "close_rules": [],
        "shaded_bundle_rules": [],
    },

    # ---- druid (org.apache.druid; large Maven reactor on acceldata-io/druid
    #      nightly/ODP-3.2.3.7-2, fork 29.0.1.3.2.3.6-2, builds on JDK 8). 72
    #      flagged CVEs span many libs. Delivered in phases by the
    #      fix_druid_cves.py driver (categorisation is path/version-aware, which
    #      the generic rule flow cannot express), so the rule lists here are
    #      empty.
    #      PHASE 1 fixes (root pom, low risk): log4j 2.25.3->2.25.4,
    #        netty4 4.1.132->4.1.135.Final, postgresql 42.7.2->42.7.11,
    #        json-path 2.3.0->2.9.0.
    #      EXCEPTIONS: shaded in hadoop-client-runtime/parquet-jackson/htrace/
    #        velocity fat jars; ODP platform forks (hadoop/zookeeper/ranger);
    #        druid-basic-security (Druid own code, backport); netty3 EOL;
    #        jetty 9.4 (jakarta); elasticsearch/pac4j major; async-http-client
    #        (3.x needs JDK11) and nimbus (10.x needs JDK11 / already >= 9.x fix).
    #      PHASE 2 (deferred): jackson, snakeyaml, aircompressor, woodstox,
    #        azure-identity, jose4j, reactor-netty, plexus-utils. ----
    "druid": {
        "repo": "sehajsandhu/druid",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/druid.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/druid",
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        # hbc-settings.xml has NO global mirror, so Druid's own pom repositories
        # (esp. the mulesoft 'sigar' repo hosting org.hyperic:sigar-dist) resolve
        # -- the global ~/.m2 settings mirrors *,!central to the ODP nexus, which
        # lacks sigar-dist and breaks druid-processing.
        "build_cmd": ("mvn -s ~/cve_fix_workdir/hbc-settings.xml clean install "
                      "-Pdist -DskipTests -Dmaven.test.skip=true "
                      "-Dweb.console.skip=true -Dcheckstyle.skip=true "
                      "-Dspotbugs.skip=true -Denforcer.skip=true -Dpmd.skip=true "
                      "-Drat.skip=true -Dmaven.javadoc.skip=true "
                      "-Danimal.sniffer.skip=true -Dspotless.check.skip=true "
                      "-Dforbiddenapis.skip=true"),
        "aligned_versions": {},
        "fix_targets": [],
        "exception_rules": [],
        "close_rules": [],
        "shaded_bundle_rules": [],
    },

    # ---- tez (org.apache.tez 0.10.x ODP fork, acceldata-io/tez
    #      nightly/ODP-3.2.3.7-2, JDK 8). 45 flagged CVEs in 3.2.3.6. Fixes are
    #      tez-pom property/managed/dM bumps verified to compile + resolve
    #      (tez-ui builds an ancient node v5.12.0 with no darwin-arm binary, so the
    #      full tez-dist tarball is not assembled locally; validation is per-module
    #      compile + dependency:tree + shaded-jar inspection). Delivered as 7
    #      per-library PRs via the fix_tez_cves.py driver. ----
    "tez": {
        "repo": "sehajsandhu/tez",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/tez.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/tez",
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        "build_cmd": ("mvn -DskipTests -Dmaven.javadoc.skip=true -Drat.skip=true "
                      "-pl '!tez-ui,!tez-dist' -am clean install"),
        "aligned_versions": {},
        "fix_targets": [],
        "exception_rules": [],
        "close_rules": [],
        "shaded_bundle_rules": [],
    },

    # ---- impala (org.apache.impala 4.4.0 ODP fork, acceldata-io/impala
    #      nightly/ODP-3.2.3.7-2, JDK 8). 137 flagged CVEs in 3.2.3.6. A full
    #      Impala build needs the heavy native (C++) toolchain bootstrap, so the
    #      fixes (pure Java dependency version bumps in java/pom.xml +
    #      bin/impala-config.sh) are validated via Maven dependency resolution on
    #      node82 (JDK8). Delivered as 9 per-library PRs via the
    #      fix_impala_cves.py driver. libthrift/thrift -> Exception (cannot bump
    #      to 0.23.0: breaks Hive compilation); most netty/jackson copies are
    #      shaded inside third-party fat jars (kudu-client / ozone-filesystem /
    #      aws bundles / htrace / cos_api / iceberg-runtime) -> Exception. ----
    "impala": {
        "repo": "sehajsandhu/impala",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/impala.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/impala",
        "pom_path": "java/pom.xml",
        "java_home": _JDK8,
        "build_cmd": ("source bin/impala-config.sh >/dev/null 2>&1; "
                      "cd java && mvn -o dependency:tree"),
        "aligned_versions": {},
        "fix_targets": [],
        "exception_rules": [],
        "close_rules": [],
        "shaded_bundle_rules": [],
    },

    # ---- flink (org.apache.flink; large Maven reactor on acceldata-io/flink
    #      nightly/ODP-3.2.3.7-2). The only flagged CVEs in 3.2.3.6 are 6 log4j2
    #      tickets (5 log4j-core + 1 log4j-1.2-api, all 2.25.3) fixed in 2.25.4.
    #      log4j-* are managed in the root pom via the single <log4j.version>
    #      property and copied into flink/lib by flink-dist's bin.xml assembly,
    #      so a one-line property bump (2.25.3 -> 2.25.4) clears all 6. Delivered
    #      by the fix_flink_cves.py driver (single branch / PR / close). ----
    "flink": {
        "repo": "sehajsandhu/flink",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/flink.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/flink",
        "pom_path": "pom.xml",
        "java_home": _JDK11,
        "build_cmd": "mvn -q -DskipTests -pl flink-dist -am clean package",
        "aligned_versions": {"log4j2": "2.25.4"},
        "fix_targets": [
            {
                "name": "log4j2",
                "lib_regex": r"^org\.apache\.logging\.log4j",
                "aligned_key": "log4j2",
                "patch": {"type": "property", "names": ["log4j.version"]},
                "commit_subject": "{branch} - CVE - Increasing log4j2 version to fix {cve}",
            },
        ],
        "exception_rules": [],
        "close_rules": [],
        "shaded_bundle_rules": [],
    },

    # ---- livy3: SAME code/branch as livy2 (acceldata-io/livy
    #      nightly/ODP-3.2.3.7-2), only a different Jira repo tag /
    #      OSV ticket set. All build targets and routing rules are
    #      identical, so it reuses the livy2 rule constants. ----
    "livy3": {
        "repo": "sehajsandhu/livy3",
        "release": "3.2.3.6",
        "git_url": "https://github.com/acceldata-io/livy.git",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "workdir": "~/cve_fix_workdir/livy",
        "pom_path": "pom.xml",
        "java_home": _JDK8,
        "build_cmd": _LIVY2_BUILD_CMD,
        "aligned_versions": _LIVY2_ALIGNED,
        "fix_targets": _LIVY2_FIX_TARGETS,
        "exception_rules": _LIVY2_EXCEPTION_RULES,
        "close_rules": [],
        "shaded_bundle_rules": _LIVY2_SHADED_BUNDLE_RULES,
    },
}


def active_profile_name() -> str:
    return os.environ.get("CVE_PROFILE", DEFAULT_PROFILE)


def get_profile(name: str = None, release: str = None) -> dict:
    """Return a copy of the named profile with portable paths resolved.

    ``java_home`` is chosen from the ODP release baseline when possible:
    3.3.6.* → JDK 11, 3.2.3.* → JDK 8. Override the release with the
    ``release`` argument or ``CVE_RELEASE`` / ``CVE_ADDRESS_RELEASE`` env vars.
    ``workdir`` is under ``CVE_WORKDIR`` (default ``~/cve_fix_workdir``).
    """
    name = name or active_profile_name()
    if name not in PROFILES:
        raise SystemExit(
            f"Unknown CVE_PROFILE={name!r}. Options: {', '.join(sorted(PROFILES))}")
    p = dict(PROFILES[name])
    rel = effective_release(p, release)
    p["effective_release"] = rel

    if p.get("build_tool") == "python":
        jdk = None
    else:
        rel_jdk = jdk_major_for_release(rel)
        if rel_jdk is not None:
            jdk = rel_jdk
        elif p.get("jdk_version") is not None:
            jdk = int(p["jdk_version"])
        else:
            jh = p.get("java_home") or ""
            if jh and _JDK11 and jh == _JDK11:
                jdk = 11
            else:
                jdk = 8
        p["jdk_version"] = jdk

    if jdk is not None:
        p["java_home"] = resolve_java_home(int(jdk)) or (p.get("java_home") or "")
    p["workdir"] = resolve_workdir(name, p.get("workdir") or "")
    return p


def profile_env(profile: dict) -> dict:
    """Return the runtime-environment constraints for a profile:

        {"jdk": <int major or None>, "python": <str or None>,
         "build_tool": <"maven"|"gradle"|"python">}

    `jdk` comes from an explicit ``jdk_version`` field, else it is inferred from
    ``java_home`` (e.g. corretto-1.8 -> 8, corretto-11 -> 11, java-11-openjdk);
    it is None for non-JVM (python) components. These values let cve_fixer gate
    FIX vs EXCEPTION on environment compatibility: a patched library that
    requires a newer JDK/Python than the component runs on is NOT a valid fix
    and must be routed to an Exception (environment/compatibility constraint).
    """
    jdk = profile.get("jdk_version")
    if jdk is None:
        jh = (profile.get("java_home") or "")
        m = re.search(r"(?:corretto|temurin|zulu|jdk|java|jvm)[-_/]?(?:1\.)?(\d+)",
                      jh, re.IGNORECASE)
        if m:
            jdk = int(m.group(1))
        elif jh:
            jdk = 8  # a java_home is set but unrecognised -> assume legacy 8
        else:
            jdk = None  # python / non-JVM component
    return {
        "jdk": int(jdk) if jdk is not None else None,
        "python": profile.get("python_version"),
        "build_tool": profile.get("build_tool", "maven"),
    }


# ===================================================================
# NEW 3.2.3.6 To-Do components (authored as skeleton profiles).
# Jira-side fields (repo + release) are verified from query_release.
# git_url / target_branch are verified against acceldata-io repos on
# nightly/ODP-3.2.3.7-2. Rule lists start empty and are populated
# during triage. build_tool marks non-Maven components (apply_component
# only works for Maven pom profiles; others need run_shell drivers).
# Fields marked VERIFY still need confirmation before an APPLY run.
# ===================================================================

# JDK homes for skeleton profiles: resolved via env / common install paths
# (see resolve_java_home at top of file). Do NOT hardcode machine paths here.


def _skeleton(**kw):
    """Build a profile dict with empty rule lists + sane defaults."""
    base = {
        "release": "3.2.3.6",
        "target_branch": "nightly/ODP-3.2.3.7-2",
        "aligned_versions": {},
        "fix_targets": [],
        "exception_rules": [],
        "close_rules": [],
        "shaded_bundle_rules": [],
    }
    base.update(kw)
    return base


_NEW_PROFILES_326 = {
    # ---------- MAVEN components (apply_component-capable once rules filled) ----------
    "hbase": _skeleton(
        repo="sehajsandhu/hbase",
        git_url="https://github.com/acceldata-io/hbase.git",
        workdir="~/cve_fix_workdir/hbase",
        pom_path="pom.xml",
        java_home=_JDK8,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip=true "
                   "-Dspotbugs.skip=true -Drat.skip=true -Denforcer.skip=true "
                   "-Dmaven.javadoc.skip=true clean install"),
    ),
    "phoenix": _skeleton(
        repo="sehajsandhu/phoenix",
        git_url="https://github.com/acceldata-io/phoenix.git",
        workdir="~/cve_fix_workdir/phoenix",
        pom_path="pom.xml",
        java_home=_JDK8,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip=true "
                   "-Drat.skip=true -Dmaven.javadoc.skip=true clean install"),
    ),
    "knox": _skeleton(
        repo="sehajsandhu/knox",
        git_url="https://github.com/acceldata-io/knox.git",
        workdir="~/cve_fix_workdir/knox",
        pom_path="pom.xml",
        java_home=_JDK8,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Drat.skip=true "
                   "-Dmaven.javadoc.skip=true clean install"),
    ),
    "ozone": _skeleton(
        repo="sehajsandhu/ozone",
        git_url="https://github.com/acceldata-io/ozone.git",
        workdir="~/cve_fix_workdir/ozone",
        pom_path="pom.xml",
        java_home=_JDK8,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip=true "
                   "-Dspotbugs.skip=true -Drat.skip=true -Dmaven.javadoc.skip=true "
                   "clean install"),
    ),
    "ranger": _skeleton(
        repo="sehajsandhu/ranger",
        git_url="https://github.com/acceldata-io/ranger.git",
        workdir="~/cve_fix_workdir/ranger",
        pom_path="pom.xml",
        java_home=_JDK8,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Drat.skip=true "
                   "-Dmaven.javadoc.skip=true -pl '!ranger-tools' clean install"),  # VERIFY module list
    ),
}

_NEW_PROFILES_326.update({
    "nifi": _skeleton(
        repo="sehajsandhu/nifi",
        git_url="https://github.com/acceldata-io/nifi.git",
        workdir="~/cve_fix_workdir/nifi",
        pom_path="pom.xml",
        java_home=_JDK8,   # root pom compiles 1.8; >1.8 profile bumps to 11
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Dcheckstyle.skip=true "
                   "-Drat.skip=true -Dmaven.javadoc.skip=true clean install"),  # VERIFY: full reactor is very large
    ),
    "oozie": _skeleton(
        repo="sehajsandhu/oozie",
        git_url="https://github.com/acceldata-io/oozie.git",
        workdir="~/cve_fix_workdir/oozie",
        pom_path="pom.xml",
        java_home=_JDK8,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Drat.skip=true "
                   "-Dmaven.javadoc.skip=true clean install"),
    ),
    "zeppelin": _skeleton(
        repo="sehajsandhu/zeppelin",
        git_url="https://github.com/acceldata-io/zeppelin.git",
        workdir="~/cve_fix_workdir/zeppelin",
        pom_path="pom.xml",
        java_home=_JDK8,
        # web modules are npm; skip frontend to fix backend jar CVEs.
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Drat.skip=true "
                   "-Dmaven.javadoc.skip=true -pl '!zeppelin-web,!zeppelin-web-angular' "
                   "clean install"),  # VERIFY module list
    ),
    "ambari": _skeleton(
        repo="sehajsandhu/ambari",
        git_url="https://github.com/acceldata-io/ambari.git",
        target_branch="branch-2.7",   # VERIFY: no nightly/ODP-3.2.3.7-2 branch exists; branch-2.7 is the ODP maint line
        workdir="~/cve_fix_workdir/ambari",
        pom_path="pom.xml",
        java_home=_JDK8,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true -Drat.skip=true "
                   "-Dmaven.javadoc.skip=true -pl ambari-server,ambari-agent -am "
                   "clean install"),  # VERIFY module list + branch
    ),
})

# ---------- NON-MAVEN (Gradle) components: apply_component WON'T work;
#            fix via run_shell drivers editing gradle files. ----------
_NEW_PROFILES_326.update({
    "kafka": _skeleton(
        repo="sehajsandhu/kafka",
        git_url="https://github.com/acceldata-io/kafka.git",
        workdir="~/cve_fix_workdir/kafka",
        build_tool="gradle",
        pom_path=None,
        version_files=["gradle/dependencies.gradle", "gradle.properties"],  # ODP fork 2.8.2.3.2.3.7-2, scala 2.13.5
        java_home=_JDK8,
        build_cmd="./gradlew jar -x test",  # VERIFY
    ),
    "kafka3": _skeleton(
        repo="sehajsandhu/kafka3",
        git_url="https://github.com/acceldata-io/kafka3.git",  # VERIFY repo name
        workdir="~/cve_fix_workdir/kafka3",
        build_tool="gradle",
        pom_path=None,
        version_files=["gradle/dependencies.gradle", "gradle.properties"],
        java_home=_JDK11,
        build_cmd="./gradlew jar -x test",  # VERIFY
    ),
    "kudu": _skeleton(
        repo="sehajsandhu/kudu",
        git_url="https://github.com/acceldata-io/kudu.git",
        workdir="~/cve_fix_workdir/kudu",
        build_tool="gradle",
        pom_path=None,
        # Java side only (C++ core is CMake / out of scope for Java-lib CVEs).
        version_files=["java/gradle/dependencies.gradle"],
        gradle_dir="java",
        java_home=_JDK8,
        build_cmd="cd java && ./gradlew assemble -x test",  # VERIFY
    ),
    "registry": _skeleton(
        repo="sehajsandhu/registry",
        git_url="https://github.com/acceldata-io/registry.git",
        workdir="~/cve_fix_workdir/registry",
        build_tool="gradle",
        pom_path=None,
        version_files=["dependencies.gradle"],
        java_home=_JDK8,
        build_cmd="./gradlew assemble -x test",  # VERIFY
    ),
    "cruise-control": _skeleton(
        repo="sehajsandhu/cruise-control",
        git_url="https://github.com/acceldata-io/cruise-control.git",
        workdir="~/cve_fix_workdir/cruise-control",
        build_tool="gradle",
        pom_path=None,
        version_files=["build.gradle", "gradle.properties"],
        java_home=_JDK8,
        build_cmd="./gradlew jar -x test",  # VERIFY
    ),
    "cruise-control3": _skeleton(
        repo="sehajsandhu/cruise-control3",
        git_url="https://github.com/acceldata-io/cruise-control3.git",  # VERIFY repo name
        workdir="~/cve_fix_workdir/cruise-control3",
        build_tool="gradle",
        pom_path=None,
        version_files=["build.gradle", "gradle.properties"],
        java_home=_JDK11,
        build_cmd="./gradlew jar -x test",  # VERIFY
    ),
})

# ---------- PYTHON components: no JVM build; fix by pinning versions in
#            requirements / vendored packages via run_shell drivers. ----------
_NEW_PROFILES_326.update({
    "airflow": _skeleton(
        repo="sehajsandhu/airflow",
        git_url="https://github.com/acceldata-io/airflow.git",
        workdir="~/cve_fix_workdir/airflow",
        build_tool="python",
        pom_path=None,
        version_files=["odp/requirements.txt", "odp/requirements-source.txt", "pyproject.toml"],
        java_home=None,
        build_cmd=None,  # pip-constraint pins; no compile
    ),
    "hue": _skeleton(
        repo="sehajsandhu/hue",
        git_url="https://github.com/acceldata-io/hue.git",
        workdir="~/cve_fix_workdir/hue",
        build_tool="python",
        pom_path=None,
        # Many CVEs are in vendored ext-py*/<pkg>-<ver>/ trees -> bump the vendored dir.
        version_files=["desktop/core/requirements.txt", "desktop/core/base_requirements.txt"],
        vendored_root="desktop/core/ext-py",  # + ext-py3
        java_home=None,
        build_cmd=None,
    ),
    "jupyterhub": _skeleton(
        repo="sehajsandhu/jupyterhub",
        git_url="https://github.com/acceldata-io/jupyterhub.git",
        workdir="~/cve_fix_workdir/jupyterhub",
        build_tool="python",
        pom_path=None,
        version_files=["requirements.txt", "odp/requirements.txt", "pyproject.toml"],
        java_home=None,
        build_cmd=None,
    ),
})

# Register the new profiles into the master table.
PROFILES.update(_NEW_PROFILES_326)

# ---------- Profiles delivered in 3.3.6.4 / Ambari 3.0.0.1 remediations ----------
PROFILES.update({
    "odp-ambari": {
        "repo": "sehajsandhu/ambari",
        "release": "3.0.0.1",
        "git_url": "https://github.com/acceldata-io/odp-ambari.git",
        "target_branch": "rel/ODP-AMBARI-3.0.0.2-1",
        "workdir": "~/cve_fix_workdir/odp-ambari",
        "pom_path": "ambari-project/pom.xml",
        "java_home": _first_existing(
            os.environ.get("CVE_JAVA_HOME_17"),
            "/usr/lib/jvm/java-17-openjdk",
            "/usr/lib/jvm/java-17",
        ) or _JDK11,
        "jdk_version": 17,
        "build_cmd": (
            "mvn -q -N -f ambari-project/pom.xml validate "
            "-DskipTests -Dcheckstyle.skip=true -Drat.skip=true"
        ),
        "aligned_versions": {},
        "fix_targets": [],
        "exception_rules": [],
        "close_rules": [],
        "shaded_bundle_rules": [],
    },
    "superset": _skeleton(
        repo="sehajsandhu/superset",
        release="3.3.6.4",
        git_url="https://github.com/acceldata-io/superset.git",
        target_branch="rel/ODP-3.3.6.4-1",
        workdir="~/cve_fix_workdir/superset",
        build_tool="python",
        pom_path=None,
        version_files=["requirements/base.txt", "pyproject.toml"],
        java_home=None,
        build_cmd=None,
    ),
    "livy4": _skeleton(
        repo="sehajsandhu/livy4",
        release="3.3.6.4",
        git_url="https://github.com/acceldata-io/livy.git",
        target_branch="nightly/ODP-4.1.1.3.3.6.5",
        workdir="~/cve_fix_workdir/livy4",
        pom_path="pom.xml",
        java_home=_JDK11,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true clean package"),
    ),
    "spark4": _skeleton(
        repo="sehajsandhu/spark4",
        release="3.3.6.4",
        git_url="https://github.com/acceldata-io/spark3.git",
        target_branch="nightly/ODP-4.1.1.3.3.6.5",
        workdir="~/cve_fix_workdir/spark4",
        pom_path="pom.xml",
        java_home=_JDK11,
        build_cmd=("mvn -DskipTests -Dmaven.test.skip=true clean package"),
    ),
    "celeborn": _skeleton(
        repo="sehajsandhu/celeborn",
        release="3.3.6.4",
        git_url="https://github.com/acceldata-io/celeborn.git",
        target_branch="nightly/ODP-3.3.6.5",
        workdir="~/cve_fix_workdir/celeborn",
        pom_path="pom.xml",
        java_home=_JDK11,
        build_cmd=("mvn -DskipTests clean package"),
    ),
    "trino": _skeleton(
        repo="sehajsandhu/trino",
        release="3.2.3.6",
        git_url="https://github.com/acceldata-io/trino.git",
        target_branch="nightly/ODP-3.2.3.7-2",
        workdir="~/cve_fix_workdir/trino",
        pom_path="pom.xml",
        java_home=_JDK11,
        build_cmd=("./mvnw -DskipTests clean package"),
    ),
})

# Populate empty fix_targets / exception_rules from the unified catalog so the
# next release can reuse delivered Ambari/batch9–14 / pinot / etc. decisions.
# Hand-tuned spark2/spark3/livy/pinot/hbase-connectors lists are preserved
# (only_empty=True).
from cve_remediation_catalog import (  # noqa: E402
    COMPONENT_CATALOG,
    COMMON_EXCEPTION_RULES,
    apply_catalog_to_profiles,
    fix_targets_table,
)

_CATALOG_FILLED = apply_catalog_to_profiles(PROFILES, only_empty=True)
