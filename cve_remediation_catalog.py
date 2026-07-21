#!/usr/bin/env python3
"""
Unified CVE remediation catalog — single source of truth for next-release runs.

Contains:
  - COMMON_EXCEPTION_RULES  reusable match→reason templates (R1–R9 style)
  - COMPONENT_CATALOG       per-component fix_targets + exception_rules
  - apply_catalog_to_profiles()  fills empty profile rule lists from this catalog

Rule format matches cve_fixer.match_rule / cve_profiles:
  exception_rules: {match, description, optional affected_prefix|path_contains|cve}
  fix_targets:     {name, lib_regex, target_version, patch, optional aligned_key|affected_prefix}

Usage:
  from cve_remediation_catalog import COMPONENT_CATALOG, apply_catalog_to_profiles
  apply_catalog_to_profiles(PROFILES)

  # Inspect one component:
  python3 -c "from cve_remediation_catalog import summarize; summarize('odp-ambari')"
"""
from __future__ import annotations

import json
import os
from copy import deepcopy
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Shared / reusable exception rules (referenced by many components)
# ---------------------------------------------------------------------------

def _r(match: str, description: str, **extra) -> Dict[str, Any]:
    d: Dict[str, Any] = {"match": match, "description": description}
    d.update(extra)
    return d


COMMON_EXCEPTION_RULES: Dict[str, Dict[str, Any]] = {
    "libthrift": _r(
        "libthrift",
        "libthrift upgrade to 0.23.x is a breaking major from the ODP 0.16.x line "
        "and must be coordinated across Hive/Spark/ODP components, not bumped inside "
        "a single consumer.",
    ),
    "commons-lang-2.6": _r(
        "commons-lang_commons-lang",
        "commons-lang 2.6 is EOL with no fixed release (fix=open); migrate to "
        "commons-lang3 instead of a 2.x bump.",
    ),
    "jackson-mapper-asl": _r(
        "jackson-mapper-asl",
        "org.codehaus.jackson:jackson-mapper-asl 1.9.x is EOL (1.9.13 latest) with "
        "no fixed release; requires migration off Codehaus Jackson.",
    ),
    "jetty-9.4": _r(
        "org.eclipse.jetty",
        "Jetty 9.4.x has no fix on the 9.4 line for this advisory; remediation is "
        "only on Jetty 11/12 which is a major servlet/API migration.",
        affected_prefix="9.4",
    ),
    "jetty-12-only": _r(
        "org.eclipse.jetty",
        "Advisory fixed versions are Jetty 12.x only; component stays on Jetty 9/11 "
        "and cannot take a pure patch bump.",
    ),
    "hadoop-platform": _r(
        "org.apache.hadoop",
        "Hadoop is an ODP platform artifact; remediation belongs to the Hadoop/ODP "
        "line, not a consumer-only Maven bump to Apache 3.4.x.",
    ),
    "zookeeper-platform": _r(
        "org.apache.zookeeper",
        "ZooKeeper is an ODP platform fork; remediation requires an ODP ZK release "
        "bump applied across components.",
    ),
    "protobuf-wire": _r(
        "com.google.protobuf",
        "protobuf-java is pinned for Hadoop/Hive wire-format compatibility; "
        "upgrading to 3.x/33.x is a major cross-ODP change.",
    ),
    "aws-sdk-bundle-netty": _r(
        "io.netty",
        "Netty is shaded inside aws-java-sdk-bundle (fat jar); consumer netty-bom "
        "bumps do not rewrite the shaded bundle. Needs newer AWS SDK / hadoop-aws.",
        path_contains="aws-java-sdk-bundle",
    ),
    "htrace-jackson": _r(
        "com.fasterxml.jackson",
        "Jackson is embedded inside inactive third-party htrace-core*.jar; no viable "
        "bump without removing/replacing htrace.",
        path_contains="htrace-core",
    ),
    "velocity-commons-io": _r(
        "commons-io",
        "commons-io is embedded/repackaged inside velocity-engine-core; a top-level "
        "commons-io override does not rewrite that jar.",
        path_contains="velocity",
    ),
    "logback-1.3-to-1.5": _r(
        "ch.qos.logback",
        "Logback advisory requires 1.5.x while component is on 1.2/1.3; 1.5 is a "
        "breaking line for some stacks — treat as major unless Jakarta-aligned.",
    ),
    "okio-aws-transitive": _r(
        "okio",
        "okio is a transitive dependency from AWS/Hadoop client jars; not safely "
        "bumpable in isolation without rewriting those client stacks.",
    ),
    "spring-security-needs-6.1plus": _r(
        "org.springframework.security",
        "Advisory requires Spring Security 6.1+/6.2+/6.4+/6.5+; not patch-compatible "
        "with a Framework 6.0-only line without a coordinated Security+Framework upgrade.",
    ),
}


def _common(*keys: str) -> List[Dict[str, Any]]:
    return [deepcopy(COMMON_EXCEPTION_RULES[k]) for k in keys]


def _fix(
    name: str,
    lib_regex: str,
    target_version: str,
    patch: Dict[str, Any],
    *,
    aligned_key: Optional[str] = None,
    affected_prefix: Optional[str] = None,
    notes: str = "",
) -> Dict[str, Any]:
    t: Dict[str, Any] = {
        "name": name,
        "lib_regex": lib_regex,
        "target_version": target_version,
        "patch": patch,
        "commit_subject": (
            "{branch} - CVE - Bumped-up " + name + " to " + target_version
            + " to address {cve}"
        ),
    }
    if aligned_key:
        t["aligned_key"] = aligned_key
    if affected_prefix:
        t["affected_prefix"] = affected_prefix
    if notes:
        t["notes"] = notes
    return t


def _pin(name: str, package: str, version: str, req_file: str) -> Dict[str, Any]:
    """Python requirements pin fix target."""
    return {
        "name": name,
        "lib_regex": rf"(?i){package}",
        "target_version": version,
        "patch": {
            "type": "requirements",
            "file": req_file,
            "packages": [package],
        },
        "commit_subject": (
            f"{{branch}} - CVE - Bumped-up {name} to {version} to address {{cve}}"
        ),
    }


# ---------------------------------------------------------------------------
# Per-component catalog
# ---------------------------------------------------------------------------

COMPONENT_CATALOG: Dict[str, Dict[str, Any]] = {
    # ===== Already rich in cve_profiles — catalog mirrors for single lookup =====
    "spark2": {
        "notes": "Profile already populated; catalog mirror for next-release lookup.",
        "source": "cve_profiles._SPARK2_*",
        "fix_targets": [
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": [
                     "fasterxml.jackson.version",
                     "fasterxml.jackson-module-scala.version",
                     "fasterxml.jackson.databind.version"]},
                 aligned_key="jackson2"),
            _fix("netty", r"^io\.netty_netty-", "4.1.135.Final",
                 {"type": "dependency", "group": "io.netty", "artifact": "netty-all"},
                 affected_prefix="4.1", aligned_key="netty4"),
        ],
        "exception_rules": _common(
            "protobuf-wire", "jackson-mapper-asl", "libthrift", "jetty-9.4",
            "commons-lang-2.6",
        ) + [
            _r("io.netty_netty", "Netty 3.10.x has no fix on the 3.x line.",
               affected_prefix="3.10"),
            _r("io.netty_netty",
               "Netty shaded in aws-java-sdk-bundle; consumer BOM does not rewrite.",
               affected_prefix="4.1.130", path_contains="aws-java-sdk-bundle"),
            _r("com.squareup.okhttp3",
               "okhttp 3.x fix needs okhttp 4 / fabric8 5+ major upgrade."),
            _r("org.apache.calcite",
               "calcite bound to spark2 Hive 1.2 fork; fix needs calcite 1.26+ major."),
            _r("org.apache.spark_spark-core",
               "Spark UI XSS fixed only in Spark 3.2.2+/3.3; Spark 2.4 EOL."),
            _r("org.yaml_snakeyaml",
               "snakeyaml 2.0 incompatible with fabric8 4.x kubernetes-client."),
        ],
    },
    "spark3-3.5.5": {
        "alias_of": "spark3",
    },
    "spark3-3.5.1": {
        "alias_of": "spark3",
    },
    "spark3-3.3.3": {
        "alias_of": "spark3",
    },
    "spark3": {
        "notes": "Shared spark3 lines; see cve_profiles._SPARK3_*.",
        "source": "cve_profiles._SPARK3_*",
        "fix_targets": [
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": [
                     "fasterxml.jackson.version",
                     "fasterxml.jackson.databind.version"]},
                 aligned_key="jackson2"),
            _fix("netty", r"^io\.netty_netty-", "4.1.135.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1", aligned_key="netty4"),
            _fix("log4j2", r"log4j", "2.25.4",
                 {"type": "property", "names": ["log4j.version"]},
                 aligned_key="log4j2"),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons-lang3.version"]},
                 aligned_key="commons-lang3"),
            _fix("lz4-java", r"lz4-java", "1.8.1",
                 {"type": "dependency", "group": "org.lz4", "artifact": "lz4-java"}),
            _fix("aircompressor", r"aircompressor", "2.0.3",
                 {"type": "dependency", "group": "io.airlift", "artifact": "aircompressor"}),
            _fix("commons-compress", r"commons-compress", "1.26.1",
                 {"type": "property", "names": ["commons-compress.version"]},
                 aligned_key="commons-compress"),
            _fix("commons-io", r"commons-io", "2.16.1",
                 {"type": "property", "names": ["commons-io.version"]},
                 aligned_key="commons-io"),
            _fix("okio", r"okio", "1.17.6",
                 {"type": "managed", "group": "com.squareup.okio", "artifact": "okio"},
                 affected_prefix="1."),
        ],
        "exception_rules": _common(
            "libthrift", "jetty-9.4", "commons-lang-2.6", "zookeeper-platform",
            "protobuf-wire",
        ) + [
            _r("com.squareup.okhttp3",
               "okhttp 3.x needs okhttp 4 / fabric8 major upgrade."),
            _r("org.apache.hive",
               "Fix only in Hive 4.0.x; spark3 bundles Hive 2.3 fork."),
            _r("org.lz4_lz4-java",
               "lz4-java CVE-2025-66566 has no fixed release (fix=open).",
               cve="CVE-2025-66566"),
            _r("com.google.guava",
               "guava pinned for Hive 2.3 compatibility; 32.x is a major break."),
            _r("kotlin-stdlib",
               "kotlin-stdlib transitive from kubernetes-client/okhttp; deferred."),
            _r("org.ini4j_ini4j",
               "ini4j abandoned; CVE-2022-41404 has no fixed release."),
            _r("org.jdom_jdom2",
               "jdom2 from Aliyun OSS SDK via Hadoop connector; platform-owned."),
        ],
        "shaded_bundle_notes": (
            "hadoop-client-runtime/api, aws-java-sdk-bundle, iceberg-spark-runtime, "
            "gcs-connector, parquet-jackson, htrace-core, hudi-spark"
        ),
    },
    "livy2": {
        "source": "cve_profiles._LIVY2_*",
        "fix_targets": [
            _fix("netty", r"^io\.netty", "4.1.133.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1"),
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": ["jackson.version"]}),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "dependency", "group": "org.apache.commons",
                  "artifact": "commons-configuration2"}),
        ],
        "exception_rules": _common(
            "libthrift", "jetty-9.4", "commons-lang-2.6", "zookeeper-platform",
            "hadoop-platform", "htrace-jackson",
        ) + [
            _r("org.apache.mina", "mina via jetty-runner; not Livy-owned pin."),
            _r("commons-lang3", "commons-lang3 inside jetty-runner fat jar.",
               path_contains="jetty-runner"),
            _r("org.apache.hive", "Hive sharelib / platform-owned."),
            _r("livy-server", "livy-server product CVE needs 0.9 backport."),
            _r("pac4j", "pac4j major upgrade required."),
        ],
    },
    "livy3": {"alias_of": "livy2"},
    "livy3_3_5_1": {"alias_of": "livy2"},
    "livy3_3_3_3": {"alias_of": "livy2"},
    "livy4": {
        "repo": "sehajsandhu/livy4",
        "git_url": "https://github.com/acceldata-io/livy.git",
        "target_branch": "nightly/ODP-4.1.1.3.3.6.5",
        "source": "livy4_cve_route_deliver.py",
        "fix_targets": [
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["commons-configuration2.version"]}),
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": ["jackson.version"]}),
            _fix("okio", r"okio", "3.4.0",
                 {"type": "managed", "group": "com.squareup.okio", "artifact": "okio-jvm"}),
        ],
        "exception_rules": _common("jetty-9.4", "hadoop-platform", "logback-1.3-to-1.5") + [
            _r("jetty-runner", "jetty-runner fat jar; not Livy-owned."),
            _r("livy-server", "livy-server product CVE."),
            _r("pac4j", "pac4j major upgrade required."),
        ],
    },
    "hbase-connectors": {
        "source": "cve_profiles + fix_hbase_netty.py",
        "fix_targets": [
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons-lang3.version"]}),
            _fix("hbase-shaded-netty", r"netty", "4.1.13",
                 {"type": "dependency", "group": "org.apache.hbase.thirdparty",
                  "artifact": "hbase-shaded-netty"},
                 notes="Maps to Netty 4.1.131 inside shaded artifact"),
        ],
        "exception_rules": _common(
            "protobuf-wire", "zookeeper-platform", "hadoop-platform",
            "commons-lang-2.6", "htrace-jackson",
        ) + [
            _r("woodstox", "woodstox major / platform-owned."),
            _r("commons-net", "commons-net major API jump."),
            _r("httpcomponents", "httpclient via Hadoop/platform."),
            _r("opentelemetry", "otel not safely bumpable in connectors alone."),
            _r("hbase-shaded-netty",
               "Remaining Netty CVEs need 4.1.132+ not yet in shaded line.",
               path_contains="hbase-shaded-netty"),
        ],
    },
    "pinot": {
        "source": "cve_profiles._PINOT_* + pinot_netty_cve_deliver + fix_pinot_htrace_jackson",
        "fix_targets": [
            _fix("netty", r"^io\.netty", "4.1.135.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1",
                 notes="Also rebuilds pinot *-shaded.jar plugins"),
            _fix("log4j2", r"log4j", "2.25.4",
                 {"type": "property", "names": ["log4j.version"]}),
            _fix("helix", r"helix", "1.3.0",
                 {"type": "property", "names": ["helix.version"]}),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons-lang3.version"]}),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["commons-configuration2.version"]}),
            _fix("nimbus-jose-jwt", r"nimbus-jose-jwt", "10.0.2",
                 {"type": "property", "names": ["nimbus-jose-jwt.version"]}),
            _fix("aircompressor", r"aircompressor", "2.0.3",
                 {"type": "property", "names": ["aircompressor.version"]}),
            _fix("async-http-client", r"async-http-client", "3.0.10",
                 {"type": "property", "names": ["async-http-client.version"]}),
        ],
        "exception_rules": _common(
            "protobuf-wire", "jetty-9.4", "hadoop-platform", "zookeeper-platform",
        ) + [
            _r("okio", "okio 1.6.0 transitive; not centrally managed for safe bump."),
        ],
        "special_fixes": [
            "htrace-embedded jackson 2.4.0 stripped via shade filters "
            "(fix_pinot_htrace_jackson.py) — not a version bump",
        ],
    },
    "flink": {
        "source": "cve_profiles + flink_cve_route_deliver.py",
        "fix_targets": [
            _fix("log4j2", r"log4j", "2.25.4",
                 {"type": "property", "names": ["log4j.version"]},
                 aligned_key="log4j2"),
        ],
        "exception_rules": _common("hadoop-platform", "jetty-9.4") + [
            _r("commons-configuration2",
               "commons-configuration2 via Hadoop; platform-owned."),
            _r("flink-table",
               "flink-table product CVE needs 1.20+/2.x major."),
        ],
    },
    "clickhouse": {
        "repo": "sehajsandhu/clickhouse",
        "git_url": "https://github.com/acceldata-io/ch-ui.git",
        "target_branch": "nightly/ODP-3.3.6.5",
        "source": "batch9_cve_route_deliver.py / fix_clickhouse_cves.py",
        "fix_targets": [
            _fix("tomcat", r"tomcat", "9.0.119",
                 {"type": "property", "names": ["tomcat.version"]},
                 notes="Latest 9.0.x; jakarta 10.1/11 is exception"),
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": ["jackson-bom.version"]}),
            _fix("logback", r"logback", "1.5.37",
                 {"type": "property", "names": ["logback.version"]},
                 notes="Pair with slf4j 2.0.18"),
            _fix("spring-framework", r"org\.springframework", "5.3.39",
                 {"type": "property", "names": ["spring-framework.version"]},
                 notes="Latest OSS 5.3.x"),
            _fix("snakeyaml", r"snakeyaml", "2.0",
                 {"type": "property", "names": ["snakeyaml.version"]}),
        ],
        "exception_rules": [
            _r("spring-boot",
               "spring-boot fix needs Boot 3.x / JDK 17; ch-ui stays on Boot 2.7."),
            _r("org.springframework",
               "Spring Framework CVEs whose only fix is 5.3.40+ (commercial) / 6.x / 7.x."),
            _r("tomcat",
               "Tomcat CVEs with no 9.0.x fix (only 10.1/11 jakarta) incompatible with Boot 2.7."),
        ],
    },
    "druid": {
        "repo": "sehajsandhu/druid",
        "source": "batch12_druid_cve_deliver.py / fix_druid_*.py",
        "fix_targets": [
            _fix("log4j2", r"log4j", "2.25.4",
                 {"type": "property", "names": ["log4j.version"]}),
            _fix("netty", r"^io\.netty", "4.1.135.Final",
                 {"type": "property", "names": ["netty4.version"]},
                 affected_prefix="4.1"),
            _fix("postgresql", r"postgresql", "42.7.11",
                 {"type": "property", "names": ["postgresql.version"]}),
            _fix("json-path", r"json-path", "2.9.0",
                 {"type": "property", "names": ["json-path.version"]}),
            _fix("jetty", r"org\.eclipse\.jetty", "9.4.57.v20241219",
                 {"type": "property", "names": ["jetty.version"]},
                 affected_prefix="9.4"),
            _fix("bouncycastle", r"bouncycastle|bcprov|bcpkix", "1.84",
                 {"type": "property", "names": ["bouncycastle.version"]}),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons-lang3.version"]}),
            _fix("commons-compress", r"commons-compress", "1.26.0",
                 {"type": "property", "names": ["commons-compress.version"]}),
            _fix("async-http-client", r"async-http-client", "3.0.10",
                 {"type": "property", "names": ["async-http-client.version"]}),
            _fix("plexus-utils", r"plexus-utils", "3.6.1",
                 {"type": "property", "names": ["plexus.version"]}),
            _fix("rhino", r"rhino", "1.7.15.1",
                 {"type": "property", "names": ["rhino.version"]}),
            _fix("azure-sdk-bom", r"azure", "1.2.25",
                 {"type": "property", "names": ["azure.sdk.bom.version"]}),
            _fix("aircompressor", r"aircompressor", "2.0.3",
                 {"type": "property", "names": ["aircompressor.version"]}),
            _fix("jackson-databind", r"jackson-databind", "2.12.7.1",
                 {"type": "property", "names": ["jackson.databind.version"]},
                 notes="Stay on 2.12.x line where required"),
            _fix("jose4j", r"jose4j", "0.9.6",
                 {"type": "property", "names": ["jose4j.version"]}),
            _fix("woodstox", r"woodstox", "6.5.1",
                 {"type": "property", "names": ["woodstox.version"]}),
        ],
        "exception_rules": _common(
            "hadoop-platform", "velocity-commons-io", "jetty-12-only",
            "commons-lang-2.6",
        ) + [
            _r("hadoop-client", "Shaded in hadoop-client-runtime/api."),
            _r("druid-basic-security", "Druid product code; needs backport."),
            _r("druid-pac4j", "Druid product / pac4j major."),
            _r("elasticsearch", "Elasticsearch major upgrade required."),
            _r("ranger", "ranger-plugins are platform-owned."),
            _r("reactor-netty", "reactor-netty vs azure SDK constraint."),
            _r("jackson-core", "jackson-core off managed 2.12 line; version-aware."),
            _r("snakeyaml", "snakeyaml 2.0 API break on this Druid line."),
            _r("nimbus-jose-jwt", "nimbus 10.x needs JDK11 / already ≥9.x for some."),
            _r("io.netty_netty", "Netty 3.x EOL.", affected_prefix="3."),
        ],
    },
    "tez": {
        "source": "fix_tez_cves.py / tez_cve_route_deliver.py",
        "fix_targets": [
            _fix("netty", r"^io\.netty", "4.1.133.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1"),
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": ["jackson.tez.version"]}),
            _fix("commons-io", r"commons-io", "2.14.0",
                 {"type": "property", "names": ["commons-io.version"]}),
            _fix("async-http-client", r"async-http-client", "2.15.0",
                 {"type": "property", "names": ["async-http-client.version"]}),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["commons-configuration2.version"]}),
            _fix("okio", r"okio", "3.4.0",
                 {"type": "property", "names": ["okio.version"]},
                 notes="3.3.6.4 used 3.4.0; earlier line used 1.17.6"),
            _fix("jdom2", r"jdom2", "2.0.6.1",
                 {"type": "property", "names": ["jdom2.version"]}),
        ],
        "exception_rules": _common(
            "htrace-jackson", "aws-sdk-bundle-netty", "protobuf-wire", "jetty-9.4",
            "commons-lang-2.6", "hadoop-platform", "zookeeper-platform",
            "logback-1.3-to-1.5",
        ) + [
            _r("bcpkix", "bcpkix-jdk15on → jdk18on is a coordinate change."),
            _r("dnsjava", "dnsjava platform-owned / Hadoop line."),
        ],
    },
    "impala": {
        "source": "fix_impala_cves.py / batch8",
        "fix_targets": [
            _fix("netty", r"^io\.netty", "4.1.133.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1"),
            _fix("log4j2", r"log4j", "2.25.4",
                 {"type": "property", "names": ["IMPALA_LOG4J2_VERSION"]}),
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": ["jackson.version"]}),
            _fix("postgresql", r"postgresql", "42.7.11",
                 {"type": "property", "names": ["postgresql.version"]}),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["commons-configuration2.version"]}),
            _fix("okio", r"okio", "1.17.6",
                 {"type": "property", "names": ["okio.version"]}),
            _fix("commons-io", r"commons-io", "2.14.0",
                 {"type": "property", "names": ["commons-io.version"]}),
            _fix("opentelemetry", r"opentelemetry", "1.62.0",
                 {"type": "property", "names": ["opentelemetry.version"]}),
        ],
        "exception_rules": _common(
            "libthrift", "jetty-9.4", "commons-lang-2.6", "htrace-jackson",
            "aws-sdk-bundle-netty",
        ) + [
            _r("kudu-client", "Shaded in kudu-client."),
            _r("ozone-filesystem", "Shaded ozone-filesystem."),
            _r("impala-minimal-s3a", "Shaded AWS SDK bundle."),
            _r("cos_api-bundle", "Shaded COS API bundle."),
            _r("iceberg-hive-runtime", "Shaded iceberg-hive-runtime."),
            _r("sqlparse", "sqlparse on Py2 Impala shell; env constraint."),
            _r("org.ini4j", "ini4j abandoned / fix=open."),
            _r("org.springframework", "Spring 6 / commercial-only fixes."),
            _r("ranger", "ranger plugins platform-owned."),
            _r("pac4j", "pac4j major."),
            _r("elasticsearch", "elasticsearch major."),
        ],
    },
    "zeppelin": {
        "repo": "sehajsandhu/zeppelin",
        "git_url": "https://github.com/acceldata-io/zeppelin.git",
        "target_branch": "nightly/ODP-3.3.6.5",
        "source": "batch10_zeppelin_cve_deliver.py",
        "fix_targets": [
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": ["jackson.version"]}),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons.lang3.version"]}),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["commons.configuration2.version"]}),
            _fix("mina", r"mina-core", "2.0.28",
                 {"type": "property", "names": ["mina.version"]}),
            _fix("bouncycastle", r"bcprov|bcpkix|bouncycastle", "1.84",
                 {"type": "property", "names": ["bouncycastle.version"]}),
            _fix("commons-vfs2", r"commons-vfs2", "2.10.0",
                 {"type": "property", "names": ["commons.vfs2.version"]}),
            _fix("netty", r"^io\.netty", "4.1.133.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1"),
            _fix("nimbus-jose-jwt", r"nimbus-jose-jwt", "10.0.2",
                 {"type": "property", "names": ["nimbus.jose.jwt.version"]}),
            _fix("okhttp", r"okhttp", "4.9.2",
                 {"type": "property", "names": ["okhttp.version"]}),
            _fix("okio", r"okio", "3.4.0",
                 {"type": "property", "names": ["okio.version"]}),
            _fix("opentelemetry", r"opentelemetry", "1.62.0",
                 {"type": "property", "names": ["opentelemetry.version"]}),
            _fix("jinjava", r"jinjava", "2.8.3",
                 {"type": "property", "names": ["jinjava.version"]}),
            _fix("jsoup", r"jsoup", "1.15.3",
                 {"type": "property", "names": ["jsoup.version"]}),
            _fix("commons-net", r"commons-net", "3.9.0",
                 {"type": "property", "names": ["commons.net.version"]}),
            _fix("plexus-utils", r"plexus-utils", "3.6.1",
                 {"type": "property", "names": ["plexus.version"]}),
            _fix("jetty", r"org\.eclipse\.jetty", "11.0.28",
                 {"type": "property", "names": ["jetty.version"]},
                 affected_prefix="11.0",
                 notes="Only when advisory lists 11.0.27+; else jetty-12-only exception"),
        ],
        "exception_rules": _common(
            "hadoop-platform", "libthrift", "commons-lang-2.6", "jetty-12-only",
        ) + [
            _r("guava", "Shaded inside docker-client-*-shaded.jar.",
               path_contains="docker-client"),
            _r("httpclient", "Shaded inside docker-client-*-shaded.jar.",
               path_contains="docker-client"),
            _r("ini4j", "No viable upstream fix on current line."),
            _r("javax.el", "No viable upstream fix on current line."),
            _r("io.netty", "Netty 3.x has no upstream fix on 3.x.",
               affected_prefix="3."),
            _r("shiro", "shiro fix is on 2.0.x (major from 1.13)."),
            _r("c3p0", "c3p0 0.12.x is a major from 0.9.5.x."),
            _r("jgit", "JGit fix requires 7.x (major)."),
            _r("commons-configuration",
               "commons-configuration 1.x; no clean pin on this branch."),
            _r("jersey", "jersey Dropwizard-managed; advisory spans 2.46/3.x."),
            _r("mchange-commons", "Comes with c3p0; no isolated pin."),
            _r("jackrabbit", "jackrabbit-jcr-commons not root-managed."),
        ],
    },
    "jupyterhub": {
        "repo": "sehajsandhu/jupyterhub",
        "git_url": "https://github.com/acceldata-io/jupyterhub.git",
        "target_branch": "nightly/ODP-3.3.6.5",
        "build_tool": "python",
        "requirements_file": "odp/requirements.txt",
        "source": "batch11_jupyterhub_cve_deliver.py",
        "fix_targets": [
            _pin("idna", "idna", "3.15", "odp/requirements.txt"),
            _pin("mistune", "mistune", "3.2.1", "odp/requirements.txt"),
            _pin("h11", "h11", "0.16.0", "odp/requirements.txt"),
            _pin("httpcore", "httpcore", "1.0.9", "odp/requirements.txt"),
            _pin("Mako", "Mako", "1.3.12", "odp/requirements.txt"),
            _pin("nbconvert", "nbconvert", "7.17.1", "odp/requirements.txt"),
            _pin("ray", "ray", "2.55.0", "odp/requirements.txt"),
            _pin("pyasn1", "pyasn1", "0.6.3", "odp/requirements.txt"),
            _pin("cryptography", "cryptography", "44.0.1", "odp/requirements.txt"),
            _pin("jupyterlab", "jupyterlab", "4.5.7", "odp/requirements.txt"),
            _pin("Pygments", "Pygments", "2.20.0", "odp/requirements.txt"),
            _pin("urllib3", "urllib3", "2.7.0", "odp/requirements.txt"),
            _pin("oauthenticator", "oauthenticator", "17.4.0", "odp/requirements.txt"),
            _pin("notebook", "notebook", "7.5.6", "odp/requirements.txt"),
            _pin("jupyterhub", "jupyterhub", "5.4.5", "odp/requirements.txt"),
            _pin("requests", "requests", "2.33.0", "odp/requirements.txt"),
            _pin("aiohttp", "aiohttp", "3.13.4", "odp/requirements.txt"),
            _pin("pillow", "pillow", "12.2.0", "odp/requirements.txt"),
            _pin("tornado", "tornado", "6.5.5", "odp/requirements.txt"),
            _pin("PyJWT", "PyJWT", "2.12.0", "odp/requirements.txt"),
        ],
        "exception_rules": [
            _r("protobuf", "protobuf fix lists 33.x; not viable from current pin."),
            _r("fonttools", "fonttools is an ODP fork; not a PyPI bump."),
            _r("pyarrow", "pyarrow 18→23 is a major ABI jump."),
            _r("cryptography",
               "When advisory only lists 46.x+, stay on 44.x (env/ABI risk)."),
        ],
    },
    "hue": {
        "repo": "sehajsandhu/hue",
        "git_url": "https://github.com/acceldata-io/hue.git",
        "target_branch": "nightly/ODP-3.3.6.5",
        "build_tool": "python",
        "requirements_file": "desktop/core/generate_requirements.py",
        "source": "batch13_hue_cve_deliver.py",
        "fix_targets": [
            _pin("pyasn1", "pyasn1", "0.6.3", "desktop/core/generate_requirements.py"),
            _pin("Markdown", "Markdown", "3.8.1", "desktop/core/generate_requirements.py"),
            _pin("python-ldap", "python-ldap", "3.4.5",
                 "desktop/core/generate_requirements.py"),
            _pin("urllib3", "urllib3", "2.7.0", "desktop/core/generate_requirements.py"),
            _pin("requests", "requests", "2.33.0", "desktop/core/generate_requirements.py"),
            _pin("djangorestframework-simplejwt", "djangorestframework-simplejwt",
                 "5.5.1", "desktop/core/generate_requirements.py"),
            _pin("PyJWT", "PyJWT", "2.12.0", "desktop/core/generate_requirements.py"),
            _pin("djangorestframework", "djangorestframework", "3.15.2",
                 "desktop/core/generate_requirements.py"),
            _pin("cryptography", "cryptography", "44.0.1",
                 "desktop/core/generate_requirements.py"),
            _pin("cbor2", "cbor2", "5.9.0", "desktop/core/generate_requirements.py"),
            _pin("sqlparse", "sqlparse", "0.5.4", "desktop/core/generate_requirements.py"),
            _pin("Mako", "Mako", "1.3.12", "desktop/core/generate_requirements.py"),
        ],
        "exception_rules": [
            _r("notebook", "False positive / Hue internal app, not Jupyter notebook."),
            _r("protobuf", "protobuf 33.x not viable same-line bump."),
            _r("pyarrow", "pyarrow 17→23 major ABI jump."),
            _r("SQLAlchemy", "SQLAlchemy 1.3→1.4 major for Hue."),
            _r("lxml", "lxml 4→6 major."),
            _r("Twisted", "Only RC available; do not ship RC into ODP."),
            _r("pip", "pip packaging tool; not an app dependency bump."),
            _r("virtualenv", "virtualenv tool exception."),
            _r("cryptography", "When only 46.x+ listed — ABI/env risk."),
        ],
    },
    "superset": {
        "repo": "sehajsandhu/superset",
        "git_url": "https://github.com/acceldata-io/superset.git",
        "target_branch": "rel/ODP-3.3.6.4-1",
        "build_tool": "python",
        "requirements_file": "requirements/base.txt",
        "source": "batch14_superset_cve_deliver.py",
        "fix_targets": [
            _pin("pyasn1", "pyasn1", "0.6.3", "requirements/base.txt"),
            _pin("idna", "idna", "3.15", "requirements/base.txt"),
            _pin("urllib3", "urllib3", "2.7.0", "requirements/base.txt"),
            _pin("pyjwt", "PyJWT", "2.12.0", "requirements/base.txt"),
            _pin("flask-cors", "flask-cors", "6.0.0", "requirements/base.txt"),
            _pin("brotli", "brotli", "1.2.0", "requirements/base.txt"),
            _pin("mako", "Mako", "1.3.12", "requirements/base.txt"),
            _pin("markdown", "Markdown", "3.8.1", "requirements/base.txt"),
            _pin("marshmallow", "marshmallow", "3.26.2", "requirements/base.txt"),
            _pin("pygments", "Pygments", "2.20.0", "requirements/base.txt"),
            _pin("requests", "requests", "2.33.0", "requirements/base.txt"),
            _pin("python-dotenv", "python-dotenv", "1.2.2", "requirements/base.txt"),
            _pin("pynacl", "PyNaCl", "1.6.2", "requirements/base.txt"),
            _pin("werkzeug", "Werkzeug", "3.1.6", "requirements/base.txt"),
            _pin("pyarrow", "pyarrow", "17.0.0", "requirements/base.txt"),
        ],
        "exception_rules": [
            _r("flask",
               "Flask ≥3 breaks pyproject.toml flask>=2.2.5,<3.0.0 for this ODP line."),
            _r("pillow",
               "Pillow 12.x breaks pyproject constraint Pillow>=11.0.0,<12."),
            _r("cryptography",
               "cryptography 46.x+; Superset ODP stays on 44.x (resolver/ABI risk)."),
            _r("paramiko", "No published fixed version (fix=open)."),
            _r("pyarrow",
               "When advisory only lists 23.x — major ABI jump from 16/17.x."),
        ],
    },
    "odp-ambari": {
        "repo": "sehajsandhu/ambari",
        "git_url": "https://github.com/acceldata-io/odp-ambari.git",
        "target_branch": "rel/ODP-AMBARI-3.0.0.2-1",
        "scan_release": "3.0.0.1",
        "java_home_note": "JDK 17",
        "source": "ambari_netty_cve_deliver.py / ambari_remaining_cve_deliver.py",
        "fix_targets": [
            _fix("netty", r"^io\.netty", "4.1.135.Final",
                 {"type": "property", "names": ["netty4.version"]},
                 affected_prefix="4.1",
                 notes="ambari-project netty-bom; standalone jars in Files view"),
            _fix("mina", r"mina-core", "2.0.28",
                 {"type": "property", "names": ["mina.core.version"]}),
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.18.6",
                 {"type": "property", "names": [
                     "fasterxml.jackson.version",
                     "fasterxml.jackson.databind.version"]}),
            _fix("postgresql", r"postgresql", "42.7.13",
                 {"type": "property", "names": ["postgres.version"]}),
            _fix("spring-ldap", r"spring-ldap-core", "2.4.4",
                 {"type": "dependency", "group": "org.springframework.ldap",
                  "artifact": "spring-ldap-core"}),
            _fix("nimbus-jose-jwt", r"nimbus-jose-jwt", "9.37.4",
                 {"type": "property", "names": ["nimbus.jose.jwt.version"]},
                 notes="property lives in ambari-server/pom.xml"),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons-lang3.version"]},
                 notes="ambari-server direct 3.9 + ambari-agent property"),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["commons-configuration2.version"]},
                 notes="ambari-agent (+ files view)"),
            _fix("commons-io", r"commons-io", "2.15.1",
                 {"type": "dependency", "group": "commons-io", "artifact": "commons-io"},
                 notes="contrib/views/files explicit 2.4 pin"),
            _fix("spring-framework", r"org\.springframework(?!\.security|\.ldap)",
                 "6.2.19",
                 {"type": "property", "names": ["spring.version"]}),
            _fix("spring-security", r"springframework\.security|spring-security",
                 "6.0.8",
                 {"type": "property", "names": ["spring.security.version"]},
                 notes="Latest 6.0.x; advisories needing 6.1+ → exception"),
            _fix("logback", r"logback", "1.3.16",
                 {"type": "property", "names": ["logback.version"]}),
        ],
        "exception_rules": _common(
            "jackson-mapper-asl", "commons-lang-2.6", "hadoop-platform",
            "zookeeper-platform", "okio-aws-transitive", "velocity-commons-io",
            "aws-sdk-bundle-netty", "spring-security-needs-6.1plus",
        ) + [
            _r("ambari-infra-solr",
               "Vulnerable jar bundled in ambari-infra-solr vendor Solr distribution; "
               "not built from odp-ambari.",
               path_contains="ambari-infra-solr"),
            _r("solr",
               "Solr/infra-solr vendor libs; remediation belongs to ambari-infra.",
               path_contains="ambari-infra-solr"),
            _r("fast-hdfs-resource",
               "Prebuilt fast-hdfs-resource.jar under stack-hooks; not Maven-managed.",
               path_contains="fast-hdfs-resource"),
            _r("org.eclipse.jetty",
               "Jetty 11.0.26 is latest published 11.0.x; fixes need 11.0.27+/12.x "
               "(Jetty 12 = major migration).",
               affected_prefix="11.0"),
            _r("commons-net",
               "commons-net 1.4.1 → 3.9.0 is a major API break across Ambari server."),
            _r("htrace",
               "Jackson inside inactive htrace-core; Exception (Deferred).",
               path_contains="htrace"),
        ],
    },
    # Keep ambari skeleton key pointing at odp-ambari catalog
    "ambari": {"alias_of": "odp-ambari"},
    "ranger": {
        "source": "ranger_cve_route_deliver.py",
        "fix_targets": [
            _fix("tomcat-embed", r"tomcat", "9.0.120",
                 {"type": "property", "names": ["tomcat.embed.version"]}),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons.lang3.version"]}),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["commons.configuration.version"]}),
            _fix("nimbus-jose-jwt", r"nimbus-jose-jwt", "10.0.2",
                 {"type": "property", "names": ["nimbus-jose-jwt.version"]}),
            _fix("logback", r"logback", "1.3.16",
                 {"type": "property", "names": ["logback.version"]}),
            _fix("poi", r"poi", "5.4.0",
                 {"type": "property", "names": ["poi.version"]}),
            _fix("opentelemetry", r"opentelemetry", "1.62.0",
                 {"type": "property", "names": ["opentelemetry.version"]}),
        ],
        "exception_rules": _common(
            "hadoop-platform", "jetty-12-only", "logback-1.3-to-1.5",
        ) + [
            _r("ozone", "ozone/jersey/hbase/grpc shaded paths."),
            _r("ranger-plugins", "Product CVEs needing ranger 2.8+."),
            _r("elasticsearch", "elasticsearch 8/9 major."),
            _r("aircompressor", "aircompressor 0.27→2.0 major."),
            _r("bouncycastle", "bc jdk15on→jdk18on coordinate change."),
            _r("commons-configuration",
               "commons-configuration 1.10 open / no fix."),
            _r("okio", "okio unmanaged transitive."),
            _r("underscore", "underscore.js frontend exception."),
            _r("org.springframework", "Spring 5.3/5.7 line constraints."),
        ],
    },
    "kudu": {
        "source": "kudu_cve_route_deliver.py",
        "fix_targets": [
            _fix("netty", r"^io\.netty", "4.1.135.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1"),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons-lang3.version"]}),
            _fix("commons-compress", r"commons-compress", "1.26.0",
                 {"type": "property", "names": ["commons-compress.version"]}),
        ],
        "exception_rules": _common(
            "hadoop-platform", "jetty-9.4", "jetty-12-only", "logback-1.3-to-1.5",
        ) + [
            _r("commons-codec", "commons-codec in shaded test-utils."),
        ],
    },
    "airflow": {
        "build_tool": "python",
        "requirements_file": "odp/constraints-3.11.txt",
        "source": "airflow_cve_route_deliver.py",
        "fix_targets": [
            _pin("eventlet", "eventlet", "0.40.3", "odp/constraints-3.11.txt"),
            _pin("h11", "h11", "0.16.0", "odp/constraints-3.11.txt"),
            _pin("cryptography", "cryptography", "43.0.1", "odp/constraints-3.11.txt"),
            _pin("urllib3", "urllib3", "2.7.0", "odp/constraints-3.11.txt"),
            _pin("Mako", "Mako", "1.3.12", "odp/constraints-3.11.txt"),
            _pin("sqlparse", "sqlparse", "0.5.4", "odp/constraints-3.11.txt"),
            _pin("requests", "requests", "2.33.0", "odp/constraints-3.11.txt"),
            _pin("idna", "idna", "3.15", "odp/constraints-3.11.txt"),
            _pin("pyasn1", "pyasn1", "0.6.3", "odp/constraints-3.11.txt"),
            _pin("Pygments", "Pygments", "2.20.0", "odp/constraints-3.11.txt"),
            _pin("PyJWT", "PyJWT", "2.12.0", "odp/constraints-3.11.txt"),
        ],
        "exception_rules": [
            _r("apache-airflow", "Airflow core product CVE; not a lib pin."),
            _r("apache-airflow-providers-http", "providers-http 4→6 major."),
            _r("apache-airflow-providers-common-sql", "providers-common-sql jump."),
            _r("Flask-AppBuilder", "FAB pin constraint."),
            _r("flask", "flask 2→3 major."),
            _r("werkzeug", "werkzeug 3.1 vs Flask 2.2 constraint."),
            _r("thrift", "thrift 0.16→0.23 major."),
            _r("protobuf", "protobuf 5/6/33 line constraints."),
        ],
    },
    "celeborn": {
        "source": "celeborn_cve_route_deliver.py",
        "fix_targets": [
            _fix("netty", r"^io\.netty", "4.1.135.Final",
                 {"type": "property", "names": ["netty.version"]},
                 affected_prefix="4.1"),
            _fix("commons-lang3", r"commons-lang3", "3.18.0",
                 {"type": "property", "names": ["commons-lang3.version"]}),
            _fix("jetty", r"org\.eclipse\.jetty", "9.4.57.v20241219",
                 {"type": "property", "names": ["jetty.version"]},
                 affected_prefix="9.4"),
        ],
        "exception_rules": _common(
            "jetty-12-only", "hadoop-platform",
        ) + [
            _r("commons-configuration2", "Via Hadoop; platform-owned."),
        ],
    },
    "spark4": {
        "repo": "sehajsandhu/spark4",
        "git_url": "https://github.com/acceldata-io/spark3.git",
        "target_branch": "nightly/ODP-4.1.1.3.3.6.5",
        "source": "spark4_cve_route_deliver.py",
        "fix_targets": [
            _fix("jetty", r"org\.eclipse\.jetty", "11.0.28",
                 {"type": "property", "names": ["jetty.version"]},
                 affected_prefix="11.0"),
            _fix("lz4-java", r"lz4-java", "1.8.1",
                 {"type": "property", "names": ["lz4-java.version"]}),
            _fix("vertx", r"vertx", "4.5.24",
                 {"type": "property", "names": ["vertx.version"]}),
        ],
        "exception_rules": _common(
            "aws-sdk-bundle-netty", "hadoop-platform", "jetty-12-only",
        ) + [
            _r("iceberg", "iceberg runtime shaded."),
            _r("gcs", "gcs-connector shaded."),
            _r("hive-exec", "hive-exec 2.3 fork."),
            _r("hudi", "hudi bundle shaded."),
            _r("okhttp", "okhttp 3→4 major."),
        ],
    },
    "trino": {
        "source": "batch7 + docs §6–7",
        "fix_targets": [
            _fix("jetty", r"org\.eclipse\.jetty", "12.0.34",
                 {"type": "property", "names": ["dep.jetty.version"]}),
            _fix("jackson", r"^com\.fasterxml\.jackson", "2.21.1",
                 {"type": "property", "names": ["dep.jackson.version"]}),
            _fix("logback", r"logback", "1.5.25",
                 {"type": "property", "names": ["dep.logback.version"]}),
            _fix("opentelemetry", r"opentelemetry", "1.62.0",
                 {"type": "property", "names": ["dep.opentelemetry.version"]}),
            _fix("commons-configuration2", r"commons-configuration2", "2.15.0",
                 {"type": "property", "names": ["dep.commons-configuration2.version"]}),
            _fix("lz4-java", r"lz4", "1.10.1",
                 {"type": "property", "names": ["dep.lz4-java.version"]}),
            _fix("grpc-netty-shaded", r"grpc", "1.75.0",
                 {"type": "property", "names": ["dep.grpc.version"]}),
            _fix("bouncycastle", r"bcprov", "1.84",
                 {"type": "property", "names": ["dep.bouncycastle.version"]}),
            _fix("reactor-netty", r"reactor-netty", "1.2.8",
                 {"type": "property", "names": ["dep.reactor-netty.version"]}),
            _fix("snowflake-jdbc", r"snowflake", "3.23.1",
                 {"type": "property", "names": ["dep.snowflake.version"]}),
            _fix("netty", r"^io\.netty", "4.1.135.Final",
                 {"type": "property", "names": ["dep.netty.version"]},
                 affected_prefix="4.1"),
            _fix("aircompressor", r"aircompressor", "2.0.3",
                 {"type": "property", "names": ["dep.aircompressor.version"]}),
        ],
        "exception_rules": _common(
            "libthrift", "commons-lang-2.6",
        ) + [
            _r("stdlib", "Go stdlib / base-image finding (crypto/tls, x509, net/http); "
               "refresh container base image, not an app dependency bump."),
            _r("kafka-clients", "kafka-clients connector constraint."),
            _r("ranger", "ranger-plugins platform-owned."),
            _r("trino-iceberg", "Needs Trino 480+ major."),
            _r("guava", "guava inside clickhouse-jdbc-all shaded.",
               path_contains="clickhouse-jdbc"),
            _r("wire-runtime", "wire-runtime fix=open."),
        ],
    },
    "oozie": {
        "source": "oozie_cve_route_deliver.py",
        "fix_targets": [],
        "exception_rules": [
            _r("pig", "lib/pig/* third-party sharelib.", path_contains="lib/pig"),
            _r("sqoop", "sharelib sqoop platform-owned.", path_contains="lib/sqoop"),
            _r("spark", "sharelib spark3 platform-owned.", path_contains="lib/spark"),
            _r("hive", "sharelib hive/hive2 platform-owned.", path_contains="lib/hive"),
        ],
        "close_notes": "Selected sharelib jars already fixed via sqoop/hive PRs.",
    },
}


def resolve_entry(name: str) -> Dict[str, Any]:
    """Resolve aliases and return a concrete catalog entry."""
    seen = set()
    while name in COMPONENT_CATALOG:
        if name in seen:
            raise ValueError(f"alias cycle involving {name}")
        seen.add(name)
        entry = COMPONENT_CATALOG[name]
        if "alias_of" in entry:
            name = entry["alias_of"]
            continue
        return entry
    raise KeyError(f"Unknown catalog component: {name}")


def get_fix_targets(component: str) -> List[Dict[str, Any]]:
    return deepcopy(resolve_entry(component).get("fix_targets") or [])


def get_exception_rules(component: str) -> List[Dict[str, Any]]:
    return deepcopy(resolve_entry(component).get("exception_rules") or [])


def apply_catalog_to_profiles(
    profiles: Dict[str, Dict[str, Any]],
    *,
    overwrite: bool = False,
    only_empty: bool = True,
) -> List[str]:
    """Fill profile fix_targets / exception_rules from the catalog.

    By default only fills when the profile list is empty (preserves hand-tuned
    spark2/spark3/livy/pinot rules already in cve_profiles.py).

    Returns list of profile keys that were updated.
    """
    updated = []
    for key, prof in profiles.items():
        catalog_key = key
        if catalog_key not in COMPONENT_CATALOG and key.replace("-", "_") in COMPONENT_CATALOG:
            catalog_key = key.replace("-", "_")
        if catalog_key not in COMPONENT_CATALOG:
            # try without version suffix: spark3-3.5.5 -> spark3
            base = key.split("-")[0] if "-" in key else key
            if base in COMPONENT_CATALOG:
                catalog_key = base
            else:
                continue
        try:
            entry = resolve_entry(catalog_key)
        except KeyError:
            continue

        changed = False
        ft = entry.get("fix_targets")
        er = entry.get("exception_rules")
        if ft is not None:
            if overwrite or (only_empty and not prof.get("fix_targets")):
                prof["fix_targets"] = deepcopy(ft)
                changed = True
        if er is not None:
            if overwrite or (only_empty and not prof.get("exception_rules")):
                prof["exception_rules"] = deepcopy(er)
                changed = True
        # carry aligned target versions into aligned_versions when empty
        if ft and (overwrite or not prof.get("aligned_versions")):
            aligned = dict(prof.get("aligned_versions") or {})
            for t in ft:
                ak = t.get("aligned_key") or t.get("name")
                tv = t.get("target_version")
                if ak and tv and ak not in aligned:
                    aligned[ak] = tv
            if aligned:
                prof["aligned_versions"] = aligned
                changed = True
        if changed:
            updated.append(key)
    # Always merge release overrides from cve_catalog_sync.py --apply
    apply_release_overrides(profiles)
    return updated


def _overrides_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "cve_catalog_overrides.json")


def load_catalog_overrides(path: Optional[str] = None) -> Dict[str, Any]:
    p = path or _overrides_path()
    if not os.path.isfile(p):
        return {}
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def apply_release_overrides(
    profiles: Dict[str, Dict[str, Any]],
    path: Optional[str] = None,
) -> List[str]:
    """Bump profile fix_targets.target_version from cve_catalog_overrides.json.

    Produced by: python3 cve_catalog_sync.py <release> --apply
    Only updates existing fix_target names; does not invent new patch stanzas.
    """
    data = load_catalog_overrides(path)
    comps = data.get("components") or {}
    if not comps:
        return []
    touched = []
    for key, prof in profiles.items():
        # resolve catalog key for this profile
        ckey = key
        if ckey not in comps:
            try:
                # ambari profile -> odp-ambari overrides
                if key == "ambari" and "odp-ambari" in comps:
                    ckey = "odp-ambari"
                elif key.startswith("spark3") and "spark3" in comps:
                    ckey = "spark3"
                else:
                    continue
            except Exception:
                continue
        versions = (comps.get(ckey) or {}).get("fix_target_versions") or {}
        if not versions:
            continue
        fts = prof.get("fix_targets") or []
        changed = False
        for t in fts:
            name = t.get("name")
            if name in versions:
                new_v = versions[name]
                if t.get("target_version") != new_v:
                    t["target_version"] = new_v
                    t["override_source"] = data.get("active_release", "overrides")
                    changed = True
                # keep aligned_versions in sync
                ak = t.get("aligned_key") or name
                aligned = prof.setdefault("aligned_versions", {})
                if isinstance(aligned, dict):
                    aligned[ak] = new_v
        if changed:
            touched.append(key)
    return touched


def summarize(component: Optional[str] = None) -> None:
    """Print a compact matrix for one or all components."""
    names = [component] if component else sorted(
        k for k, v in COMPONENT_CATALOG.items() if "alias_of" not in v
    )
    for name in names:
        e = resolve_entry(name)
        ft = e.get("fix_targets") or []
        er = e.get("exception_rules") or []
        print(f"\n=== {name} ===")
        print(f"  source: {e.get('source', '—')}")
        print(f"  fix_targets ({len(ft)}):")
        for t in ft:
            print(f"    - {t['name']} → {t.get('target_version')}")
        print(f"  exception_rules ({len(er)}):")
        for r in er:
            print(f"    - {r['match']}: {(r.get('description') or '')[:90]}")


def fix_targets_table() -> str:
    """Markdown table of all component → library → target_version."""
    lines = [
        "| Component | Library | Target version |",
        "|---|---|---|",
    ]
    for name in sorted(k for k, v in COMPONENT_CATALOG.items() if "alias_of" not in v):
        for t in resolve_entry(name).get("fix_targets") or []:
            lines.append(
                f"| {name} | {t['name']} | {t.get('target_version', '')} |"
            )
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "table":
        print(fix_targets_table())
    elif len(sys.argv) > 1:
        summarize(sys.argv[1])
    else:
        summarize()
        print("\n--- components ---")
        print(", ".join(sorted(
            k for k, v in COMPONENT_CATALOG.items() if "alias_of" not in v
        )))
