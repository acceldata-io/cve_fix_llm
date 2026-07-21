#!/usr/bin/env python3
"""Route Oozie (sehajsandhu/oozie, release 3.3.6.4) To Do CVEs:

1) lib/pig/*          -> Exception Request (3rd-party Pig sharelib)
2) Already-fixed sharelib jars (sqoop/hive/spark PRs) -> Closed with PR ref
3) Other lib/sqoop|spark3|hive|hive2 sharelib -> Exception (owned by that component)
4) WEB-INF/lib + lib/git left as To Do (Oozie-owned; separate bump pass)

  CVE_DRY_RUN=1 to preview
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ASSIGNEE = "senthil.kumar"
DRY = os.environ.get("CVE_DRY_RUN", "") not in ("", "0", "false", "False")
RESULT = Path("/tmp/oozie_cve_route_result.json")

# jar basename (or prefix) -> (bucket_required, pr_url, why)
# Only close when CVE-Path is under the given sharelib bucket.
CLOSE_RULES = [
    {
        "jar_re": r"^commons-lang3-3\.5\.jar$",
        "bucket": "lib/sqoop",
        "pr": "https://github.com/acceldata-io/sqoop/pull/47",
        "why": "Sqoop commons-lang3 bumped to 3.18.0 (OSV-23399).",
    },
    {
        "jar_re": r"^aircompressor-2\.0\.2\.jar$",
        "bucket": "lib/sqoop",
        "pr": "https://github.com/acceldata-io/sqoop/pull/35",
        "why": "Sqoop aircompressor upgraded; nightly/ODP-3.3.6.5 already at 2.0.3.",
    },
    {
        "jar_re": r"^snakeyaml-1\.24\.jar$",
        "bucket": "lib/sqoop",
        "pr": "https://github.com/acceldata-io/sqoop/pull/37",
        "why": "Sqoop snakeyaml bumped (OSV-13375 / sqoop#37).",
    },
    {
        "jar_re": r"^grpc-netty-shaded-1\.72\.0\.jar$",
        "bucket": "lib/sqoop",
        "pr": "https://github.com/acceldata-io/hive/pull/186",
        "why": "Hive grpc-netty-shaded bumped to 1.75.0 (OSV-21258); Oozie Sqoop sharelib pulls Hive.",
    },
    {
        "jar_re": r"^commons-configuration2-2\.10\.1\.jar$",
        "bucket": "lib/sqoop",
        "pr": "https://github.com/acceldata-io/hive/pull/188",
        "why": "Hive commons-configuration2 bumped to 2.15.0 (OSV-21185); Oozie Sqoop sharelib pulls Hive.",
    },
]

PIG_EXCEPTION = (
    "This CVE is in Apache Pig sharelib jars bundled under Oozie lib/pig "
    "(third-party component). Pig is not owned/fixed inside the Oozie build; "
    "remediation requires upgrading or rebuilding the Pig sharelib separately. "
    "Exception Request (Deferred)."
)

SHARELIB_EXCEPTION = {
    "lib/sqoop": (
        "This CVE is in jars shipped via Oozie's Sqoop sharelib (lib/sqoop), not "
        "an Oozie-owned dependency. Fix must be applied in Sqoop (or its "
        "transitive stack: Hive/HBase/Hadoop) and then the Oozie sharelib "
        "refreshed. Exception Request (Deferred)."
    ),
    "lib/spark3": (
        "This CVE is in jars shipped via Oozie's Spark3 sharelib (lib/spark3), "
        "not an Oozie-owned dependency. Fix must be applied in Spark3 / its Hive "
        "2.3 fork and then the Oozie sharelib refreshed. Exception Request "
        "(Deferred)."
    ),
    "lib/hive": (
        "This CVE is in jars shipped via Oozie's Hive sharelib (lib/hive), not "
        "an Oozie-owned dependency. Fix must be applied in Hive and then the "
        "Oozie sharelib refreshed. Exception Request (Deferred)."
    ),
    "lib/hive2": (
        "This CVE is in jars shipped via Oozie's Hive2 sharelib (lib/hive2), not "
        "an Oozie-owned dependency. Fix must be applied in Hive and then the "
        "Oozie sharelib refreshed. Exception Request (Deferred)."
    ),
}


def field_text(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        out = []

        def walk(n):
            if isinstance(n, dict):
                if n.get("type") == "text":
                    out.append(n.get("text") or "")
                for c in n.get("content") or []:
                    walk(c)
            elif isinstance(n, list):
                for c in n:
                    walk(c)

        walk(v)
        return " ".join(out) if out else ""
    return str(v)


def bucket_of(path: str) -> str:
    m = re.search(r"/(lib/[^/]+|WEB-INF/lib)/", (path or "").replace("\\", "/"))
    return m.group(1) if m else "other"


def load_tickets(ca):
    jql = (
        'project = OSV AND status = "To Do" AND summary ~ "sehajsandhu/oozie" '
        "ORDER BY key ASC"
    )
    issues = []
    token = None
    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            "fields": "summary,customfield_10888,customfield_10893,status",
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
        path = field_text(f.get("customfield_10888"))
        found = field_text(f.get("customfield_10893"))
        # Prefer 3.3.6.4 scan set; keep tickets with empty found if path is set
        if found and "3.3.6.4" not in found:
            continue
        jar = path.split("/")[-1] if path else ""
        rows.append(
            {
                "key": i["key"],
                "summary": f["summary"],
                "path": path,
                "jar": jar,
                "bucket": bucket_of(path),
                "found": found,
            }
        )
    return rows


def match_close(row):
    for rule in CLOSE_RULES:
        if row["bucket"] != rule["bucket"]:
            continue
        if re.search(rule["jar_re"], row["jar"]):
            return rule
    return None


def main():
    sys.path.insert(0, "/root/cve_fix_llm")
    os.chdir("/root/cve_fix_llm")
    import cve_env

    cve_env.load_repo_env()
    import cve_analyser as ca

    ca.DRY_RUN = DRY
    rows = load_tickets(ca)
    print(f"Loaded {len(rows)} To Do tickets (3.3.6.4 filter)", flush=True)

    plan = defaultdict(list)
    for row in rows:
        b = row["bucket"]
        if b == "lib/pig":
            plan["exception_pig"].append(row)
            continue
        rule = match_close(row)
        if rule:
            row = dict(row)
            row["pr"] = rule["pr"]
            row["why"] = rule["why"]
            plan["close"].append(row)
            continue
        if b in SHARELIB_EXCEPTION:
            plan["exception_sharelib"].append(row)
            continue
        plan["leave_oozie_owned"].append(row)

    print("\n===== PLAN =====", flush=True)
    for k, v in plan.items():
        print(f"  {k}: {len(v)}", flush=True)
        for r in v[:8]:
            print(f"    {r['key']} [{r['bucket']}] {r['jar']}", flush=True)
        if len(v) > 8:
            print(f"    ... +{len(v)-8} more", flush=True)

    result = {
        "dry": DRY,
        "counts": {k: len(v) for k, v in plan.items()},
        "closed": [],
        "exceptioned": [],
        "left": [],
        "failed": [],
    }

    # 1) Pig exceptions
    for row in plan["exception_pig"]:
        key = row["key"]
        print(f"EXCEPTION_PIG {key}", flush=True)
        if DRY:
            result["exceptioned"].append(key)
            continue
        ok = ca.update_ticket_exception(
            key, PIG_EXCEPTION, reason="Deferred", assignee=ASSIGNEE
        )
        try:
            ca.add_comment(key, f"Exception Request (Deferred): {PIG_EXCEPTION}")
        except Exception as e:
            print(f"  comment warn: {e}")
        ca.assign_issue(key, ca.resolve_assignee(ASSIGNEE))
        (result["exceptioned"] if ok else result["failed"]).append(key)
        print(f"  ok={ok}", flush=True)

    # 2) Close already-addressed sharelib
    for row in plan["close"]:
        key = row["key"]
        comment = (
            f"Closed: transitive via Oozie {row['bucket']} sharelib. "
            f"Already addressed in the owning component — {row['why']} "
            f"PR: {row['pr']}. Oozie sharelib will pick this up when rebuilt "
            f"against the updated component."
        )
        print(f"CLOSE {key} -> {row['pr']}", flush=True)
        if DRY:
            result["closed"].append({"key": key, "pr": row["pr"]})
            continue
        ok = ca.close_ticket_with_comment(key, comment, "Closed", assignee=ASSIGNEE)
        if ok:
            result["closed"].append({"key": key, "pr": row["pr"]})
        else:
            result["failed"].append(key)
        print(f"  ok={ok}", flush=True)

    # 3) Exception remaining sharelibs
    for row in plan["exception_sharelib"]:
        key = row["key"]
        details = SHARELIB_EXCEPTION[row["bucket"]]
        print(f"EXCEPTION_SHARELIB {key} [{row['bucket']}]", flush=True)
        if DRY:
            result["exceptioned"].append(key)
            continue
        ok = ca.update_ticket_exception(
            key, details, reason="Deferred", assignee=ASSIGNEE
        )
        try:
            ca.add_comment(key, f"Exception Request (Deferred): {details}")
        except Exception as e:
            print(f"  comment warn: {e}")
        ca.assign_issue(key, ca.resolve_assignee(ASSIGNEE))
        (result["exceptioned"] if ok else result["failed"]).append(key)
        print(f"  ok={ok}", flush=True)

    # 4) Leave Oozie-owned
    for row in plan["leave_oozie_owned"]:
        result["left"].append(
            {"key": row["key"], "bucket": row["bucket"], "jar": row["jar"]}
        )
        print(f"LEAVE {row['key']} [{row['bucket']}] {row['jar']}", flush=True)

    RESULT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("\n===== SUMMARY =====", flush=True)
    print(json.dumps(result["counts"], indent=2), flush=True)
    print(f"closed={len(result['closed'])} exceptioned={len(result['exceptioned'])} "
          f"left={len(result['left'])} failed={len(result['failed'])}", flush=True)
    print(f"Wrote {RESULT}", flush=True)


if __name__ == "__main__":
    main()
