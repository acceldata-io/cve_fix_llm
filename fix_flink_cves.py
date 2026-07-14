"""
Delivery driver for Flink's 3.2.3.6 CVEs.

The only flagged Flink CVEs are 6 log4j2 tickets (5 log4j-core + 1 log4j-1.2-api,
all 2.25.3) fixed in 2.25.4. log4j-* are managed in the root pom via the single
<log4j.version> property and copied into flink/lib by flink-dist's bin.xml
assembly, so a one-line property bump (2.25.3 -> 2.25.4) clears all 6. All four
log4j 2.25.4 artifacts are on Maven Central and no submodule overrides the
property, so the rebuilt flink/lib carries 2.25.4.

The branch (OSV-18068) is already committed + pushed. This script only opens the
PR and Closes the 6 linked tickets. Honors CVE_DRY_RUN=1.
"""

import json
import os

os.environ.setdefault("CVE_PROFILE", "flink")

import cve_analyser as ca
import cve_fixer as cf

BRANCH = "OSV-18068"
TITLE = ("OSV-18068 - CVE - Increasing log4j2 version to 2.25.4 to fix the "
         "flink/lib log4j CVEs")

ISSUES = json.load(open("/tmp/flink_326.json"))
KEYS = [i["key"] for i in ISSUES]


def main() -> None:
    print(f"Flink delivery for {len(KEYS)} log4j tickets  DRY_RUN={ca.DRY_RUN}")

    plan = {
        "branch": BRANCH,
        "libraries": ["log4j-core", "log4j-1.2-api"],
        "target_version": "2.25.4",
        "issues": [{"key": k} for k in KEYS],
    }

    pr_url = cf.create_pull_request(plan, TITLE)
    if not pr_url:
        print("PR not created; aborting ticket closure.")
        return

    comment = (
        f"Fixed via PR: {pr_url}  -  the log4j2 jars are copied into flink/lib by "
        f"flink-dist from the root pom's managed <log4j.version> property. That "
        f"property was bumped from 2.25.3 to 2.25.4 on {cf.TARGET_BRANCH}, so the "
        f"rebuilt flink/lib ships log4j-core / log4j-1.2-api 2.25.4 which fixes "
        f"this CVE."
    )

    closed = 0
    for k in KEYS:
        if ca.close_ticket_with_comment(k, comment, "Closed"):
            closed += 1
    print(f"\nClosed {closed}/{len(KEYS)} tickets. PR: {pr_url}")


if __name__ == "__main__":
    main()
