"""
One-off delivery driver for the Pinot htrace-embedded Jackson 2.4.0 fix.

The 59 deferred jackson 2.4.0 CVEs (53 jackson-databind + 6 jackson-core) in
pinot-orc-*-shaded.jar are NOT fixable by a version bump: the vulnerable
Jackson 2.4.0 is vendored inside the htrace-core4-4.1.0-incubating fat jar
(relocated to org.apache.htrace.shaded.fasterxml.jackson) and ships the
matching META-INF/maven/com.fasterxml.jackson.core/* pom.properties. The fix
adds a maven-shade <filters> on org.apache.htrace:htrace-core4 (in
pinot-orc/pom.xml and pinot-parquet/pom.xml) to strip those embedded Jackson
classes + metadata while keeping htrace core tracing intact.

The branch (OSV-18776) is already committed + pushed and the rebuilt shaded
jars verified (no jackson 2.4.0 classes/pom.properties; htrace core present).
This script only opens the PR and Closes the 59 linked tickets.

Honors CVE_DRY_RUN=1 to preview without writing.
"""

import json
import os

os.environ.setdefault("CVE_PROFILE", "pinot")

import cve_analyser as ca
import cve_fixer as cf

BRANCH = "OSV-18776"
TITLE = ("OSV-18776 - CVE - Strip Jackson 2.4.0 embedded in htrace-core4 "
         "from pinot-orc/pinot-parquet shaded jars")

KEYS = json.load(open("/tmp/orc_jackson_keys.json"))


def main() -> None:
    print(f"Delivery for {len(KEYS)} pinot-orc Jackson 2.4.0 tickets "
          f"(DRY_RUN={ca.DRY_RUN}).")

    plan = {
        "branch": BRANCH,
        "libraries": ["jackson-databind", "jackson-core"],
        "target_version": "removed from shaded jar (htrace-embedded 2.4.0 stripped)",
        "issues": [{"key": k} for k in KEYS],
    }

    pr_url = cf.create_pull_request(plan, TITLE)
    if not pr_url:
        print("PR not created; aborting ticket closure.")
        return

    comment = (
        f"Fixed via PR: {pr_url}  -  Jackson 2.4.0 (jackson-databind / "
        f"jackson-core) is not a normal dependency here: it is vendored inside "
        f"the htrace-core4-4.1.0-incubating fat jar (relocated to "
        f"org.apache.htrace.shaded.fasterxml.jackson), which also carries the "
        f"jackson 2.4.0 META-INF/maven pom.properties that scanners read. Added "
        f"a maven-shade <filters> on org.apache.htrace:htrace-core4 in "
        f"pinot-orc/pom.xml to strip the embedded Jackson classes and metadata "
        f"on {cf.TARGET_BRANCH}. The rebuilt pinot-orc shaded jar was verified "
        f"to contain no Jackson 2.4.0 classes or pom.properties, while htrace "
        f"core tracing classes remain intact."
    )

    closed = 0
    for k in KEYS:
        if ca.close_ticket_with_comment(k, comment, "Closed"):
            closed += 1
    print(f"\nClosed {closed}/{len(KEYS)} tickets. PR: {pr_url}")


if __name__ == "__main__":
    main()
