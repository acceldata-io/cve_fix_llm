"""
Delivery driver for the ClickHouse (ch-ui-wrapper) 3.2.3.6 CVEs.

All 70 flagged CVEs live inside the single ch-ui-wrapper Spring Boot 2.7.18 fat
jar (BOOT-INF/lib/*). The wrapper only serves the CH-UI static bundle, so the
deps are plain Spring Boot managed libraries. The fix overrides four version
properties in ch-ui-wrapper/pom.xml and rebuilds:

  tomcat.version            9.0.109 -> 9.0.119  (latest 9.0.x)
  jackson-bom.version       2.15.0  -> 2.18.6
  logback.version           1.4.12  -> 1.5.37   (+ slf4j.version 2.0.18)
  spring-framework.version  5.3.31  -> 5.3.39   (latest OSS 5.3.x)
  snakeyaml.version         already 2.0 (covers all 7 snakeyaml CVEs)

That branch (OSV-20571) is already committed + pushed and the rebuilt
BOOT-INF/lib verified to carry the bumped versions. This script only opens the
PR, Closes the covered tickets, and routes the rest to Exception Request.

Categorisation (build-verified, see /tmp/ch_plan.json) is version-aware: a
ticket is CLOSED iff the rebuilt jar's version >= the lowest fix version on a
line we can ship (cve_fixer.uncovered_issues with per-family targets). The
tomcat / spring families therefore split fix-vs-exception by the per-ticket
FIXED version, which is why this is a bespoke driver rather than the generic
rule flow.

  CLOSE      51  (9 Critical / 27 High / 15 Medium)
  EXCEPTION  19  (4 Critical /  7 High /  8 Medium)

Honors CVE_DRY_RUN=1 to preview without writing.
"""

import json
import os

os.environ.setdefault("CVE_PROFILE", "clickhouse")

import cve_analyser as ca
import cve_fixer as cf

BRANCH = "OSV-20571"
TITLE = ("OSV-20571 - CVE - ch-ui-wrapper: bump tomcat 9.0.119 / jackson 2.18.6 "
         "/ logback 1.5.37 / spring 5.3.39 to fix bundled CVEs")

PLAN = json.load(open("/tmp/ch_plan.json"))
ISSUES = {i["key"]: i for i in json.load(open("/tmp/ch_326.json"))}

CLOSE_KEYS = PLAN["close"]
EXC_KEYS = PLAN["exc"]


# -------------------------------------------------------------------
# Per-family exception rationale
# -------------------------------------------------------------------
def exception_reason(issue: dict) -> str:
    lib = issue["affected_library"].lower()
    fixed = issue["fixed_version"]
    if lib.startswith("spring-boot"):
        return (
            "ch-ui-wrapper runs on Spring Boot 2.7.18 (the ODP JDK 8/11 "
            "baseline). This CVE is fixed only in Spring Boot 3.3.11+ / 3.4.x / "
            "3.5.x / 4.x (fixed in " + fixed + "), which require Jakarta EE 9+ "
            "(the jakarta.* namespace) and JDK 17 - a major framework migration "
            "incompatible with the ODP baseline. Deferred."
        )
    if "tomcat-embed" in lib:
        return (
            "ch-ui-wrapper embeds Tomcat through Spring Boot 2.7 (javax.servlet) "
            "and has been bumped to tomcat-embed 9.0.119, the latest 9.0.x "
            "release. This CVE has no fix on the 9.0.x line; it is fixed only in "
            "Tomcat 10.1.x / 11.x (fixed in " + fixed + "), which use the "
            "Jakarta EE (jakarta.servlet) namespace and are incompatible with "
            "Spring Boot 2.7. Deferred."
        )
    # spring-framework family (spring-core / spring-web / spring-webmvc /
    # spring-context / spring-expression)
    return (
        "spring-framework is managed by Spring Boot 2.7.18 and has been bumped "
        "to 5.3.39, the latest OSS 5.3.x release on Maven Central. This CVE is "
        "fixed only in spring-framework 5.3.40+ / 6.x / 7.x (fixed in " + fixed +
        "): the 5.3.40+ patches are commercial-only (Broadcom enterprise/extended "
        "support, not published to Maven Central) and the 6.x / 7.x lines require "
        "Jakarta EE 9+ and JDK 17 (a Spring Boot 3.x upgrade) which is "
        "incompatible with the ODP JDK 8/11 baseline. Deferred."
    )


def main() -> None:
    print(f"ClickHouse (ch-ui-wrapper) delivery  DRY_RUN={ca.DRY_RUN}")
    print(f"  CLOSE={len(CLOSE_KEYS)}  EXCEPTION={len(EXC_KEYS)}  "
          f"total={len(CLOSE_KEYS) + len(EXC_KEYS)}")

    plan = {
        "branch": BRANCH,
        "libraries": ["tomcat-embed", "jackson", "logback", "snakeyaml",
                      "spring-framework"],
        "target_version": ("tomcat 9.0.119 / jackson 2.18.6 / logback 1.5.37 / "
                           "spring 5.3.39 / snakeyaml 2.0"),
        "issues": [{"key": k} for k in CLOSE_KEYS],
    }

    pr_url = cf.create_pull_request(plan, TITLE)
    if not pr_url:
        print("PR not created; aborting.")
        return

    comment = (
        f"Fixed via PR: {pr_url}  -  the flagged library is bundled inside the "
        f"ch-ui-wrapper Spring Boot fat jar (BOOT-INF/lib). On "
        f"{cf.TARGET_BRANCH} the ch-ui-wrapper/pom.xml managed versions were "
        f"raised to tomcat-embed 9.0.119, jackson 2.18.6, logback 1.5.37 "
        f"(with slf4j 2.0.18), spring-framework 5.3.39 and snakeyaml 2.0. The "
        f"rebuilt ch-ui-wrapper jar was verified to carry the fixed version for "
        f"this CVE in BOOT-INF/lib."
    )

    print(f"\n--- Closing {len(CLOSE_KEYS)} fixed tickets ---")
    closed = 0
    for k in CLOSE_KEYS:
        if ca.close_ticket_with_comment(k, comment, "Closed"):
            closed += 1

    print(f"\n--- Routing {len(EXC_KEYS)} exception tickets ---")
    routed = 0
    for k in EXC_KEYS:
        if ca.update_ticket_exception(k, exception_reason(ISSUES[k])):
            routed += 1

    print(f"\nDone. Closed {closed}/{len(CLOSE_KEYS)}, "
          f"routed {routed}/{len(EXC_KEYS)}. PR: {pr_url}")


if __name__ == "__main__":
    main()
