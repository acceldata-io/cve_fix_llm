"""
Delivery driver for Druid's 3.2.3.6 CVEs (PHASE 1).

Druid (org.apache.druid, ODP fork 29.0.1.3.2.3.6-2, JDK 8) has 72 flagged CVEs.
Categorisation (path/version-aware, see /tmp/druid_plan.json):

  FIX        17  root-pom property/managed bumps, build-verified in the
                 distribution's lib/extensions:
                   log4j      2.25.3 -> 2.25.4   (log4j-core / log4j-1.2-api)
                   netty4     4.1.132 -> 4.1.135.Final (netty-codec*/-dns/-http*)
                   postgresql 42.7.2 -> 42.7.11
                   json-path  2.3.0  -> 2.9.0
  EXCEPTION  41  shaded inside hadoop-client-runtime / parquet-jackson / htrace /
                 velocity fat jars; ODP platform forks (hadoop / zookeeper /
                 ranger); druid-basic-security (Druid own code -> backport);
                 netty3 EOL (fix=open); jetty 9.4 (jakarta-only fix);
                 elasticsearch / pac4j major; async-http-client (3.x needs
                 JDK 11); nimbus (10.x needs JDK 11, 9.x fix already met);
                 commons-lang (fix=open).
  DEFER      14  PHASE 2 (jackson, snakeyaml, aircompressor, woodstox,
                 azure-identity, jose4j, reactor-netty, plexus-utils) - left in
                 To Do, handled separately after compatibility testing.

The branch (OSV-19xxx, the first FIX ticket) is committed + pushed and the
rebuilt distribution verified before this runs. This script opens the PR, Closes
the 17 FIX tickets, and routes the 41 EXCEPTION tickets. Honors CVE_DRY_RUN=1.
"""

import json
import os

os.environ.setdefault("CVE_PROFILE", "druid")

import cve_analyser as ca
import cve_fixer as cf

PLAN = json.load(open("/tmp/druid_plan.json"))
FIX_KEYS = PLAN["fix"]
EXC_KEYS = PLAN["exception"]
REASONS = PLAN["reasons"]

# Branch named after the first (highest) FIX ticket, created DESC.
BRANCH = sorted(FIX_KEYS, reverse=True)[0]
TITLE = (f"{BRANCH} - CVE - Druid: bump log4j 2.25.4 / netty 4.1.135 / "
         f"postgresql 42.7.11 / json-path 2.9.0 to fix bundled CVEs")


def main() -> None:
    print(f"Druid PHASE 1 delivery  DRY_RUN={ca.DRY_RUN}")
    print(f"  branch={BRANCH}  FIX={len(FIX_KEYS)}  EXCEPTION={len(EXC_KEYS)}  "
          f"DEFER={len(PLAN['defer'])}")

    plan = {
        "branch": BRANCH,
        "libraries": ["log4j-core/1.2-api", "netty-codec*", "postgresql",
                      "json-path"],
        "target_version": ("log4j 2.25.4 / netty 4.1.135.Final / postgresql "
                           "42.7.11 / json-path 2.9.0"),
        "issues": [{"key": k} for k in FIX_KEYS],
    }

    pr_url = cf.create_pull_request(plan, TITLE)
    if not pr_url:
        print("PR not created; aborting.")
        return

    comment = (
        f"Fixed via PR: {pr_url}  -  the flagged jar is bundled in the Druid "
        f"distribution (druid/lib or an extension) from a root-pom managed "
        f"version. On {cf.TARGET_BRANCH} the root pom was bumped to log4j 2.25.4, "
        f"netty4 4.1.135.Final, postgresql 42.7.11 and json-path 2.9.0; the "
        f"rebuilt Druid distribution was verified to carry the fixed version for "
        f"this CVE."
    )

    print(f"\n--- Closing {len(FIX_KEYS)} FIX tickets ---")
    closed = 0
    for k in FIX_KEYS:
        if ca.close_ticket_with_comment(k, comment, "Closed"):
            closed += 1

    print(f"\n--- Routing {len(EXC_KEYS)} EXCEPTION tickets ---")
    routed = 0
    for k in EXC_KEYS:
        if ca.update_ticket_exception(k, REASONS[k]):
            routed += 1

    print(f"\nDone. Closed {closed}/{len(FIX_KEYS)}, routed {routed}/"
          f"{len(EXC_KEYS)}. {len(PLAN['defer'])} deferred to Phase 2. PR: {pr_url}")


if __name__ == "__main__":
    main()
