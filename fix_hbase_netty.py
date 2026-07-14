"""
Dedicated driver: bump HBase's third-party shaded netty
(org.apache.hbase.thirdparty:hbase-shaded-netty) in the hbase-connectors root
pom to the latest available release, to address the netty CVEs that live INSIDE
hbase-shaded-netty-*.jar.

Why a dedicated driver instead of a normal cve_fixer fix target:
  - hbase-shaded-netty is a THIRD-PARTY SHADED fat jar, so cve_analyser marks the
    netty CVEs as is_thirdparty_shaded and cve_fixer's generic fix-target flow
    deliberately EXCLUDES them (a normal version bump can't touch a shaded jar).
  - Here we CAN move the jar by pinning the shaded artifact via a
    dependencyManagement override, but the fix-target version lives in the
    hbase-thirdparty namespace (4.1.13) while the CVE fixed-versions are in the
    netty namespace (4.1.131 / 4.1.132 / 4.1.133), so cve_fixer's generic
    coverage math does not apply.

hbase-shaded-netty 4.1.13 (latest on Maven Central) ships netty 4.1.131.Final,
which COVERS the older (2025) netty CVEs but NOT the newer (2026) ones that need
netty 4.1.132 / 4.1.133 (no hbase-thirdparty shaded release bundles those yet).

This driver therefore:
  1. pins hbase-shaded-netty -> SHADED_VERSION (dependencyManagement override),
  2. builds + pushes a branch + opens a PR (reusing cve_fixer helpers),
  3. closes ONLY the covered (netty <= PROVIDES_NETTY) tickets with the PR link.
The remaining (uncovered) netty tickets are left "To Do" so the standard
cve_fixer.py shaded-bundle Exception pass defers them with the proper rationale.

Run AFTER selecting the hbase-connectors profile and BEFORE the main
cve_fixer.py routing pass:

    CVE_PROFILE=hbase-connectors CVE_DRY_RUN=1 python3 fix_hbase_netty.py   # preview
    CVE_PROFILE=hbase-connectors CVE_APPLY=1   python3 fix_hbase_netty.py   # execute

APPLY defaults False (plan only). DRY_RUN (Jira writes) is controlled by
cve_analyser (CVE_DRY_RUN).
"""

import cve_analyser as ca
import cve_fixer as cf

# The HBase third-party shaded artifact that bundles netty, and the latest
# available release + the netty version it effectively provides.
SHADED_GROUP = "org.apache.hbase.thirdparty"
SHADED_ARTIFACT = "hbase-shaded-netty"
SHADED_VERSION = "4.1.13"          # latest on Maven Central
PROVIDES_NETTY = "4.1.131.Final"   # netty bundled inside hbase-shaded-netty 4.1.13


def netty_shaded_issues(lib_map):
    """All netty tickets whose vulnerable class is inside hbase-shaded-netty."""
    out = []
    for lib, entries in lib_map.items():
        if not lib.lower().startswith("io.netty_netty-"):
            continue
        for iss in entries:
            jar = ca.jar_filename(iss.get("cve_path") or "").lower()
            if SHADED_ARTIFACT in jar:
                out.append(iss)
    return out


def split_covered(issues):
    """
    Partition netty tickets into (covered, uncovered) by comparing the netty
    version provided by SHADED_VERSION against each CVE's 4.1.x fixed version.
    A ticket is covered when PROVIDES_NETTY >= its lowest 4.1.x fixed version.
    """
    provides = cf.parse_version(PROVIDES_NETTY)
    covered, uncovered = [], []
    for iss in issues:
        fixes = cf.split_fix_versions(iss["fixed_version"])
        line = [v for v in fixes if v.startswith("4.1.")]  # stay on the 4.1.x line
        need = min((cf.parse_version(v) for v in line), default=None)
        if need is not None and provides >= need:
            covered.append(iss)
        else:
            uncovered.append(iss)
    return covered, uncovered


def main():
    print("=" * 80)
    print(f"  HBASE-SHADED-NETTY OVERRIDE  |  profile: {cf.PROFILE_NAME}")
    print(f"  pin {SHADED_GROUP}:{SHADED_ARTIFACT} -> {SHADED_VERSION} "
          f"(netty {PROVIDES_NETTY})")
    print(f"  branch base: {cf.TARGET_BRANCH}  |  APPLY={cf.APPLY}  "
          f"|  DRY_RUN={ca.DRY_RUN}")
    print("=" * 80)

    issues = ca.fetch_all_tickets()
    if not issues:
        print("No issues found or fetch failed.")
        return

    lib_map = ca.group_by_library(issues)
    netty = netty_shaded_issues(lib_map)
    if not netty:
        print("No hbase-shaded-netty tickets To Do (already handled?). Nothing to do.")
        return

    covered, uncovered = split_covered(netty)
    print(f"\n  netty tickets in {SHADED_ARTIFACT}: {len(netty)}")
    print(f"  COVERED by netty {PROVIDES_NETTY} ({len(covered)}): "
          f"{', '.join(i['key'] for i in covered)}")
    print(f"  NOT covered (need netty 4.1.132/4.1.133) ({len(uncovered)}): "
          f"{', '.join(i['key'] for i in uncovered)}")
    print("  -> uncovered tickets are left To Do for cve_fixer's shaded "
          "Exception pass.")

    if not covered:
        print("\n  No covered tickets; nothing to fix via the version bump.")
        return

    branch_ticket = covered[0]["key"]   # issues are created DESC from the fetch
    commit_cve = next((i["cve_id"] for i in covered if i["cve_id"] != "UNKNOWN"),
                      covered[0]["cve_id"])
    commit_subject = (f"{branch_ticket} - CVE - Increasing {SHADED_ARTIFACT} to "
                      f"{SHADED_VERSION} (netty {PROVIDES_NETTY}) to fix {commit_cve}")

    plan = {
        "name": SHADED_ARTIFACT,
        "patch": {"type": "managed", "group": SHADED_GROUP, "artifact": SHADED_ARTIFACT},
        "target_version": SHADED_VERSION,
        "libraries": [f"{SHADED_GROUP}_{SHADED_ARTIFACT}"],
        "issues": covered,            # only covered tickets get closed on the PR
        "branch": branch_ticket,
        "commit_cve": commit_cve,
        "commit_subject": commit_subject,
    }

    print(f"\n  Fix branch     : {plan['branch']}  (off {cf.TARGET_BRANCH})")
    print(f"  Patch          : {plan['patch']} -> {SHADED_VERSION}")
    print(f"  Commit message : {commit_subject}")
    print(f"  Closes on PR   : {', '.join(i['key'] for i in covered)}")

    if not cf.APPLY:
        print("\n  APPLY is False -> plan only. No git/build/push performed.")
        return

    if not cf.ensure_repo():
        print("  ERROR: could not clone/fetch the repo; aborting.")
        return

    skip = cf.already_fixed_reason(plan)
    if skip:
        print(f"  SKIP: {skip}. Nothing to do.")
        return

    if not cf.create_fix_branch(plan["branch"]):
        print("  ERROR: git preparation failed; aborting.")
        return

    changes = cf.apply_pom_patch(plan["patch"], plan["target_version"])
    if not changes:
        print("  WARNING: no pom changes made (already pinned / anchor not found?).")
    else:
        for c in changes:
            print(f"    - {c}")

    if not cf.run_build():
        print("  Build failed. Branch left in place for manual inspection.")
        return

    print(f"  Committing on branch {plan['branch']}.")
    if cf.run(f'git commit -am "{commit_subject}"', cwd=cf.WORKDIR) != 0:
        print("  ERROR: commit failed (nothing to commit?); not pushing.")
        return
    if cf.run(f"git push -u origin {plan['branch']}", cwd=cf.WORKDIR) != 0:
        print("  ERROR: push failed. Commit is local; push manually.")
        return
    print("  SUCCESS. Branch pushed.")
    cf.record_fix(plan)

    if cf.SKIP_PR:
        print("  CVE_SKIP_PR set -> not opening PR / closing tickets.")
        return
    print(f"  Opening PR {plan['branch']} -> {cf.TARGET_BRANCH} on {cf.REPO_SLUG}.")
    pr_url = cf.create_pull_request(plan, commit_subject)
    if not pr_url:
        print("  PR not created; covered tickets left open for manual handling.")
        return
    cf.close_tickets_for_plan(plan, pr_url)


if __name__ == "__main__":
    main()
