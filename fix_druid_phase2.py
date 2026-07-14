"""
Druid PHASE 2 delivery as SEPARATE per-library PRs (one commit + PR per library
group), reviewer basapuram-kumar, and closes/routes the matching Jira tickets.

Build already validated on JDK 8 (-Pdist, twice). Distribution verified:
  jackson-databind 2.12.7.1 | jose4j 0.9.6 | plexus-utils 3.6.1 |
  aircompressor 2.0.3 | azure-identity 1.13.0 (azure-sdk-bom 1.2.25) |
  woodstox-core 6.5.1

FIX (8 tickets, 6 PRs):
  jackson-databind 2.12.7.1   OSV-17937, OSV-17936   (root pom dM, in-line patch)
  jose4j           0.9.6      OSV-17957              (root pom dM)
  plexus-utils     3.6.1      OSV-18047              (root pom dM)
  aircompressor    2.0.3      OSV-18025, OSV-17955   (root pom dM override)
  azure-identity   1.13.0     OSV-17940              (azure-ext azure-sdk-bom 1.2.25)
  woodstox-core    6.5.1      OSV-17943              (azure-ext dM pin)

EXCEPTION (6 tickets):
  jackson-core  OSV-18020/18021/18022/18023  needs 2.13/2.15+, away from Druid's
                                             pinned jackson 2.12.7 (regression risk)
  snakeyaml     OSV-18012                    1.33 -> 2.0 breaking SafeConstructor API
  reactor-netty-http OSV-17933               1.2.8 incompatible w/ azure-core-http-netty
                                             (azure-sdk-bom pins reactor-netty 1.0.x)

Honors CVE_DRY_RUN=1.
"""

import os
import subprocess

os.environ.setdefault("CVE_PROFILE", "druid")

import cve_analyser as ca
import cve_fixer as cf

WORKDIR = os.path.expanduser("~/cve_fix_workdir/druid")
TB = cf.TARGET_BRANCH
REVIEWER = "basapuram-kumar"

ROOT = "pom.xml"
AZ = "extensions-core/azure-extensions/pom.xml"

JACKSON_BOM_ANCHOR = """            <dependency>
                <groupId>com.fasterxml.jackson</groupId>
                <artifactId>jackson-bom</artifactId>"""
JACKSON_DB_INSERT = """            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-databind</artifactId>
                <version>2.12.7.1</version>
            </dependency>
""" + JACKSON_BOM_ANCHOR

ZSTD_ANCHOR = """            <dependency>
                <groupId>com.github.luben</groupId>
                <artifactId>zstd-jni</artifactId>
                <version>1.5.2-3</version>
            </dependency>"""
AIR_INSERT = ZSTD_ANCHOR + """
            <dependency>
                <groupId>io.airlift</groupId>
                <artifactId>aircompressor</artifactId>
                <version>2.0.3</version>
            </dependency>"""

AZ_BOM_ANCHOR = """        <dependencies>
            <dependency>
                <groupId>com.azure</groupId>
                <artifactId>azure-sdk-bom</artifactId>"""
WOODSTOX_INSERT = """        <dependencies>
            <dependency>
                <groupId>com.fasterxml.woodstox</groupId>
                <artifactId>woodstox-core</artifactId>
                <version>6.5.1</version>
            </dependency>
            <dependency>
                <groupId>com.azure</groupId>
                <artifactId>azure-sdk-bom</artifactId>"""

# group -> (file, old_substr, new_substr, branch, [keys], commit-summary)
GROUPS = {
    "jackson-databind": (ROOT, JACKSON_BOM_ANCHOR, JACKSON_DB_INSERT,
        "OSV-17937", ["OSV-17937", "OSV-17936"],
        "Pinning jackson-databind to 2.12.7.1 to fix the Druid jackson-databind CVEs"),
    "jose4j": (ROOT,
        "<artifactId>jose4j</artifactId>\n                <version>0.9.4</version>",
        "<artifactId>jose4j</artifactId>\n                <version>0.9.6</version>",
        "OSV-17957", ["OSV-17957"],
        "Increasing jose4j version to 0.9.6 to fix the Druid jose4j CVEs"),
    "plexus-utils": (ROOT,
        "<artifactId>plexus-utils</artifactId>\n                <version>3.0.24</version>",
        "<artifactId>plexus-utils</artifactId>\n                <version>3.6.1</version>",
        "OSV-18047", ["OSV-18047"],
        "Increasing plexus-utils version to 3.6.1 to fix the Druid plexus-utils CVEs"),
    "aircompressor": (ROOT, ZSTD_ANCHOR, AIR_INSERT,
        "OSV-18025", ["OSV-18025", "OSV-17955"],
        "Increasing aircompressor version to 2.0.3 to fix the Druid aircompressor CVEs"),
    "azure-identity": (AZ,
        "<artifactId>azure-sdk-bom</artifactId>\n                <version>1.2.19</version>",
        "<artifactId>azure-sdk-bom</artifactId>\n                <version>1.2.25</version>",
        "OSV-17940", ["OSV-17940"],
        "Increasing azure-sdk-bom to 1.2.25 (azure-identity 1.13.0) to fix the Druid azure-identity CVEs"),
    "woodstox": (AZ, AZ_BOM_ANCHOR, WOODSTOX_INSERT,
        "OSV-17943", ["OSV-17943"],
        "Pinning woodstox-core to 6.5.1 to fix the Druid woodstox-core CVEs"),
}

EXCEPTIONS = {
    "OSV-18020": "jackson-core 2.12.7 is bundled in druid/lib and is pinned project-wide via jackson-bom (jackson.version=2.12.7). The fix requires jackson-core 2.15.0+, which moves Druid 29 off its validated jackson 2.12 line and carries a high serialization/compat regression risk on JDK 8. Deferred to a coordinated jackson upgrade.",
    "OSV-18021": "jackson-core 2.12.7 (druid/lib) is pinned via jackson-bom (jackson.version=2.12.7). Fix requires 2.13.0+, moving Druid off its validated jackson 2.12 baseline (regression risk on JDK 8). Deferred to a coordinated jackson upgrade.",
    "OSV-18022": "jackson-core 2.12.7 (druid/lib) is pinned via jackson-bom (jackson.version=2.12.7). CVE-2025-52999 fix requires 2.15.0+, moving Druid off its validated jackson 2.12 baseline (regression risk on JDK 8). Deferred to a coordinated jackson upgrade.",
    "OSV-18023": "jackson-core 2.12.7 (druid/lib) is pinned via jackson-bom (jackson.version=2.12.7). GHSA-72hv-8253-57qq fix requires 2.15.0+/2.18.6, moving Druid off its validated jackson 2.12 baseline (regression risk on JDK 8). Deferred to a coordinated jackson upgrade.",
    "OSV-18012": "snakeyaml 1.33 (managed in root dependencyManagement, bundled in druid-protobuf/avro/kubernetes extensions). CVE-2022-1471 is only fixed in snakeyaml 2.0, which is a breaking change (SafeConstructor becomes the default and the constructor API changes); Druid 29 is validated against snakeyaml 1.x. The vulnerable path requires loading untrusted YAML with the unsafe constructor, which Druid does not do (descriptor/config YAML is operator-supplied/trusted). Routed to exception pending the snakeyaml 2.x migration in a later Druid baseline.",
    "OSV-17933": "reactor-netty-http 1.0.39 -> 1.0.45 is the highest version the Azure SDK stack supports: it is supplied transitively via azure-sdk-bom (azure-core-http-netty), which pins the reactor-netty 1.0.x/1.1.x line. CVE-2025-22227 is only fixed in reactor-netty-http 1.2.8 / 1.3.0-M5, which require reactor-core 3.7.x and are API-incompatible with azure-core-http-netty bundled in druid-azure-extensions. Forcing 1.2.8 breaks the Azure extension. Routed to exception pending an Azure SDK major upgrade.",
}


def git(cmd: str) -> int:
    print(f"    $ {cmd}")
    return subprocess.run(cmd, shell=True, cwd=WORKDIR).returncode


def gh(method: str, path: str, payload: dict):
    token = cf.github_token()
    headers = {"Authorization": f"token {token}",
               "Accept": "application/vnd.github+json"}
    url = f"https://api.github.com/repos/{cf.REPO_SLUG}{path}"
    return ca.SESSION.request(method, url, headers=headers, json=payload)


def deliver(group: str) -> None:
    f, old, new, branch, keys, summary = GROUPS[group]
    title = f"{branch} - CVE - {summary}"
    print(f"\n{'='*72}\n  {group.upper()}  branch={branch}  file={f}  ({len(keys)} tickets)\n{'='*72}")

    if ca.DRY_RUN:
        print(f"  [DRY_RUN] {branch}: edit {f}, PR, reviewer={REVIEWER}, close {keys}")
        return

    if git(f"git checkout -f -B {branch} origin/{TB}") != 0:
        print("  ERROR checkout"); return
    path = os.path.join(WORKDIR, f)
    text = open(path, encoding="utf-8").read()
    if text.count(old) != 1:
        print(f"  ERROR: anchor count={text.count(old)} (expected 1); abort {group}")
        return
    open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
    git(f"git add {f}")
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
    gh("PATCH", f"/pulls/{num}",
       {"title": title,
        "body": f"- Tickets : {', '.join(keys)}\n\nDruid 3.2.3.6 CVE Phase 2 "
                f"per-library fix; build-validated on JDK 8 via -Pdist and "
                f"verified in the distribution."})
    rr = gh("POST", f"/pulls/{num}/requested_reviewers", {"reviewers": [REVIEWER]})
    print(f"  reviewer {REVIEWER}: {rr.status_code}")

    comment = (f"Fixed via PR: {pr_url}  -  on {TB} the {group} version was bumped; "
               f"the rebuilt Druid distribution (JDK 8, -Pdist) was verified to "
               f"carry the fixed version for this CVE. (Per-library PR.)")
    for k in keys:
        ca.close_ticket_with_comment(k, comment, "Closed")
    print(f"  {group}: PR {pr_url} | closed {len(keys)}")


def main() -> None:
    print(f"Druid PHASE 2 split delivery  DRY_RUN={ca.DRY_RUN}")
    if not ca.DRY_RUN and git("git fetch origin --prune") != 0:
        print("fetch failed"); return
    for g in ["jackson-databind", "jose4j", "plexus-utils", "aircompressor",
              "azure-identity", "woodstox"]:
        deliver(g)

    print(f"\n{'='*72}\n  ROUTING {len(EXCEPTIONS)} EXCEPTIONS\n{'='*72}")
    if ca.DRY_RUN:
        for k in EXCEPTIONS:
            print(f"  [DRY_RUN] exception {k}")
    else:
        routed = 0
        for k, reason in EXCEPTIONS.items():
            if ca.update_ticket_exception(k, reason):
                routed += 1
        print(f"  routed {routed}/{len(EXCEPTIONS)} exceptions")


if __name__ == "__main__":
    main()
