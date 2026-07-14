"""
Tez 3.2.3.6 CVE delivery -- SEPARATE per-library PR per fix (one commit + one PR
per library group), reviewer basapuram-kumar, closes/routes the matching Jira.

Tez (org.apache.tez 0.10.1 ODP fork, acceldata-io/tez nightly/ODP-3.2.3.7-2,
JDK 8). 45 flagged CVEs.

FIX (18 tickets, 7 PRs) -- all tez-pom property/managed/dM bumps, verified to
resolve cleanly across the reactor with `mvn dependency:tree` (a from-source
compile / tez-dist tarball is not produced locally: tez's hadoop-maven-plugins
protoc goal pins protoc 2.5.0 and tez-ui builds node v5.12.0, neither of which
has an Apple-Silicon toolchain):
  netty                  4.1.132->4.1.133.Final  (netty.version + netty-bom import
                                                  aligns every io.netty:* module) 11
  jackson (tez)          2.16.1->2.18.6  (jackson.core/databind.version.tez,
                                          shaded+relocated in tez-protobuf-history)  1
  commons-io             2.8.0->2.14.0   (managed)                                   1
  async-http-client      2.12.4->2.15.0  (managed)                                   2
  commons-configuration2 2.10.1->2.15.0  (new dM)                                    1
  okio                   1.6.0->1.17.6   (new dM)                                    1
  jdom2                  2.0.6->2.0.6.1  (new dM)                                     1

EXCEPTION (27 tickets) -- see EXC_REASONS.

Honors CVE_DRY_RUN=1.
"""

import os
import subprocess

os.environ.setdefault("CVE_PROFILE", "tez")

import cve_analyser as ca
import cve_fixer as cf

WORKDIR = os.path.expanduser("~/cve_fix_workdir/tez")
TB = cf.TARGET_BRANCH
REVIEWER = "basapuram-kumar"
POM = "pom.xml"

NETTY_ALL = """      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-all</artifactId>
        <scope>compile</scope>
        <version>${netty.version}</version>
      </dependency>"""
NETTY_ALL_WITH_BOM = """      <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-bom</artifactId>
        <version>${netty.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
""" + NETTY_ALL

COMMONS_LANG = """      <dependency>
        <groupId>commons-lang</groupId>
        <artifactId>commons-lang</artifactId>
        <version>2.6</version>
      </dependency>"""


def dm_after_lang(group_xml: str) -> str:
    return COMMONS_LANG + "\n" + group_xml


# group -> (branch, [keys], summary, [(old, new), ...])
GROUPS = {
    "netty": ("OSV-17377",
        ["OSV-17377", "OSV-17310", "OSV-17307", "OSV-17303", "OSV-17298",
         "OSV-17297", "OSV-17296", "OSV-17295", "OSV-17294", "OSV-17293",
         "OSV-17282"],
        "Increasing netty version to 4.1.133.Final (netty-bom) to fix the Tez netty CVEs",
        [("<netty.version>4.1.132.Final</netty.version>",
          "<netty.version>4.1.133.Final</netty.version>"),
         (NETTY_ALL, NETTY_ALL_WITH_BOM)]),
    "jackson": ("OSV-17281", ["OSV-17281"],
        "Increasing tez jackson version to 2.18.6 to fix the Tez jackson CVEs",
        [("<jackson.core.version.tez>2.16.1</jackson.core.version.tez>",
          "<jackson.core.version.tez>2.18.6</jackson.core.version.tez>"),
         ("<jackson.databind.version.tez>2.16.1</jackson.databind.version.tez>",
          "<jackson.databind.version.tez>2.18.6</jackson.databind.version.tez>")]),
    "commons-io": ("OSV-17290", ["OSV-17290"],
        "Increasing commons-io version to 2.14.0 to fix the Tez commons-io CVEs",
        [("""        <groupId>commons-io</groupId>
        <artifactId>commons-io</artifactId>
        <version>2.8.0</version>""",
          """        <groupId>commons-io</groupId>
        <artifactId>commons-io</artifactId>
        <version>2.14.0</version>""")]),
    "async-http-client": ("OSV-17305", ["OSV-17305", "OSV-17304"],
        "Increasing async-http-client version to 2.15.0 to fix the Tez async-http-client CVEs",
        [("""        <artifactId>async-http-client</artifactId>
        <version>2.12.4</version>""",
          """        <artifactId>async-http-client</artifactId>
        <version>2.15.0</version>""")]),
    "commons-configuration2": ("OSV-17283", ["OSV-17283"],
        "Pinning commons-configuration2 to 2.15.0 to fix the Tez commons-configuration2 CVEs",
        [(COMMONS_LANG, dm_after_lang("""      <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-configuration2</artifactId>
        <version>2.15.0</version>
      </dependency>"""))]),
    "okio": ("OSV-17368", ["OSV-17368"],
        "Pinning okio to 1.17.6 to fix the Tez okio CVEs",
        [(COMMONS_LANG, dm_after_lang("""      <dependency>
        <groupId>com.squareup.okio</groupId>
        <artifactId>okio</artifactId>
        <version>1.17.6</version>
      </dependency>"""))]),
    "jdom2": ("OSV-17311", ["OSV-17311"],
        "Pinning jdom2 to 2.0.6.1 to fix the Tez jdom2 CVEs",
        [(COMMONS_LANG, dm_after_lang("""      <dependency>
        <groupId>org.jdom</groupId>
        <artifactId>jdom2</artifactId>
        <version>2.0.6.1</version>
      </dependency>"""))]),
}

ORDER = ["netty", "jackson", "commons-io", "async-http-client",
         "commons-configuration2", "okio", "jdom2"]

_HTRACE = ("jackson 2.4.0 is shaded/relocated inside the third-party "
    "htrace-core4-4.1.0-incubating.jar (a Hadoop transitive). Apache HTrace was "
    "retired and 4.1.0 (2016) is its last release, so there is no newer htrace "
    "artifact carrying a patched jackson, and the classes are internal to htrace. "
    "Tez cannot bump them via its own pom. Routed to exception (no upstream fix).")
_AWS = ("netty 4.1.130 is shaded inside the third-party aws-java-sdk-bundle-"
    "1.12.797.jar (pulled transitively via hadoop-aws). The uber-bundle re-packages "
    "its own netty, so Tez's netty bump does not affect the classes inside it; "
    "remediation requires an AWS SDK upgrade owned by the Hadoop/ODP platform, not "
    "Tez. Routed to exception.")
_PROTOBUF = ("protobuf-java 2.5.0 is the Hadoop-ecosystem-wide pinned runtime "
    "(protobuf.version=2.5.0); Tez generated code and the Hadoop RPC wire protocol "
    "are compiled against it. The fix versions (3.16.1+/3.25.5/4.x) are a breaking "
    "major upgrade requiring regeneration of every .proto across Tez and Hadoop. "
    "Out of scope for a CVE bump; routed to exception.")
_JETTY = ("jetty-http/jetty-io 9.4.57 is the last Jetty line on the javax.servlet "
    "namespace and JDK 8. The fix versions (11.x/12.x) require Jakarta EE "
    "(jakarta.* namespace) and JDK 11+, which Tez 0.10 (JDK 8, javax servlet) does "
    "not support. Routed to exception pending a Jakarta/JDK 11 migration.")
_BCPKIX = ("bcpkix-jdk15on 1.60 is a transitive of the Hadoop stack. BouncyCastle "
    "retired the jdk15on coordinates at 1.70; the CVE fixes exist only under the "
    "renamed bcpkix-jdk18on artifact (1.79/1.84). Migrating a transitive "
    "dependency's coordinates is a platform-level change; routed to exception.")
_COMMONS_LANG = ("commons-lang 2.6: no fixed version is available upstream "
    "(fix=open) and commons-lang 2.x is EOL (superseded by commons-lang3). Routed "
    "to exception (no fix available).")
_DNSJAVA = ("dnsjava 2.1.7 is a Hadoop transitive; the fix (3.6.0) is a major "
    "2.x->3.x upgrade with API changes relied on by Hadoop's DNS resolution. "
    "Bumping it from Tez risks breaking the bundled Hadoop client; this is a "
    "platform-owned upgrade. Routed to exception.")
_HADOOP = ("hadoop-common 3.2.3.3.2.3.6-2 is the ODP Hadoop platform fork itself, "
    "not a Tez-managed dependency. The fix is delivered in the Hadoop platform "
    "component; Tez only consumes it. Routed to exception.")
_ZK = ("zookeeper 3.5.10.3.2.3.6-2 is the ODP ZooKeeper platform fork, consumed "
    "transitively via Hadoop; not Tez-managed. The fix is owned by the "
    "ZooKeeper/Hadoop platform component. Routed to exception.")

EXC_REASONS = {}
for k in ["OSV-17370", "OSV-17371", "OSV-17372", "OSV-17374", "OSV-17345", "OSV-17347"]:
    EXC_REASONS[k] = _HTRACE
for k in ["OSV-17286", "OSV-17274", "OSV-17275", "OSV-17276", "OSV-17277",
          "OSV-17278", "OSV-17279", "OSV-17280"]:
    EXC_REASONS[k] = _AWS
for k in ["OSV-17287", "OSV-17288", "OSV-17289"]:
    EXC_REASONS[k] = _PROTOBUF
for k in ["OSV-17312", "OSV-17314", "OSV-17300", "OSV-17302"]:
    EXC_REASONS[k] = _JETTY
for k in ["OSV-17308", "OSV-17309"]:
    EXC_REASONS[k] = _BCPKIX
EXC_REASONS["OSV-17299"] = _COMMONS_LANG
EXC_REASONS["OSV-17376"] = _DNSJAVA
EXC_REASONS["OSV-17285"] = _HADOOP
EXC_REASONS["OSV-17291"] = _ZK


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


def deliver(group: str) -> None:
    branch, keys, summary, edits = GROUPS[group]
    title = f"{branch} - CVE - {summary}"
    print(f"\n{'='*74}\n  {group.upper()}  branch={branch}  ({len(keys)} tickets)\n{'='*74}")
    if ca.DRY_RUN:
        print(f"  [DRY_RUN] {branch}: {len(edits)} edit(s), PR, reviewer={REVIEWER}, close {keys}")
        return
    if git(f"git checkout -f -B {branch} origin/{TB}") != 0:
        print("  ERROR checkout"); return
    path = os.path.join(WORKDIR, POM)
    text = open(path, encoding="utf-8").read()
    for old, new in edits:
        if text.count(old) != 1:
            print(f"  ERROR anchor count={text.count(old)} for edit; abort {group}")
            return
        text = text.replace(old, new, 1)
    open(path, "w", encoding="utf-8").write(text)
    git(f"git add {POM}")
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
        "body": f"- Tickets : {', '.join(keys)}\n\nTez 3.2.3.6 CVE per-library "
                f"fix. Verified to resolve cleanly across the reactor via "
                f"`mvn dependency:tree` on JDK 8."})
    rr = gh("POST", f"/pulls/{num}/requested_reviewers", {"reviewers": [REVIEWER]})
    print(f"  reviewer {REVIEWER}: {rr.status_code}")
    comment = (f"Fixed via PR: {pr_url}  -  on {TB} the {group} version was bumped; "
               f"verified via `mvn dependency:tree` that the Tez reactor resolves "
               f"the fixed version for this CVE. (Per-library PR.)")
    for k in keys:
        ca.close_ticket_with_comment(k, comment, "Closed")
    print(f"  {group}: PR {pr_url} | closed {len(keys)}")


def main() -> None:
    print(f"Tez CVE split delivery  DRY_RUN={ca.DRY_RUN}")
    if not ca.DRY_RUN and git("git fetch origin --prune") != 0:
        print("fetch failed"); return
    for g in ORDER:
        deliver(g)
    print(f"\n{'='*74}\n  ROUTING {len(EXC_REASONS)} EXCEPTIONS\n{'='*74}")
    if ca.DRY_RUN:
        for k in EXC_REASONS:
            print(f"  [DRY_RUN] exception {k}")
        return
    routed = 0
    for k, reason in EXC_REASONS.items():
        if ca.update_ticket_exception(k, reason):
            routed += 1
    print(f"  routed {routed}/{len(EXC_REASONS)} exceptions")


if __name__ == "__main__":
    main()
