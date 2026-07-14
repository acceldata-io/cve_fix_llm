"""Read configured library versions across ODP component branches (read-only)."""
import json
import re
import subprocess
import urllib.request

TOKEN = subprocess.run(
    "printf 'host=github.com\\nprotocol=https\\n\\n' | git credential fill 2>/dev/null"
    " | sed -n 's/^password=//p'", shell=True, capture_output=True, text=True).stdout.strip()

# component -> (list of raw file paths "<repo>@<branch>:<path>")
COMPONENTS = {
    "zookeeper":   [("acceldata-io/zookeeper", "nightly/ODP-3.2.3.7-2", "pom.xml")],
    "hadoop":      [("acceldata-io/hadoop", "nightly/ODP-3.2.3.7-2", "hadoop-project/pom.xml")],
    "hbase":       [("acceldata-io/hbase", "nightly/ODP-3.2.3.7-2", "pom.xml")],
    "tez":         [("acceldata-io/tez", "nightly/ODP-3.2.3.7-2", "pom.xml")],
    "impala":      [("acceldata-io/impala", "nightly/ODP-3.2.3.7-2", "bin/impala-config.sh"),
                    ("acceldata-io/impala", "nightly/ODP-3.2.3.7-2", "java/pom.xml")],
    "spark2":      [("acceldata-io/spark", "nightly/ODP-3.2.3.7-2", "pom.xml")],
    "spark3.5.5":  [("acceldata-io/spark3", "nightly/ODP-3.2.3.7-2", "pom.xml")],
    "spark3.3.3":  [("acceldata-io/spark3", "nightly/ODP-3.3.3.3.2.3.7-2", "pom.xml")],
    "spark3.5.1":  [("acceldata-io/spark3", "nightly/ODP-3.5.1.3.2.3.7-2", "pom.xml")],
    "pinot":       [("acceldata-io/pinot", "nightly/ODP-3.2.3.7-2", "pom.xml")],
    "clickhouse":  [("acceldata-io/ch-ui", "nightly/ODP-3.2.3.7-2", "ch-ui-wrapper/pom.xml")],
    "druid":       [("acceldata-io/druid", "nightly/ODP-3.2.3.7-2", "pom.xml")],
    "flink":       [("acceldata-io/flink", "nightly/ODP-3.2.3.7-2", "pom.xml")],
}

# display label -> candidate property names (lowercased) + dependency ga matchers
LIBS = [
    ("Hadoop-thirdparty", ["hadoop-thirdparty.version", "hadoop.thirdparty.version"], ["org.apache.hadoop.thirdparty:hadoop-shaded-guava", "org.apache.hadoop.thirdparty:hadoop-shaded-protobuf_3_25"]),
    ("commons-lang3", ["commons-lang3.version"], ["org.apache.commons:commons-lang3"]),
    ("commons-text", ["commons-text.version"], ["org.apache.commons:commons-text"]),
    ("commons-configuration2", ["commons-configuration2.version", "commons.configuration2.version"], ["org.apache.commons:commons-configuration2"]),
    ("Netty4", ["netty.version", "netty4.version", "netty.4.version", "io.netty.version", "netty-all.version"], ["io.netty:netty-all", "io.netty:netty-handler", "io.netty:netty-bom"]),
    ("protobuf", ["protobuf.version", "protobuf-java.version", "protobuf.java.version", "protoc.version"], ["com.google.protobuf:protobuf-java"]),
    ("commons-io", ["commons-io.version"], ["commons-io:commons-io"]),
    ("commons-compress", ["commons-compress.version"], ["org.apache.commons:commons-compress"]),
    ("tomcat", ["tomcat.version", "tomcat.embed.version"], ["org.apache.tomcat.embed:tomcat-embed-core"]),
    ("opentelemetry-javaagent", ["opentelemetry-javaagent.version", "opentelemetry.version", "opentelemetry-api.version"], ["io.opentelemetry.javaagent:opentelemetry-javaagent", "io.opentelemetry:opentelemetry-api"]),
    ("hbase-thirdparty", ["hbase-thirdparty.version", "hbase.thirdparty.version"], ["org.apache.hbase.thirdparty:hbase-shaded-netty", "org.apache.hbase.thirdparty:hbase-shaded-miscellaneous"]),
    ("beanutils", ["beanutils.version"], []),
    ("avro", ["avro.version"], ["org.apache.avro:avro"]),
    ("Jetty", ["jetty.version", "jetty9.version", "jetty.major.version"], ["org.eclipse.jetty:jetty-server", "org.eclipse.jetty:jetty-util", "org.eclipse.jetty:jetty-http"]),
    ("nimbus-jose", ["nimbus-jose-jwt.version", "nimbus.jose.jwt.version", "nimbus-jose.version", "nimbusds.version"], ["com.nimbusds:nimbus-jose-jwt"]),
    ("commons-beanutils", ["commons-beanutils.version"], ["commons-beanutils:commons-beanutils"]),
    ("jackson2", ["jackson.version", "jackson2.version", "fasterxml.jackson.version", "jackson-bom.version", "jackson.databind.version"], ["com.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson:jackson-bom"]),
    ("guava", ["guava.version"], ["com.google.guava:guava"]),
    ("log4j2", ["log4j2.version", "log4j.version"], ["org.apache.logging.log4j:log4j-core"]),
    ("xmlsec", ["xmlsec.version"], ["org.apache.santuario:xmlsec"]),
    ("cron-utils", ["cron-utils.version", "cronutils.version"], ["com.cronutils:cron-utils"]),
    ("bouncycastle", ["bouncycastle.version", "bouncy-castle.version", "bc.version", "bcprov.version"], ["org.bouncycastle:bcprov-jdk15on", "org.bouncycastle:bcprov-jdk18on"]),
    ("dnsjava", ["dnsjava.version"], ["dnsjava:dnsjava"]),
    ("libthrift", ["thrift.version", "libthrift.version"], ["org.apache.thrift:libthrift"]),
    ("aircompressor", ["aircompressor.version"], ["io.airlift:aircompressor"]),
]

# impala uses ${env.IMPALA_*}; map property/lib -> env var (read from config.sh)
IMPALA_ENV = {
    "jackson2": "IMPALA_JACKSON_DATABIND_VERSION",
    "log4j2": "IMPALA_LOG4J2_VERSION",
    "guava": "IMPALA_GUAVA_VERSION",
    "avro": "IMPALA_AVRO_JAVA_VERSION",
    "protobuf": "IMPALA_PROTOBUF_JAVA_VERSION",
    "libthrift": "IMPALA_THRIFT_POM_VERSION",
    "bouncycastle": "IMPALA_BOUNCY_CASTLE_VERSION",
    "xmlsec": "IMPALA_XMLSEC_VERSION",
}


def fetch(repo, branch, path):
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"token {TOKEN}"})
    try:
        return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
    except Exception as e:
        return f"__ERR__ {e}"


def props_from_pom(text):
    d = {}
    for m in re.finditer(r"<([a-zA-Z0-9_.\-]+)>\s*([^<>]+?)\s*</\1>", text):
        d.setdefault(m.group(1).lower(), m.group(2).strip())  # first (top-level) wins
    return d


def deps_from_pom(text):
    """{ 'groupId:artifactId': version }"""
    out = {}
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        blk = m.group(1)
        g = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", blk)
        a = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", blk)
        v = re.search(r"<version>\s*([^<]+?)\s*</version>", blk)
        if g and a and v:
            out[f"{g.group(1).strip()}:{a.group(1).strip()}"] = v.group(1).strip()
    return out


def resolve(val, props, depth=0):
    if not val or depth > 5:
        return val
    m = re.fullmatch(r"\$\{([^}]+)\}", val.strip())
    if m:
        key = m.group(1).lower()
        if key in props:
            return resolve(props[key], props, depth + 1)
    return val


def impala_env(cfg_text):
    env = {}
    for m in re.finditer(r"export\s+([A-Z][A-Z0-9_]+)=([^\s#]+)", cfg_text):
        env[m.group(1)] = m.group(2)
    # resolve ${CDP_*}/${APACHE_*} refs one level
    for k, v in list(env.items()):
        mm = re.fullmatch(r"\$\{([A-Z0-9_]+)(:-[^}]*)?\}", v)
        if mm and mm.group(1) in env:
            env[k] = env[mm.group(1)]
    return env


results = {}
for comp, files in COMPONENTS.items():
    props, deps, cfg = {}, {}, ""
    for repo, branch, path in files:
        txt = fetch(repo, branch, path)
        if txt.startswith("__ERR__"):
            print(f"  WARN {comp} {path}: {txt[:80]}")
            continue
        if path.endswith(".sh"):
            cfg = txt
        else:
            props.update(props_from_pom(txt))
            deps.update(deps_from_pom(txt))
    env = impala_env(cfg) if cfg else {}
    row = {}
    for label, candidates, gas in LIBS:
        val = None
        if comp == "impala" and label in IMPALA_ENV and IMPALA_ENV[label] in env:
            val = env[IMPALA_ENV[label]]
        if val is None:
            for c in candidates:
                if c in props:
                    val = resolve(props[c], props); break
        if val is None:
            for ga in gas:
                if ga in deps:
                    val = resolve(deps[ga], props); break
        row[label] = val or "-"
    results[comp] = row

json.dump(results, open("/tmp/ver_audit.json", "w"), indent=1)

# print matrix: libs as rows, components as columns
comps = list(COMPONENTS)
print("\nLIB," + ",".join(comps))
for label, _, _ in LIBS:
    print(label + "," + ",".join(results[c][label] for c in comps))
